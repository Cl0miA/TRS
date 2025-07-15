import numpy as np

##############################################################

#Hamming weight function

#args: a list seen as a vector

def Ham_weight(L):
    n=len(L)
    w=0
    for i in range (n):
        if L[i]!=0:
            w=w+1
    return w

##############################################################

#Second function KeyGen that will generate only part of the keys based on the generator matrix G given 
# and the argument 'is a signer' 'yes:1' 'no:0'

#args: G is the generator matrix of the code from which the keys will be derived and n_s is the answer to the question 'is a signer'

def KeyGen_(G,n_s):
    k=G.ncols()
    n=G.nrows()
    Fn=VectorSpace(GF(2),n)
    y=Fn.random_element()
    if n_s==1:
        Fk=VectorSpace(GF(2),k)
        x=Fk.random_element()
        while x==zero_vector(GF(2),k):
            x=Fk.random_element()
    else:
        x=vector(GF(2),[0 for i in range (k)])
    t=Ham_weight(list(x))
    e=y*G+x
    sk=(y,x)
    pk=(e,G,t)
    return sk,pk

##############################################################

#Permutation function

#args: a list seen as a vector

def perm(L):
    l=len(L)
    L=np.roll(L,6)
    temp=L[l-1]
    L[l-1]=L[0]
    L[0]=temp
    return tuple(list(L))

##############################################################

#Second AGS function, implementation of only the 'signing' part of the identification scheme, 
# leaving the verify part for the verify function

#args: m is the message to sign, sk is the secret keys, pk the public keys

def AGS_(m,sk,pk):
    S=[]
    y=sk[0]
    x=sk[1]
    e=pk[0]
    G=pk[1]
    t=pk[2]
    n=G.nrows()
    k=G.ncols()
    Fn=VectorSpace(GF(2),n)
    for i in range (5):
        u=Fn.random_element()
        c1=hash(perm([0 for i in range (n)]))
        c2=hash(perm(list(u*G)))
        r=randrange(k)
        c3=hash(perm(list((u*G)+vector(GF(2),np.roll(list(x),r)))))
        b=(int(hash(tuple(m)))+r)%2
        if b==0:
            p1=u*G+vector(GF(2),np.roll(y*G,r))
            p2=perm([0 for i in range (n)])
            S.append([r,c1,c3,p1,p2])
        else:
            p1=perm(list(u*G))
            p2=perm(np.roll(list(x),r))
            S.append([k,c2,c3,p1,p2])
    return S

##############################################################

#Verify function for only one signer, or the second part of the AGS indentification scheme 

#args: S is the result of the AGS_ sign function, a list containing the random r, teh commitments, and the responses
# pk the public keys and m the message

def Ver(S,pk,m):
    e=pk[0]
    G=pk[1]
    t=pk[2]
    n=G.nrows()
    k=G.ncols()
    for i in range (len(S)):
        r=S[i][0]
        c=S[i][1]
        c3=S[i][2]
        p1=S[i][3]
        p2=S[i][4]
        if r!=k:
            if c==hash(p2) and c3==hash(perm(list(p1+vector(GF(2),np.roll(list(e),r))))):
                return True
            else:
                return False
        else:
            if c==hash(p1) and c3==hash(tuple(vector(GF(2),p1)+vector(GF(2),p2))):
                if Ham_weight(p2)<=t:
                    return True
                else:
                    return False
            else:
                return False
            
##############################################################

#Ring function that creates a ring for signers and non-signers given them the appropriate keys

#args: nb_s is the number of signers in the ring, nb_n is the number of non-signers in the ring

def Ring(nb_s,nb_n):
    n=randrange(2,20)
    k=randrange(2,15)
    Mnk=MatrixSpace(GF(2),n,k)
    G=Mnk.random_element()
    E=[]
    SK=[]
    for i in range (nb_s):
        sk_i,pk_i=KeyGen_(G,1)
        E.append([pk_i[0],pk_i[2]])
        SK.append([sk_i[0],sk_i[1]])
    for j in range (nb_n):
        sk_j,pk_j=KeyGen_(G,0)
        E.append([pk_j[0],pk_j[2]])
        SK.append([sk_j[0],sk_j[1]])
    return G,E,SK

##############################################################

#Alternate version of the Ring function where the generator matrix G is given in arguments, useful for some properties

#args: G is a generator matrix of the code, nb_s is the number of signers in the ring and nb_n is the number of non-signers

def Ring_G(G,nb_s,nb_n):
    E=[]
    SK=[]
    for i in range (nb_s):
        sk_i,pk_i=KeyGen_(G,1)
        E.append([pk_i[0],pk_i[2]])
        SK.append([sk_i[0],sk_i[1]])
    for j in range (nb_n):
        sk_j,pk_j=KeyGen_(G,0)
        E.append([pk_j[0],pk_j[2]])
        SK.append([sk_j[0],sk_j[1]])
    return E,SK

##############################################################

#Sign function for a TRS scheme

#args: m is the message to sign, G is a generator matrix, E is the public key of the ring, SK is the private key of the ring

def Sign(m,G,E,SK):
    S=[]
    for i in range (len(E)):
        sk=[SK[i][0],SK[i][1]]
        pk=[E[i][0],G,E[i][1]]
        S.append(AGS_(m,sk,pk))
    return S

##############################################################

#Verify function for a TRS scheme

#args: m is the message to sign, G is a generator matrix, E is the public key of the ring, S is the signature of the ring

def Verify(m,G,E,S):
    T=[]
    for i in range (len(S)):
        pk=[E[i][0],G,E[i][1]]
        s=S[i]
        T.append(Ver(s,pk,m))
    return T

##############################################################

#Function that combine a key generation, a signature and a verification of the signature for a TRS scheme

#args: m is the message to sign, nb_s is the number of signers in the ring, the nb_n the number of non-signers,
# e is an argument to retrieve or not the public key of the ring

def TRS(m,nb_s,nb_n,e=False):
    G,E,SK=Ring(nb_s,nb_n)
    S=Sign(m,G,E,SK)
    T=Verify(m,G,E,S)
    for i in T:
        if i==False:
            return False
    if e==True:
        return S,E
    else:
        return S