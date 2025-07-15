import numpy as np

##############################################################

#Extendability function for a TRS meaning from two ring with the same generator matrix and the same non-signers, aggregate the signers into one ring

#args: G is a generator matrix, E1 the public key of the ring 1, SK the private key, 
# E2 the public key of the ring 2, SK2 teh private key

def Ext(G,E1,SK1,E2,SK2):
    k=G.ncols()
    E=E1[::-1]
    SK=SK1[::-1]
    i=0
    while SK2[i][1]!=zero_vector(GF(2),k):
        i=i+1
    for j in range (i):
        E.append(E2[j])
        SK.append(SK2[j])
    return G,E[::-1],SK[::-1]

##############################################################

#Setup function for the flexibility function, where the lines for the public and private keys of the non-signers are in the right place

#args: G a generator matrix, E the public key of the ring, SK the private key of the ring,
# j the index of the non-signer in their way to become signer

def Flex_Setup(G,E,SK,j):
    k=G.ncols()
    i=0
    while SK[i][1]!=zero_vector(GF(2),k):
        i=i+1
    if j>i-1:
        E_=E[j]
        E[j]=E[i]
        E[i]=E_
        SK_=SK[j]
        SK[j]=SK[i]
        SK[i]=SK_
        return G,E,SK
    else:
        return False

##############################################################

#Flexibility function that will from a ring change a non-signer to a signer

#args: G a generator matrix, E the public key, SK the private key

def Flex(G,E,SK):
    k=G.ncols()
    i=0
    while SK[i][1]!=zero_vector(GF(2),k):
        i=i+1
    sk,pk=KeyGen_(G,1)
    E[i]=[pk[0],pk[2]]
    SK[i]=sk
    return G,E,SK

##############################################################

#Setup function for the clippability function, where the lines for the public and private keys of the non-signers are in the right place

#args: G a generator matrix, E the public key of the ring, SK the private key of the ring,
# j the index of the non-signer in their way to leave the ring

def Clip_Setup(G,E,SK,j):
    k=G.ncols()
    i=0
    while SK[i][1]!=zero_vector(GF(2),k):
        i=i+1
    if j>i-1:
        new_E=E[0:j]+E[j:len(E)-1]+E[j]
        new_SK=SK[0:j]+SK[j:len(SK)-1]+SK[j]
        return new_E,new_SK
    else:
        return False

##############################################################

#Clippability function that will suppress a non-signer in the ring 

#args: G the generator matrix, E the public key of the ring, SK the private key

def Clip(G,E,SK):
    l=len(E)
    E=E[0:l-1]
    SK=SK[0:l-1]
    return G,E,SK

##############################################################

#Setup function for the splittability function, where the lines for the public and private keys of the non-signers are in the right place

#args: G a generator matrix, E the public key of the ring, SK the private key of the ring,
# j the index of the signer in their way to become non-signer

def Split_Setup(G,E,SK,j):
    k=G.ncols()
    i=0
    while SK[i][1]!=zero_vector(GF(2),k):
        i=i+1
    if j<i:
        E_=E[j]
        E[j]=E[i-1]
        E[i-1]=E_
        SK_=SK[j]
        SK[j]=SK[i-1]
        SK[i-1]=SK_
        return G,E,SK
    else:
        return False

##############################################################

#Splittability function, meaning a signer will become a non-signer

#args: G a generator matrix, E the public key of the ring, SK the private key

def Split(G,E,SK):
    k=G.ncols()
    i=0
    while SK[i][1]!=zero_vector(GF(2),k):
        i=i+1
    sk,pk=KeyGen_(G,0)
    E[i-1]=[pk[0],pk[2]]
    SK[i-1]=sk
    return G,E,SK

##############################################################

#Revocaibility function, from a ring suppress a signer, using the splittability and clippability function 

#args: G a generator matrix, E the public key of the ring, SK the private key

def Revoc(G,E,SK):
    G,E,SK=Split(G,E,SK)
    G,E,SK=Clip(G,E,SK)
    return G,E,SK