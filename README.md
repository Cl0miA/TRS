# TRS
Threshold Ring Signature And Advanced Properties Implementations

**This project is a proof of conxept. It is not intended for use in real-world cryptographic applications. Do not use this implementation for securing sensitive data.**

---

## Introduction

This project aims to **create threshold ring signature** and **build signatures with advanced properties**. Users can select from multiple properties, all accessible through various independent functions. 


## Features

- **Ring**
  Create a ring a signers and non-signers. Can be seen as a setup for the signature phase. 
  
- **TRS**  
  Build a threshold ring signature using the AGS identification scheme.

- **Advanced Properties**  
  Add advanaced properties to the threshold ring signature.


## How It Works

### Creating a Ring
Depending on the functionnalities of the ring, you can use :

1. **Ring(nb_s,nb_n)**
   to create a whole ring, with the number of signers and non-signers, given them all private and public keys.
   
3. **Ring_G(G,nb_s,nb_n)**
   to create a ring with a specific generator matrix with the number of signers and non-signers, given them all private and public keys.

### Building a Threshold Ring Signature
Depending on the number of data the user wants, you can use :

1. **TRS(m,nb_s,nb_n)**
   to build a valid threshold ring signature, returning the signature.

2. **TRS(m,nb_s,nb_n,e)**
   to build a valid threshold ring signature, returning the signature and the public key.
   
### Advanced Properties

1. **Extendability**  
   - To add two rings into one, after that the user can sign the document using the TRS function and the newly formed ring.

2. **Flexibility**  
(Before using this property, the user needs to use the **Flex_Setup** function, and give in parameters the index of the non-signer becoming signer.)
   - To change a non-signer into a signer in the ring, after that the user can sign the document using the TRS function and the newly formed ring.

3. **Clippability**  
(Before using this property, the user needs to use the **Clip_Setup** function, and give in parameters the index of the non-signer leaving the ring.)
   - To suppress a non-signer in the ring, after that the user can sign the document using the TRS function and the newly formed ring.
  
4. **Splittability**  
(Before using this property, the user needs to use the **Split_Setup** function, and give in parameters the index of the signer becoming non-signer.)
   - To change a signer into a non-signer in the ring, after that the user can sign the document using the TRS function and the newly formed ring.

5. **Revocability**
   - To suppress a signer from a ring, by turning them into a non-signer and then clipping them out of the ring, after that the user can sign the document using the TRS function and the newly formed ring.
