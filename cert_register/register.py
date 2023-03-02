'''
import struct
import binascii
import sha256
import rsa_algorithm as rsa

class register(object):
    def __init__(self, nonce) -> None:
        self._nonce: bytes = nonce

    #RSA encrypt, using PK
    def rsa_encrypt(self, text: bytes, key: bytes) -> bytes:
        ciphertext = rsa.encrypt(text, key)
        return ciphertext

    #sent message
    def signing(self, message: bytes) -> bytes:     #message = ID(A) || PU(A)
        self._msg: bytes = message
        self._msg_len: int = len(message)
       
        payload = self.plaintext_gen(self._msg)

        #payload -> digest 256bit -> encrypt RSA
        digest = sha256.hash_function(payload)      
        signature = self.rsa_encrypt(digest) 

        cp = payload + signature
        return cp
   


    def plaintext_gen(self) -> bytes:
        # Formatting control information and nonce
        self.q:int = 15 - len(self._nonce)  # length of Q, the encoded message length

        flags: int = self.q - 1
        b_0: bytes = struct.pack("B", flags) + self._nonce + sha256.long_to_bytes(len(self._msg), self.q)
     
        b = b_0 + self._msg
        return b
'''    
#from security_system.cert_verify.verify import abc

#print(abc())
'''
import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
'''
import sys
print(sys.path)
sys.path.append('d:\\SIPLab\\security_system\\cert_register')