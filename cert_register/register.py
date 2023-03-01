import struct
import binascii
import sha256, rsa_sc

class register(object):
    def __init__(self, nonce) -> None:
        self._nonce: bytes = nonce

    #RSA encrypt, using PK
    def rsa_encrypt(self, text: bytes, key: bytes) -> bytes:
        ciphertext = rsa_sc.encrypt(text, key)
        return ciphertext

    #sent message
    def signing(self, message: bytes) -> bytes:     #message = ID(A) || PU(A)
        self._msg: bytes = message
        self._msg_len: int = len(message)
       
        payload = self.plaintext_gen(self._msg)
        digest = sha256.hash_function(payload)
        signature = self.rsa_encrypt(digest)
        cp = payload + signature
        return cp
   


    def plaintext_gen(self, msg: bytes) -> bytes:
        # Formatting control information and nonce
        self.q:int = 15 - len(self._nonce)  # length of Q, the encoded message length

        flags: int = self.q - 1
        b_0: bytes = struct.pack("B", flags) + self._nonce + sha256.long_to_bytes(len(msg), self.q)

       
        b = b_0 + msg
        return b


