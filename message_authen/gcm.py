import aes
import struct
import binascii
import math


#input data
'''
plaintext: P
AAD: A
ini_vector ~ nonce: IV  (recommend 96 bit)

GCM: protect A and P
'''

#Output data
'''
ciphertext: C
authencication tag: T
'''

class GCMmode(object):
    def __init__(self, key, IV, A, tag_len) -> None:
        self._key: bytes = key
        self._IV: bytes = IV
        self.len_IV: int = len(IV)

        self._A: bytes = A
        self.len_A: int = len(A)
        self._tag_len: int = tag_len

    #aes encrypt & decrypt, use in cmac
    def _aes_encrypt(self, block: bytes) -> bytes:
        key = aes.AES(self._key)
        return key.encrypt(block)

    def _aes_decrypt(self, block: bytes) -> bytes:
        key = aes.AES(self._key)
        return key.decrypt(block)
    
    #pad/unpad bit '0' to full of block
    def _pad(self, data: bytes) -> bytes:
        padding_length: int = self._block_size - (len(data) % self._block_size)
        padding: bytes = b'\x00' * padding_length
        return data + padding

    def _unpad(self, data: bytes) -> bytes:
        padding_length: int = data[-1]
        return data[:-padding_length]

    #xor function
    def _xor(self, a: bytes, b: bytes) -> bytes:
        return bytes([x ^ y for x, y in zip(a, b)])
    

    #increment function used in generate counter mode
    def incre_func(self, X: bytes, s: int):
        X = bin(int.from_bytes(X, byteorder='big', signed=False))[2:] # binary string
        lsb_x = (int(X[-s:], 2) + 1) % (2**s)
        lsb_x = format(lsb_x, f'0{s}b')
        print(X)
        inc_s = X[:len(X) - s] + lsb_x
        inc_s = int(inc_s, 2).to_bytes((len(inc_s) + 7) // 8, byteorder='big') # byte string
        return inc_s

    #multiplication operation on block
    def mul(self, x: bytes, y: bytes) -> bytes:
        x = aes.bytes_to_long(x)
        y = aes.bytes_to_long(y)

        R = int('11100001' +'0'*120, 2)
        z = 0
        v = y
        for i in range(0, 128):
            if x & (1 << i):
                z ^= v
            if v & 1:
                v >>= 1
                v ^= R
            else:
                v >>= 1
        return aes.long_to_bytes(z)   

    #GHASH function
    def ghash_func(self, x: bytes, H: bytes) -> bytes:
        y = self.mul(x[0, 16], H)
        for i in range(16, int(len(x/16))):
            pre = self._xor(x[i: i+16], y)
            y = self.mul(pre, H)
        return y
    
    #GCTR function
    def GCTR(self, icb: bytes, x: bytes):
        n = math.ceil(x)
        cb = icb
        for i in range(0, n - 1):
            cp = self._aes_encrypt(cb)
            y = self._xor(x[i, 16*i], cp)        
            cb = self. incre_func(cb, 32)
            cipher += y
        cp = self._aes_encrypt(cb)[:len(x)-16*(n-1)]
        y_ = self._xor(x[16*(n-1):], cp)
        cipher += y_
        return cipher
    
    #Algorithm for the Authenticated Encryption Function
    def encrypt_gcm(self, P: bytes) -> bytes:
        H = self._aes_encrypt(b'0' * 16)

        #define block J0
        if len(self._IV) == 24:
            
            

