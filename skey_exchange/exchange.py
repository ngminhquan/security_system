import _rsa as rsa
from _rsa import long_to_bytes, bytes_to_long

#Đọc private và public key của 2 user A, B

prA = 521291911194115881971784259129829406557
puA = 592023132272619312135417828289467928637

pA = 0x1758230e52f3c841d
qA = 0x1361610518f599d83
nA = pA*qA

prB = 376977870950477749744287648692459257913
puB = 173092507290167731023112407286471506137

pB = 0x168eec6483eaf6769
qB = 0x199b892966d00294b
nB = pB * qB


#Mã hóa và giải mã qua rsa

def rsa_encrypt(text: bytes, e: int, n: int) -> bytes:
    text = bytes_to_long(text)
    ciphertext = rsa.encrypt(text, e, n)
    ciphertext = long_to_bytes(ciphertext)
    return ciphertext

def rsa_decrypt(text: bytes, d:int, n: int) -> bytes:
    text = bytes_to_long(text)
    decrypted_message = rsa.decrypt(text, d, n)
    decrypted_message = long_to_bytes(decrypted_message)
    return decrypted_message


#Trao đổi khóa phiên
class key_exchange(object):
    def __init__(self, puA, puB, prA, prB, nA, nB) -> None:
        self._puA: int = puA
        self._prA: int = prA
        self._puB: int = puB
        self._prB: int = prB
        self._nA: int = nA
        self._nB: int = nB

    #Mã hóa khóa phiên để truyền di
    def encrypt_key(self, sessionkey: bytes) -> bytes:
        ssk_encrypt_1 = rsa_encrypt(sessionkey, self._prA, self._nA)
        ssk_encrypt_2 = rsa_encrypt(ssk_encrypt_1, self._puB, self._nB)
        return ssk_encrypt_2
    
    #Giải mã khóa phiên để hai bên thực hiện trao đổi
    def decrypt_key(self, encrypt_sessionkey: bytes) -> bytes:
        ssk_decrypt_1 = rsa_decrypt(encrypt_sessionkey, self._prB, self._nB)
        ssk = rsa_decrypt(ssk_decrypt_1,self._puA, self._nA)
        return ssk


#test
'''
sk = key_exchange(puA, puB, prA, prB, nA, nB)
ssk = b'minhquan'

encr = sk.encrypt_key(ssk)
decr = sk.decrypt_key(encr)

print('encr: ',encr)
print('ssk: ', decr)
'''