import _rsa as rsa
from _rsa import long_to_bytes, bytes_to_long

#Đọc private và public key của 2 user A, B
'''
prA = 
puA = 
nA = 

prB = 
puB = 
nB = 
'''

#Mã hóa và giải mã qua rsa
'''
def rsa_encrypt(text: bytes, e: int, n: int) -> bytes:
    text = bytes_to_long(text)
    ciphertext = rsa.encrypt(text, e, n)
    ciphertext = long_to_bytes(ciphertext)
    return ciphertext

def rsa_decrypt(text: bytes) -> bytes:
    text = bytes_to_long(text)
    decrypted_message = rsa.decrypt(text, d, n)
    decrypted_message = long_to_bytes(decrypted_message)
    return decrypted_message
'''

#Trao đổi khóa phiên
class key_exchange(object):
    def __init__(self, session_key) -> None:
        pass
