from aes import long_to_bytes, bytes_to_long, keySetupDec, keySetupEnc, encrypt, decrypt
import struct
import binascii
import math
from PIL import Image
import time


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
        self.rk_enc = keySetupEnc(key)
        self.rk_dec = keySetupDec(key)

    #aes encrypt & decrypt, use in cmac
    def _aes_encrypt(self, block: bytes) -> bytes:
        return encrypt(block)

    def _aes_decrypt(self, block: bytes) -> bytes:
        return decrypt(block)

    #xor function
    def _xor(self, a: bytes, b: bytes) -> bytes:
        return bytes([x ^ y for x, y in zip(a, b)])
    

    #increment function used in generate counter mode
    def incre_func(self, X: bytes, s: int):
        X = bin(int.from_bytes(X, byteorder='big', signed=False))[2:] # binary string
        lsb_x = (int(X[-s:], 2) + 1) % (2**s)
        lsb_x = format(lsb_x, f'0{s}b')
        inc_s = X[:len(X) - s] + lsb_x
        inc_s = int(inc_s, 2).to_bytes((len(inc_s) + 7) // 8, byteorder='big') # byte string
        return inc_s

    #multiplication operation on block
    def mul(self, x: bytes, y: bytes) -> bytes:
        x = bytes_to_long(x)
        y = bytes_to_long(y)

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
        return long_to_bytes(z)   

    #GHASH function
    def ghash_func(self, x: bytes, H: bytes) -> bytes:
        y = self.mul(x[0: 16], H)
        for i in range(16, int(len(x)/16)):
            pre = self._xor(x[i: i+16], y)
            y = self.mul(pre, H)
        return y
    
    #GCTR function
    def GCTR(self, icb: bytes, x: bytes):
        n = math.ceil(len(x)/16)
        cb = icb
        cipher = b''
        for i in range(0, n-1):
            cp = self._aes_encrypt(cb)
            y = self._xor(x[16 * i: 16 * i + 16], cp) 
            cb = self. incre_func(cb, 32)
            cipher += y
        cp = (self._aes_encrypt(cb))[:len(x) - 16*(n-1)]
        y_ = self._xor(x[16*(n-1):], cp)
        cipher += y_
        return cipher
    
    #Algorithm for the Authenticated Encryption Function
    def encrypt_gcm(self, P: bytes) -> bytes:
        _hash = self._aes_encrypt(b'\x00' * 16)

        #define block J0
        if len(self._IV) == 12:
            j0 = self._IV + b'\x00'*3+b'\x01'
        else:
            s = 16 * math.ceil(len(self._IV)/16) - len(self._IV)
            j0 = self.ghash_func(self._IV + b'\x00'*(s + 8) + long_to_bytes(len(self._IV), 8), _hash)

        # #mã hóa plaintexts
        cipher = self.GCTR(j0, P)

        #define u and v: lưu độ dài của C: ciphertext và A: additional authen data
        u = 16 * math.ceil(len(cipher)/16) - len(cipher)
        v = 16 * math.ceil(len(self._A)/16) - len(self._A)

        #define a block s as follow
        A_gen = self._A + b'\x00'*v + cipher + b'\x00'*u + long_to_bytes(len(self._A), 8) + long_to_bytes(len(cipher), 8) 
        s = self.ghash_func(A_gen, _hash)
        #tag of the plaintext
        tag = self.GCTR(j0, s)[:self._tag_len]
        return cipher,tag
    
    #authencicated decryption function
    def decrypt_gcm(self, cp: bytes, tag: bytes):
        if len(tag) != self._tag_len:
            print('FAIL')
        _hash = self._aes_encrypt(b'\x00'*16)
        
        #define block j0
        if len(self._IV) == 12:
            j0 = self._IV + b'\x00'*3+b'\x01'
        else:
            s = 16 * math.ceil(len(self._IV)/16) - len(self._IV)
            j0 = self.ghash_func(self._IV + b'\x00'*(s + 8) + long_to_bytes(len(self._IV), 8), _hash)
        
        #find plaintext
        plaintext = self.GCTR(j0, cp)

        #define u and v: lưu độ dài của C: ciphertext và A: additional authen data
        u = 16 * math.ceil(len(cp)/16) - len(cp)
        v = 16 * math.ceil(len(self._A)/16) - len(self._A)

        #define a block s as follow
        A_gen = self._A + b'\x00'*v + cp + b'\x00'*u + long_to_bytes(len(self._A), 8) + long_to_bytes(len(cp), 8) 
        s = self.ghash_func(A_gen, _hash)

        tag_new = self.GCTR(j0, s)[:self._tag_len]
        if tag_new == tag:
            return plaintext
        else:
            return 'FAIL'
        
#test vector
'''
key = b'sixteen bit key.'
IV = b'12byte nonce'
A = b'hello'
tag_len = 16
msg = b'minhquan iot k65 dai hoc bach khoa ha noi minhquan iot k65 dai hoc bach khoa ha noi minhquan iot k65 dai hoc bach khoa ha noi'

gcm = GCMmode(key, IV, A, tag_len)

cptext, tag = gcm.encrypt_gcm(msg)
print('cp: ', cptext)
pt = gcm.decrypt_gcm(cptext, tag)
print('pt: ', pt)
'''










key = b'128bit keylength'

IV = b'12byte nonce'
A = b'hello'
tag_len = 16
#msg = b''
img = Image.open('non_Dicom_image.jpg')
msg = img.tobytes()
msg = b'minh quan 123456'

gcm = GCMmode(key, IV, A, tag_len)

cptext, tag = gcm.encrypt_gcm(msg)
#print(cptext)
pt = gcm.decrypt_gcm(cptext,tag)

import time
import register, verify, key_genaration, exchange
import random
import field
from tinyec import registry

#t1

#register cert
reg = register.register(b'123456')
m = b'minhquan'


cp = b"\x08123456\x00\x00\x00\x00\x00\x00\x00\x00\x08quan\x01Q\xbe*\x12\xf1\x81\xcc\x84\xb0y\xf3\xb8&\xa7\x1f<\xa8K\x80~\xed\xe3\xe2\xa0\xae\n\xffn\x89\x1e\\\x91`S\xda+\xaf\xfd\x1c|\x7f\x05?\xf1\x0b\xcf\xd4\xe0*\x11\x80$H$\xfd&\xf8\xc9\xfe\xc9\x0c\xe8\xc4\xb9t\xba\\\x96\x0be\xd0\xa9tl\xd9h\xf3\xa8\xc2\xf2\x98\x92C\xe0av\xad}\xec1\xe2\xdelp%\xe2\x95\x8e\xc16a\xfa\x95\x91;q]\x9f\xde\x90\xe7\xe09PEKI\xb7\x17\\zE\x80\x03b\xee\x07\xf1\x1e\x18Q}\x1c,\xef\x1b\xe0\xac\xe9F%?\xbe[D\x12\x881\x8e\r{l\xc8\x1d'\x80m\xd1X\xe1\xdbF\xfd\xb1\x88s#\xac,@\x11a\x19\xf8(\xf2f\xba\xbd\x88\t\x12\x9e\xb4\xa0\xce\x13dO\xd2#\xff&\x15Y\xban\xca\xa5\xb4\xe1\x94\xa0\xa3\x06\xe5\x83V\xf4\xc1xi\xe6hh\xca\x14\x97\x90\x99|<\x15\x15\xd711*\xb8\x9f\x8a\xf0b@ 5\xc8O e/\n\xd8\xef\xe4\xa6E\x18\xcd\x1c\x98\xd80k\xca\x18"
ver = verify.verify_cert(cp)

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
sk = exchange.key_exchange(puA, puB, prA, prB, nA, nB)
ssk = b'128bit keylength'



# example key pairs
dA =b'81DB1EE100150FF2EA338D708271BE38300CB54241D79950F77B063039804F1D'

x_qA =b'44106E913F92BC02A1705D9953A8414DB95E1AAA49E81D9E85F929A8E3100BE5'
y_qA =b'8AB4846F11CACCB73CE49CBDD120F5A900A69FD32C272223F789EF10EB089BDC'

dB =b'55E40BC41E37E3E2AD25C3C6654511FFA8474A91A0032087593852D3E7D76BD3'

x_qB =b'8D2D688C6CF93E1160AD04CC4429117DC2C41825E1E9FCA0ADDD34E6F1B39F7B'
y_qB =b'990C57520812BE512641E47034832106BC7D3E8DD0E4C7F1136D7006547CEC6A'

x_Z =b'89AFC39D41D3B327814B80940B042590F96556EC91E6AE7939BCE31F3A18BF2B'
y_Z =b'49C27868F4ECA2179BFD7D59B1E3BF34C1DBDE61AE12931648F43E59632504DE'

# take sample parameters
samplecurve = registry.get_curve("brainpoolP256r1")
p = samplecurve.field.p
a = samplecurve.a
b = samplecurve.b
x_g = samplecurve.g.x
y_g = samplecurve.g.y
n = samplecurve.field.n
curve = field.Curve(a, b, p, n, x_g, y_g)

def compress_point(point):
    return hex(point.x) + hex(point.y % 2)[2:]

def calcPubKey(priKey: int):
    pubKey = priKey * curve.g
    return pubKey

def calculateMK(selfPriKey: int, receivedPubKey):
    mk = receivedPubKey * selfPriKey
    return mk

priKey1 = int(dA, 16)
priKey2 = int(dB, 16)
pubKey1 = priKey1 * curve.g
pubKey2 = priKey2 * curve.g

list = []
count = 20
avg = 0
for i in range(30):
    for i in range(count):
        start_time = time.time()
            # Tim so i
        while(1):
            i = random.randrange(pow(2, 64),pow(2,64+1))
            if key_genaration.primetest(i) == True:
                break
            else:
                continue
        # Tim so y
        while(1):
            y = random.randrange(pow(2,64),pow(2,64+1))
            if (y == i):
                continue
            if (key_genaration.primetest(y)== True):
                break
            else:
                continue
        p = str(hex(i))
        q = str(hex(y))
        x, y = 0, 0
        x = key_genaration.rdnumfile(p)
        y = key_genaration.rdnumfile(q)
        result = key_genaration.listed(x, y)



        #cert create...
        cpt = reg.signing(m)
        pt = ver.verify()

        #ssk agreement   

        #rsa
        encr = sk.encrypt_key(ssk)
        decr = sk.decrypt_key(encr)

        #ecc   
        '''   
        mk1 = calculateMK(priKey1, pubKey2)
        mk2 = calculateMK(priKey2, pubKey1)
        '''

        # Đoạn code cần đo thời gian thực thi
        cptext = gcm.encrypt_gcm(msg)
        pt = gcm.decrypt_gcm(cptext,tag)

        end_time = time.time()

        duration = end_time - start_time
        avg += duration

    avg /= count
    list.append(avg/1.9 * 1000)
    #print("Thời gian chạy: {:.3f} mili giây".format(avg/2 * 1000))

print(list)

