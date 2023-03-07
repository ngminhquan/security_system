import struct, sys
#Doc tu string 1 so hex
def rdnum16(a):
    ret =""
    for i in a: #Tao string chua cac ki tu so
        if (i.isalnum()):
            ret+=i
        else:
            break
    return int(ret,16)
#Doc tu file 1 so dec
def rdnum10(a):
    ret =""
    for i in a:
        if (i.isnumeric()):
            ret+=i
        else:
            break
    return int(ret)

'''
# Lay cap q, p
with open ("p_q.txt", "r") as f:
    p = rdnum16(f.readline())
    q = rdnum16(f.readline())
# Lay cap key e, d
with open ("key_output.txt", "r") as f:         #chuyen sang đọc đầu vào bên register
    e = rdnum10(f.readline())
    d = rdnum10(f.readline())

# Lay message 128 bit
phi =(q-1)*(p-1)
n = q*p
#lam txt nhap message
m = 123456
'''


#Ma hoa
def encrypt(mes, key, n):
    ciphertext = pow(mes, key, n)
    return ciphertext
#Giai ma
def decrypt(cp, key, n):
    plaintext = pow(cp, key, n)
    return plaintext


'''
# Bat dau ma hoa
encr = pow(m,e,n)
decr = pow(encr,d,n)

cp = str(hex(encr))
pt = str(hex(decr))

print('encrypt: ',encr)
print('decrypt: ', decr)
'''
'''
import gmpy2

# Khởi tạo các giá trị
p = gmpy2.mpz('36551857810237059959')
q = gmpy2.mpz('34617677746801239509')
n = p * q
phi = (p - 1) * (q - 1)
e = gmpy2.mpz('939210407647999299948957255085848502077')
d = gmpy2.invert(e, phi)
print(d)
m = gmpy2.mpz('123456')

# Mã hóa
c = pow(m, e, n)
print("Mã hóa: ", c)

# Giải mã
m2 = pow(c, d, n)
print("Giải mã:", m2)
'''

#convert bytes -> long and long -> bytes
def long_to_bytes(n, blocksize=0):

    if n < 0 or blocksize < 0:
        raise ValueError("Values must be non-negative")

    result = []
    pack = struct.pack

    # Fill the first block independently from the value of n
    bsr = blocksize
    while bsr >= 8:
        result.insert(0, pack('>Q', n & 0xFFFFFFFFFFFFFFFF))
        n = n >> 64
        bsr -= 8

    while bsr >= 4:
        result.insert(0, pack('>I', n & 0xFFFFFFFF))
        n = n >> 32
        bsr -= 4

    while bsr > 0:
        result.insert(0, pack('>B', n & 0xFF))
        n = n >> 8
        bsr -= 1

    if n == 0:
        if len(result) == 0:
            bresult = b'\x00'
        else:
            bresult = b''.join(result)
    else:
        # The encoded number exceeds the block size
        while n > 0:
            result.insert(0, pack('>Q', n & 0xFFFFFFFFFFFFFFFF))
            n = n >> 64
        result[0] = result[0].lstrip(b'\x00')
        bresult = b''.join(result)
        # bresult has minimum length here
        if blocksize > 0:
            target_len = ((len(bresult) - 1) // blocksize + 1) * blocksize
            bresult = b'\x00' * (target_len - len(bresult)) + bresult

    return bresult


def bytes_to_long(s):
    """Convert a byte string to a long integer (big endian).

    In Python 3.2+, use the native method instead::

        >>> int.from_bytes(s, 'big')

    For instance::

        >>> int.from_bytes(b'\x00P', 'big')
        80

    This is (essentially) the inverse of :func:`long_to_bytes`.
    """
    acc = 0

    unpack = struct.unpack

    # Up to Python 2.7.4, struct.unpack can't work with bytearrays nor
    # memoryviews
    if sys.version_info[0:3] < (2, 7, 4):
        if isinstance(s, bytearray):
            s = bytes(s)
        elif isinstance(s, memoryview):
            s = s.tobytes()

    length = len(s)
    if length % 4:
        extra = (4 - length % 4)
        s = b'\x00' * extra + s
        length = length + extra
    for i in range(0, length, 4):
        acc = (acc << 32) + unpack('>I', s[i:i+4])[0]
    return acc