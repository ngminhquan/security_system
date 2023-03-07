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

#Ma hoa
def encrypt(mes, key, n):
    ciphertext = pow(mes, key, n)
    return ciphertext
#Giai ma
def decrypt(cp, key, n):
    plaintext = pow(cp, key, n)
    return plaintext

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

