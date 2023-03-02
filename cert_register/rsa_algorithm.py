from cert_verify import verify
verify.abc()

'''
def compmod(a,b,n):	#Tinh a^b mod n
    bi = str(bin(b))#Lay string cac bit cua b
    l = len(bi)     #Lay do dai string
#Thuat toan bat dau
    c = 0
    f = 1
    for i in range(l):	# Bat dau tu most important bit
        c = 2*c
        f = (f*f)%n        
        if bi[i] == '1':
            c = c+1    
            f = (f*a)%n
    #Tinh toan
    return f
#Ma hoa
def rsa(mes, key, n):
    ret = compmod(mes, key, n)
    return ret
#Giai ma
def de_rsa(mes, key, n):
    ret = compmod(mes, key, n)
    return ret
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
# Lay cap q, p
with open ("PaQ.txt", "r") as f:
    p = rdnum16(f.readline())
    q = rdnum16(f.readline())
# Lay cap key e, d
with open ("Caccapkey.txt", "r") as f:
    e = rdnum10(f.readline())
    d = rdnum10(f.readline())
# Lay message 128 bit
phi =(q-1)*(p-1)
n = q*p
with open ("Mes.txt", "r") as f:
    m = rdnum16(f.readline())

# Bat dau ma hoa
encr = pow(m,e,n)
decr = pow(encr,d,n)
with open ("Result1.txt", "w") as f:
    f.write(str(hex(encr))+"\n")
with open ("Result2.txt", "w") as f:
    f.write(str(hex(decr))+"\n")
'''