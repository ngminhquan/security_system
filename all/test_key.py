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

prA = 19716162942487440881048260018159766091289957818673774797574881523084271497152960759935711608917778952468999414397403572907222306063846624891166986722912011
puA = 13005862105430627309810534673378326726464790260963073928916147419885996726894558330890920776746568072753186194130823163016416355881524750797783966545917571

pA = 0x10c9cece03c6c6666d3a13504fca3866dbc0b4b5a77adba3abae8e84574d16367
qA = 0x179c4d4a0631ac5888a7bbd282e86106287d394e1c6fb8a1667adc92f58ab7655
nA = pA*qA

prB = 514079204596045738253196156424672504894627151173105777739957168957040025897982451477020133964854755510604531813226024186066648144776741244683589705336501
puB = 4353522681153549849200001950205372436247701624760392766981083068623410062251657077800711329754528558391577993462835811501162374840190910478641937453955741

pB = 0x17c35d0031450a91ef26ee83a548a42eba58e45512a3022e4edaf42c63e80dbbf
qB = 0x115d2436460491a0f26a273eb46488517aa8ef6b8e9779d67b7d692dc105a65e1
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

#print(mk1 == mk2)

count = 20
avg = 0
for i in range(count):
    start_time = time.time()

    # Đoạn code cần đo thời gian thực thi

    #key gen
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
    '''
    encr = sk.encrypt_key(ssk)
    decr = sk.decrypt_key(encr)
    '''

    # Perform further operations with the shared secret key
    # (e.g., derive a symmetric encryption key)

    #ecc   
    '''
    mk1 = calculateMK(priKey1, pubKey2)
    mk2 = calculateMK(priKey2, pubKey1)
    '''


    
    
    end_time = time.time()

    duration = end_time - start_time
    avg += duration

avg /= count
print("Thời gian chạy: {:.5f} giây".format(avg))


