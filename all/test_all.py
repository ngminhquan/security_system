import time
import register, verify, key_genaration, exchange
from ccm import CCMmode
from gcm import GCMmode         
import random
import field
from tinyec import registry
from pydrive2.auth import GoogleAuth
from pydrive2.drive import GoogleDrive
from binascii import hexlify, unhexlify
from PIL import Image
from pydrive2.auth import GoogleAuth
from pydrive2.drive import GoogleDrive

print('0')
#Authentication
'''
gauth = GoogleAuth()
gauth.LocalWebserverAuth() 
drive = GoogleDrive(gauth)

user_file  =  'user quan'

'''
#tao mot nguoi dung moi
def create_folder(parent_folder_id):
  newFolder = drive.CreateFile({'title': parent_folder_id,"mimeType": "application/vnd.google-apps.folder"})
  newFolder.Upload()
  return newFolder

#tao cert va private key
def upload_file(title_drive_folder,file_name):
  file_list = drive.ListFile({'q': "title='%s' and mimeType='application/vnd.google-apps.folder' and trashed=false" % title_drive_folder}).GetList()
  parent_folder = file_list[0]
  file = drive.CreateFile({
  'title': file_name,
  'parents': [{'kind': 'drive#fileLink', 'id': parent_folder['id']}],
  'mimeType': 'txt'
  })
  file.Upload()
  with open(file_name,'r',encoding='UTF-8') as upload_file:
    file.SetContentString(upload_file.read())
  file.Upload()
  return file
with open('cert_&_key.txt','w',encoding='utf-8') as cp, open('key_output.txt','r',encoding='utf-8') as key, open('cert.txt','r',encoding='utf-8') as cert:
  keydata = key.read()
  certdata = cert.read()
  private_key = ''
  for value in keydata:
    private_key += value
    if value == '\n':
      break
  cp.write(str(certdata) + '\n' +private_key)
file = 'cert_&_key.txt'
def download_file(file_name, destination_path):
    # Create file instance
    file_list = drive.ListFile({'q': f"title='{file_name}'"}).GetList()

    if len(file_list) == 0:
        print(f"File '{file_name}' not found.")
        return

    # Download the file
    file_instance = file_list[0]
    file_instance.GetContentFile(destination_path)



    print('Get user request')

def move_file(file_name, source_folder_name, destination_folder_name):
    # Search for the file by name in the source folder
    source_folder = drive.ListFile({'q': f"title='{source_folder_name}' and mimeType='application/vnd.google-apps.folder'"}).GetList()
    if len(source_folder) == 0:
        print(f"Source folder '{source_folder_name}' not found.")
        return

    file_list = drive.ListFile({'q': f"title='{file_name}' and '{source_folder[0]['id']}' in parents"}).GetList()
    if len(file_list) == 0:
        print(f"File '{file_name}' not found in source folder '{source_folder_name}'.")
        return

    # Search for the destination folder by name
    destination_folder = drive.ListFile({'q': f"title='{destination_folder_name}' and mimeType='application/vnd.google-apps.folder'"}).GetList()
    if len(destination_folder) == 0:
        print(f"Destination folder '{destination_folder_name}' not found.")
        return

    # Move the file to the destination folder
    file_instance = file_list[0]
    file_instance['parents'] = [{'id': destination_folder[0]['id']}]
    file_instance.Upload()
    file_instance.FetchMetadata()

    print(f"File '{file_name}' moved successfully from '{source_folder_name}' to '{destination_folder_name}'.")

# Specify the file name, source folder name, and destination folder name

# Specify the file ID and destination path to save the file
def copy_file(file_name, source_folder_name, destination_folder_name):
    # Search for the file by name in the source folder
    source_folder = drive.ListFile({'q': f"title='{source_folder_name}' and mimeType='application/vnd.google-apps.folder'"}).GetList()
    if len(source_folder) == 0:
        print(f"Source folder '{source_folder_name}' not found.")
        return

    file_list = drive.ListFile({'q': f"title='{file_name}' and '{source_folder[0]['id']}' in parents"}).GetList()
    if len(file_list) == 0:
        print(f"File '{file_name}' not found in source folder '{source_folder_name}'.")
        return

    # Search for the destination folder by name
    destination_folder = drive.ListFile({'q': f"title='{destination_folder_name}' and mimeType='application/vnd.google-apps.folder'"}).GetList()
    if len(destination_folder) == 0:
        print(f"Destination folder '{destination_folder_name}' not found.")
        return

    # Copy the file to the destination folder
    file_instance = file_list[0]
    copied_file = file_instance.CopyToFolder(destination_folder[0]['id'])



#register cert
reg = register.register(b'123456')
m = b'minhquan'


cp = b"\x08123456\x00\x00\x00\x00\x00\x00\x00\x00\x08quan\x01Q\xbe*\x12\xf1\x81\xcc\x84\xb0y\xf3\xb8&\xa7\x1f<\xa8K\x80~\xed\xe3\xe2\xa0\xae\n\xffn\x89\x1e\\\x91`S\xda+\xaf\xfd\x1c|\x7f\x05?\xf1\x0b\xcf\xd4\xe0*\x11\x80$H$\xfd&\xf8\xc9\xfe\xc9\x0c\xe8\xc4\xb9t\xba\\\x96\x0be\xd0\xa9tl\xd9h\xf3\xa8\xc2\xf2\x98\x92C\xe0av\xad}\xec1\xe2\xdelp%\xe2\x95\x8e\xc16a\xfa\x95\x91;q]\x9f\xde\x90\xe7\xe09PEKI\xb7\x17\\zE\x80\x03b\xee\x07\xf1\x1e\x18Q}\x1c,\xef\x1b\xe0\xac\xe9F%?\xbe[D\x12\x881\x8e\r{l\xc8\x1d'\x80m\xd1X\xe1\xdbF\xfd\xb1\x88s#\xac,@\x11a\x19\xf8(\xf2f\xba\xbd\x88\t\x12\x9e\xb4\xa0\xce\x13dO\xd2#\xff&\x15Y\xban\xca\xa5\xb4\xe1\x94\xa0\xa3\x06\xe5\x83V\xf4\xc1xi\xe6hh\xca\x14\x97\x90\x99|<\x15\x15\xd711*\xb8\x9f\x8a\xf0b@ 5\xc8O e/\n\xd8\xef\xe4\xa6E\x18\xcd\x1c\x98\xd80k\xca\x18"
ver = verify.verify_cert(cp)

print('1')
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
print('2')

'''
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
'''

#ccm

key = b'128bit keylength'


nonce = unhexlify('101112131415161718191a1b')
mac_len = 16
assoc = unhexlify('000102030405060708090a0b0c0d0e0f10111213')
#msg = b''
img = Image.open('non_Dicom_image.jpg')
msg1 = img.tobytes()
ccm = CCMmode(key, nonce, assoc, mac_len)

print('3')
#gcm
'''
key = b'128bit keylength'

IV = b'12byte nonce'
A = b'hello'
tag_len = 16
#msg = b''
img = Image.open('non_Dicom_image.jpg')
msg = img.tobytes()

gcm = GCMmode(key, IV, A, tag_len)

cptext, tag = gcm.encrypt_gcm(msg)
#print(cptext)
pt = gcm.decrypt_gcm(cptext,tag)

img_copy = Image.frombytes(img.mode, img.size, pt)
img_copy.save('gcm_image_copy.jpg')
'''



count = 5
avg = 0
for i in range(count):
    start_time = time.time()
    print('4')
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


    print('5')
    #cert create...
    cpt = reg.signing(m)
    pt = ver.verify()

    #ssk agreement   
    print('6')
    #rsa
    
    encr = sk.encrypt_key(ssk)
    decr = sk.decrypt_key(encr)
    print('7')
    #ecc    
    '''  
    mk1 = calculateMK(priKey1, pubKey2)
    mk2 = calculateMK(priKey2, pubKey1)
    '''

    #ccm
    
    cp1 = ccm.encrypt(msg1)
    #   pt = ccm.verify(cp1)
    print('8')
    
    #gcm
    '''
    #cptext, tag = gcm.encrypt_gcm(msg)
    pt = gcm.decrypt_gcm(cptext,tag)
    '''

    
    #upload/download time
    print('1')
    start_time = time.time()
    gauth = GoogleAuth()
    gauth.LocalWebserverAuth() 
    drive = GoogleDrive(gauth)
    print('2')
    user_file  =  'user quan'
    #dang nhap
    if i == 0:
        create_folder(user_file)
    print('3')  
    #capcert
    upload_file(user_file,file)
    #send request
    upload_file(user_file,'user_request')
    #gui cert
    download_file('cert.txt',user_file)
    #key exhange
    copy_file('rsa_key.txt',user_file,'user A')
    
    
    end_time = time.time()

    duration = end_time - start_time
    avg += duration

avg /= count
print("Thời gian chạy: {:.5f} giây".format(avg))


