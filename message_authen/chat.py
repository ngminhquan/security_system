import ccm

#test
'''
key = b'sixteenbytes key'
nonce = b'12345678'
mac_len = 16
assoc = b'day la associated data'
msg = b'nguyen minh quan'

chat = ccm.CCMmode(key, nonce, assoc, mac_len)
cp = chat.encrypt(msg)
print(cp)

pt = chat.verify(cp)
print(pt)
'''