test = b'doviethung'
import aes
print(len(test))
for j in test:
    print(j)

test= bin(aes.bytes_to_long(test))
print(len(test))
