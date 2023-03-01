#Hung
import hashlib
import cv2
#
def hex_to_bin(s):
    trans = {
        "0": "0000",
        "1": "0001",
        "2": "0010",
        "3": "0011",
        "4": "0100",
        "5": "0101",
        "6": "0110",
        "7": "0111",
        "8": "1000",
        "9": "1001",
        "A": "1010",
        "B": "1011",
        "C": "1100",
        "D": "1101",
        "E": "1110",
        "F": "1111"}
    binary = ""
    for i in range(len(s)):
        binary = binary + trans[s[i]]
    return binary
# sinh ra otp gom 6 ky tu bat ki gom chu cai va so su fung thu vien secret
def generate_otp(num):
    if (num < 10):
        ch = chr(num + ord('0'))
    elif (num < 36):
        ch = chr(num - 10 + ord('a'))
    else:
        ch = chr(num - 36 + ord('A'))
    return ch

# lay du lieu tu anh
def get_bytes_string_image(image_path):
    img = cv2.imread(image_path)
    return img.tobytes()

def sha_resize(bytes_string):
    return hashlib.sha256(bytes_string).hexdigest()[:60].upper()

def otp(image_hex_string):
    split = []
    for i in range(0, len(image_hex_string), 10):
        split.append(int(hex_to_bin(image_hex_string[i:i + 10])) % 62)
    otp = []
    for i in split:
        otp.append(generate_otp(int(i)))
    return otp

#main
def id_user(image_path):
    img_byte_string = get_bytes_string_image(image_path)
    img_sha_hex_string = sha_resize(img_byte_string)
    list = otp(img_sha_hex_string)
    return ''.join(list)





