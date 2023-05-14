import struct
import binascii
import sha256
import rsa_ as rsa

#Cặp khóa của CA (dùng để kí, giải mã cert)

p = 303953423661034916093096644870386209181207882190109489802359407814502178204142880456445845400114949390822809700510973804482088607676275375723726772362211612693844376393028541697210763896181255064839684797019197009985280246124161704265682628819777866911221637690304160465221385233230380509247180540947915227323
q = 342653238510123978583794870696242261004803035710088264440592564382719948800396946614784025713205403091499081989303381711601358363277859151979593270123243511681701790226412922512915715094845777002654106954264206822893542568341511517207826332082521242203378259625570761581107399830541200268038439973411801314211
e = 58586957418369495224362637833285779962524952838512825773193522788704424363062507175839201425023817062221566236988488060015620365304181095272689538303568528435715695497302179664466905546903933272496909594445287352269089861047855052941457726673530474894667890816834863527316149894015124446848126505918091307529419852193697076187682262834261000089180672890250362336875616829452264897275479344987082219836310327557251283263894138190531331072449636735334855778799565389702018638126966987304956184436325298453541919619469047723885790031829147985298676066674175975771367167157473914209040515270148337365532558615606453666693
d = 60888307194732098836418130500621005400154488806885389863827584218335898445301811441782188676231273630717821720858508421492130956966195244475211078850661321717432556234216511467770425208590451532535886355568945514146676426356422420012852173429530564118592070656010236260101289622474400192695511846804178035065754857706839021596389005386710538426428527180236963701464008225469357790634753580506885152493742227070827648145147242402028606246919622852604006518326301816545827201296600032308297649079961994946031402905808646474432777480424013688804935664469093536027249917336151959154331679559132127715955041090207745880597
phi =(q-1)*(p-1)
n = q*p



class verify_cert(object):
    def __init__(self, ciphertext: bytes) -> None:
        self._ciphertext: bytes = ciphertext
        self._len_cp: int = len(ciphertext)

        #Đọc nonce và độ dài nonce từ ciphertext
        flags = self._ciphertext[:1]
        q  = struct.unpack('B', flags)
        q = int.from_bytes(q, byteorder='big') + 1
        len_nonce = 15 - q
        self.nonce = self._ciphertext[1:len_nonce+1]

        #Đọc message và độ dài từ ciphertext
        msg_len = self._ciphertext[1+len_nonce:16]
        self.msg_len: int = int.from_bytes(msg_len, byteorder='big')
        self.msg: bytes = self._ciphertext[-self.msg_len:]

        self.len_payload = 16 + self.msg_len
        self.payload = self._ciphertext[:self.len_payload]

    #RSA decrypt, using PU & PK
    def rsa_decrypt(self, text: bytes) -> bytes:
        text = sha256.bytes_to_long(text)
        decrypted_message = rsa.decrypt(text, d, n)
        decrypted_message = sha256.long_to_bytes(decrypted_message)
        return decrypted_message

    #verify received msg
    def verify(self) -> bytes:          #verify the received msg
        
        #cắt đoạn cert từ bản mã, băm lại cert + giải mã đoạn digest -> so sánh để xác thực

        #initial hash
        cipher_digest = self._ciphertext[self.len_payload:]
        _hash = self.rsa_decrypt(cipher_digest)

        #find test hash
        new_hash = sha256.hash_function(self.payload)

        #print('ihash: ', _hash)
        #print('ahash: ', new_hash)
        if _hash != new_hash:
            #print('INVALID')
            return 0
        else:
            #return 'VALID'
            return 0

    #Dựa vào plaintext_gen để viết hàm ngược lại tìm nonce, msg
    '''
    def plaintext_gen(self) -> bytes:
        # Formatting control information and nonce
        self.q:int = 15 - len(self._nonce)  # length of Q, the encoded message length

        flags: int = self.q - 1
        b_0: bytes = struct.pack("B", flags) + self._nonce + sha256.long_to_bytes(len(self._msg), self.q)
     
        b = b_0 + self._msg
        return b
    '''

cp = b"\x08123456\x00\x00\x00\x00\x00\x00\x00\x00\x08quan\x01Q\xbe*\x12\xf1\x81\xcc\x84\xb0y\xf3\xb8&\xa7\x1f<\xa8K\x80~\xed\xe3\xe2\xa0\xae\n\xffn\x89\x1e\\\x91`S\xda+\xaf\xfd\x1c|\x7f\x05?\xf1\x0b\xcf\xd4\xe0*\x11\x80$H$\xfd&\xf8\xc9\xfe\xc9\x0c\xe8\xc4\xb9t\xba\\\x96\x0be\xd0\xa9tl\xd9h\xf3\xa8\xc2\xf2\x98\x92C\xe0av\xad}\xec1\xe2\xdelp%\xe2\x95\x8e\xc16a\xfa\x95\x91;q]\x9f\xde\x90\xe7\xe09PEKI\xb7\x17\\zE\x80\x03b\xee\x07\xf1\x1e\x18Q}\x1c,\xef\x1b\xe0\xac\xe9F%?\xbe[D\x12\x881\x8e\r{l\xc8\x1d'\x80m\xd1X\xe1\xdbF\xfd\xb1\x88s#\xac,@\x11a\x19\xf8(\xf2f\xba\xbd\x88\t\x12\x9e\xb4\xa0\xce\x13dO\xd2#\xff&\x15Y\xban\xca\xa5\xb4\xe1\x94\xa0\xa3\x06\xe5\x83V\xf4\xc1xi\xe6hh\xca\x14\x97\x90\x99|<\x15\x15\xd711*\xb8\x9f\x8a\xf0b@ 5\xc8O e/\n\xd8\xef\xe4\xa6E\x18\xcd\x1c\x98\xd80k\xca\x18"
a = verify_cert(cp)
pt = a.verify()

 