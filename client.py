import binascii
import socket
import os
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def read_line(sock: socket.socket, end='\n'):
   msg = ''
   char = ''
   while char != end:
      msg += char
      char = sock.recv(1).decode()
      if len(char) == 0:
         raise OSError('Connection closed')
   return msg

clientsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
clientsocket.connect(('localhost', 8089))
publickey = RSA.importKey(clientsocket.recv( 1024 ), passphrase=None)
print(' Received public key')

random_key = os.urandom(16)  # 16 bytes or 128 bits one time session key for AES
print("session key will sent to Server:",  binascii.hexlify(random_key))

encryptor = PKCS1_OAEP.new(publickey)
encrypted = encryptor.encrypt(random_key)
print("Encrypted session key:", encrypted)
clientsocket.send(encrypted)

cipher = AES.new(random_key,AES.MODE_ECB)

'''key = b'Sixteen byte key'
cipher = AES.new(key,AES.MODE_ECB)
nonce = cipher.nonce
ciphertext, tag = cipher.encrypt_and_digest(encrypted)
print(ciphertext)'''
'''

first_server_msg = clientsocket.recv(1024).decode('utf-8')
print(first_server_msg)

a = random.randint(0, 100)  # private to client
x_alice = calc_exp(a)  # not secret
clientsocket.send(bytes(json.dumps({"alice_i": x_alice.real, "alice_j": x_alice.imag}), "UTF-8"))

# convert key to a 16 byte string
extended_key = (str(computed_key) * (int(16 / len(str(computed_key))) + 1))[:16]  # hack extension, not a secure key
dec_suite = AES.new(extended_key.encode('utf-8'), AES.MODE_ECB)
enc = AES.new(extended_key.encode('utf-8'), AES.MODE_ECB)
'''
release = ['taken' , 'weak' , 'bam' , 'Successfully' , 'Accounts_Information' , 'Join_requests' ,
           'NO account with this number had been registered' ,'there is no Such Join request' , 'Destination account is wrong' ,
           'You can not Deposit from another account' , 'Not enough money' , 'Withdraw' , 'You can not Withdraw from another account' ,
           'ERROR ACCESS CONTROL']
while True:
   server_msg = clientsocket.recv(1024)
   if len(server_msg) > 0:
      dec_server_msg = cipher.decrypt(server_msg).decode()
      print("Received from Bob: \nencrypted: {} \ndecrypted: {}".format(server_msg, dec_server_msg))
      if any(s in dec_server_msg for s in release):
         continue
      if 'HLT(0)' in dec_server_msg :
         break
   msg = input("Provide message for server:\n")
   msg = msg + ' ' * (16 - (len(msg) % 16))
   enc_msg = cipher.encrypt(msg.encode('utf-8'))
   assert (len(enc_msg) % 16 == 0)
   clientsocket.send(enc_msg)

