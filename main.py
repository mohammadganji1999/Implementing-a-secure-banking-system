
import random
import string
import time
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
import socket
import threading

import User
from User import *
import cryptography
BAM_punish = 3

Blp_dict  = {'Unclassified' : 0 ,    'Confidential' : 1 , 'Secret'  : 2 , 'TopSecret' :   3}
Biba_dict = {'Untrusted'    : 0 , 'SlightlyTrusted' : 1 , 'Trusted' : 2 , 'VeryTrusted' : 3}

def welcome_page(c , cipher):
    # msg = server_vocabulary[random.randint(0, 2)]
    msg =  "\n Hi \n Please choose one of below Options \n 1.Login \n 2.Register \n 3.HLT  "
    msg = msg + ' ' * (16 - (len(msg) % 16))
    enc_msg = cipher.encrypt(msg.encode('utf-8'))
    c.send(enc_msg)
    time.sleep(0.5)
    client_msg = c.recv(1024)
    if len(client_msg) > 0:
        dec_client_msg = cipher.decrypt(client_msg)
        print("Received from Client: \nencrypted: {} \ndecrypted: {}".format(client_msg, dec_client_msg))
        return dec_client_msg
    return None

def get_user_pass(c , cipher  ):
    msg =  'Please enter username password or enter -1 to back to main menu'
    msg = msg + ' ' * (16 - (len(msg) % 16))
    enc_msg = cipher.encrypt(msg.encode('utf-8'))
    c.send(enc_msg)
    time.sleep(0.5)
    user  = c.recv(1024)
    return user

def Login_page(c , cipher):
    user = get_user_pass(c , cipher)
    userpass = cipher.decrypt(user)  #type : <class 'bytes'>
    if is_number(userpass):
        if int(userpass) == -1:
            return -1 , ' '
    if len(user) > 0  :
        username , password = userpass.decode().split()
        if username in user_dict and verify_password(user_dict[username].passw , password) :
            print("Received from User: \nuser: {} \npass: {}".format(username, password))
            return 1 , username
    return 0 , ' '

def Register_page(c , cipher ):
    user = get_user_pass(c, cipher)
    userpass = cipher.decrypt(user)  #type : <class 'bytes'>
    if is_number(userpass):
        if int(userpass) == -1:
            return -1

    if len(user) > 0  :
        username , password = userpass.decode().split()
        if username in user_dict:
            msg = 'taken username try another one please'
            msg = msg + ' ' * (16 - (len(msg) % 16))
            enc_msg = cipher.encrypt(msg.encode('utf-8'))
            c.send(enc_msg)
            return 0
        if not password_check(password):
            msg = "weak password , a password should have 8 character length or more , 1 (digit,symbol,uppercase and lowercase)" \
                  " or more "
            msg = msg + ' ' * (16 - (len(msg) % 16))
            enc_msg = cipher.encrypt(msg.encode('utf-8'))
            c.send(enc_msg)
            return 0
        #OK :) register
        user_dict[username] = User(hash_password(password))
        account_dic[username] = {}
        print("Received from User: \nuser: {} \npass: {}".format(username, hash_password(password)))
        return 1

def read_line(sock: socket.socket, end='\n'):
    msg = ''
    char = ''
    while char != end:
        msg += char
        char = sock.recv(1).decode()
        if len(char) == 0:
            raise OSError('Connection closed')
    return bytes(msg)

def account_validation(number : str , for_join = False):
    for user in account_dic :
        for account in account_dic[user]:
            if number == account :
                if for_join:
                    return user
                return False
    if for_join:
        return None
    return True

def generate_account_number(size=10, chars = string.digits):
    while True:
        generated = str(random.randint(1 , 9)) + ''.join(random.choice(chars) for _ in range(size - 1))
        if account_validation(generated):
            return generated


def send_message(c, cipher, param : str):
    param = param + ' ' * (16 - (len(param) % 16))
    enc_msg = cipher.encrypt(param.encode('utf-8'))
    c.send(enc_msg)
    time.sleep(0.5)


def Show_accounts(username , c , cipher):
    Accounts_information = 'Accounts_Information'
    for account in account_dic[username]:
        Accounts_information += str(account_dic[username][account])

    send_message(c , cipher , Accounts_information)


def Show_join_requests(username, c, cipher):
    Join_requests = 'Join_requests : '
    for request in user_dict[username].Join_requests:  # request : ['john' , '123456789']
        Join_requests += 'user ({}) requests for account ({})\n'.format(request[0] , request[1])

    send_message(c , cipher , Join_requests)


def check_and_remove(username, requestuser, requestaccount):
    for request in user_dict[username].Join_requests:
        if request[0] == requestuser and request[1] == requestaccount:
            return True
    return False


def Update_Sources(acount_number, amount):
    for user in account_dic:
        for account in account_dic[user]:
            if account == acount_number:
                val_Source = int(account_dic[user][account].amount) - int(amount)
                account_dic[user][account].amount = str(val_Source)


def Update_Dests(acount_number, amount):
    for user in account_dic:
        for account in account_dic[user]:
            if account == acount_number:
                val_Dest = int(account_dic[user][account].amount) + int(amount)
                account_dic[user][account].amount = str(val_Dest)





def manage_account(c , cipher , username ):
    while True :
        print(account_dic)
        print(user_dict)
        print(user_dict[username].Join_requests)
        '''print(user_dict)
        print(account_dic)
        print(user_dict['john'].Join_requests)'''
        Show_join_requests(username, c, cipher)
        msg = "\nhelp--  Create [account_type] [amount] [conf_label] [integrity_label]  " \
              "\nShow_MyAccount" \
              "\nJoin [account_no]" \
              "\nAccept [username] [Account_number] [conf_label] [integrity_label]" \
              "\nDeposit [from_account_no] [to_account_no] [amount]"

        msg = msg + ' ' * (16 - (len(msg) % 16))
        enc_msg = cipher.encrypt(msg.encode('utf-8'))
        c.send(enc_msg)
        time.sleep(0.5)
        client_msg = c.recv(1024)
        if len(client_msg) > 0:
            dec_client_msg = cipher.decrypt(client_msg)  #  type <class : bytes>
            print("Received from Alice: \nencrypted: {} \ndecrypted: {}".format(client_msg, dec_client_msg))
            if 'Create' in dec_client_msg.decode():
                account_list = dec_client_msg.decode().split()
                account_number = generate_account_number()
                account_dic[username][account_number] = Acount(account_type=account_list[1] , amount=account_list[2] ,
                                                            confidentialy=account_list[3] , integerity=account_list[4] ,
                                                            owner=username)
                send_message(c , cipher , 'Successfully created Account account number : ' + account_number )
                print(account_dic)
            elif 'Show_MyAccount' in dec_client_msg.decode():
                Show_accounts(username , c , cipher)

            elif 'Accept' in dec_client_msg.decode():
                acceptance_list = dec_client_msg.decode().split()
                if check_and_remove(username , acceptance_list[1] , acceptance_list[2]):
                    account_dic[acceptance_list[1]][acceptance_list[2]] = Acount(account_dic[username][acceptance_list[2]].account_type ,
                                                                                 account_dic[username][acceptance_list[2]].amount ,
                                                                                 username , integerity=acceptance_list[4] ,
                                                                                 confidentialy=acceptance_list[3])
                    user_dict[username].Join_requests.remove([acceptance_list[1] , acceptance_list[2]])
                    send_message(c , cipher , 'Successfully Accepted Join request')

                else:
                    send_message(c , cipher , 'there is no Such Join request')

            elif 'Join' in dec_client_msg.decode():
                AccountN = dec_client_msg.decode().split()[1]
                owner = account_validation(AccountN , for_join=True)
                if owner is None:
                    send_message(c , cipher , 'NO account with this number had been registered')
                else:
                   real_owner = account_dic[owner][AccountN].owner
                   user_dict[real_owner].Join_requests.append([username , AccountN])
                   send_message(c, cipher, 'Successfully Join request sent')

            elif 'Deposit' in dec_client_msg.decode():
                Deposit_list = dec_client_msg.decode().split() # Deposit [from_account_no] [to_account_no] [amount]
                if Deposit_list[1] in account_dic[username]:
                    if not account_validation(Deposit_list[2]):
                        if int(account_dic[username][Deposit_list[1]].amount) < int(Deposit_list[3]):
                            send_message(c, cipher, 'Not enough money')
                        else:
                            Update_Sources(Deposit_list[1] , Deposit_list[3])
                            Update_Dests(Deposit_list[2] , Deposit_list[3])
                    else:
                        send_message(c , cipher , 'Destination account is wrong')
                else:
                    send_message(c , cipher , 'You can not Deposit from another account')

            elif 'Withdraw' in  dec_client_msg.decode(): #Withdraw [from_account_no] [amount]
                Withdraw_list =  dec_client_msg.decode().split()
                if Withdraw_list[1] in account_dic[username]:
                    if int(account_dic[username][Withdraw_list[1]].amount) < int(Withdraw_list[2]):
                        send_message(c, cipher, 'Not enough money')
                    else:
                        owner_conf  = account_dic[account_dic[username][Withdraw_list[1]].owner][Withdraw_list[1]].confidentialy
                        owner_integ = account_dic[account_dic[username][Withdraw_list[1]].owner][Withdraw_list[1]].integerity
                        my_conf  = account_dic[username][Withdraw_list[1]].confidentialy
                        my_integ = account_dic[username][Withdraw_list[1]].integerity
                        if account_dic[username][Withdraw_list[1]].owner == username or (Blp_dict[my_conf] <= Blp_dict[owner_conf] and
                                                                                         Biba_dict[my_integ] >= Biba_dict[owner_integ]):
                            Update_Sources(Withdraw_list[1] , Withdraw_list[2])

                        else:
                            send_message(c ,cipher , 'ERROR ACCESS CONTROL')
                else:
                    send_message(c, cipher, 'You can not Withdraw from another account')
            else:
                return


def serve_client(c: socket.socket, addr):
        try:
            print("connection requested from {}".format(addr[1]))
            while True:
                try:
                    print('  Sending public key')
                    c.send(publickey.exportKey(format='PEM', passphrase=None, pkcs=1))
                    shkey = c.recv(128)
                    decryptor = PKCS1_OAEP.new(key)
                    decrypted = decryptor.decrypt(shkey)
                    print('Decrypted session key:',  binascii.hexlify(decrypted))
                    cipher = AES.new(decrypted, AES.MODE_ECB)
                    break
                    #print("Computed shared key: {}   ".format(type(computed_key)))
                except:
                    c.send(bytes(""" Error parsing. Please send again """, "UTF-8"))

            # convert key to a 16 byte string
            # hack extension, not a secure key
            #extended_key = (str(computed_key) * (int(16 / len(str(computed_key))) + 1))[:16]
            #dec_suite = AES.new(extended_key.encode('utf-8'), AES.MODE_ECB)
            #enc = AES.new(extended_key.encode('utf-8'), AES.MODE_ECB)
            while True:
                    #msg = server_vocabulary[random.randint(0, 2)]
                    dec_client_msg  = welcome_page(c , cipher)
                    if int(dec_client_msg.decode()) == 3 :  # HLT
                        msg = 'HLT(0)' + ' ' * (16 - (len('HLT(0)') % 16))
                        enc_msg = cipher.encrypt(msg.encode('utf-8'))
                        c.send(enc_msg)
                        break

                    elif int(dec_client_msg.decode()) == 1 : # Log_in
                        login_code = 0
                        bam = -1
                        while (login_code == 0):
                            bam += 1
                            if bam == BAM_punish :
                                bam = -1
                                msg = "You'll got bam try again after " + str(10) + " seconds"
                                send_message(c , cipher , msg)
                                time.sleep(10)
                                #print("after baming user {}".format(addr))
                            login_code , username = Login_page(c, cipher)

                        if login_code == -1 :
                            continue
                        if login_code == 1 :  # logged Successfully
                            manage_account(c , cipher , username)



                    elif int(dec_client_msg.decode()) == 2:  # Register
                        Register_code = 0
                        while (Register_code == 0):
                            Register_code   = Register_page(c, cipher )

                        if Register_code == -1:
                            continue
                        if Register_code == 1 : # Successful Registration
                            pass



                    else :
                        break
            c.close()
        except OSError as error:
            print(error)
        finally:
            c.close()

def start_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('localhost', 8089))
    s.listen(5)
    try:
        while True:
            s.settimeout(0.1)
            while True:
                try:
                    c, addr = s.accept()
                    break
                except socket.timeout:
                    continue
            c.settimeout(None)

            threading.Thread(target=serve_client, args=(c, addr), daemon=True).start()

    except OSError as error:
        print(error)
    except KeyboardInterrupt:
        pass

from Crypto.Cipher import PKCS1_OAEP

user_dict = {}
user_dict['john'] = User(hash_password('1234'))
user_dict['joe']  = User(hash_password('1111'))

account_dic ={}
#after creating user joe
account_dic['joe']  = {}
#after creating user john
account_dic['john'] = {}

#def __init__(self, account_type: str, amount: int, owner: str, integerity: str, confidentialy: str):


account_dic['joe']['1111']  = Acount(account_type='joe' ,  amount='100' , owner='joe'  , integerity='Trusted' , confidentialy='Confidential')
account_dic['john']['1234'] = Acount(account_type='john' , amount='100' , owner='john' , integerity='Trusted' , confidentialy='Unclassified')
user_dict['joe'].Join_requests.append(['john' , '1111'])

random_generator = Random.new().read
key = RSA.generate(1024)
publickey = key.publickey() # pub key export for exchange
msg = b'A message for encryption'
encryptor = PKCS1_OAEP.new(publickey)
encrypted = encryptor.encrypt(msg)
#print("Encrypted:", binascii.hexlify(encrypted))

decryptor = PKCS1_OAEP.new(key)
decrypted = decryptor.decrypt(encrypted)
#print('Decrypted:', decrypted)
start_server()
