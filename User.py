import re , hashlib , binascii , os


def hash_password(password):
    """Hash a password for storing."""
    salt = hashlib.sha256(os.urandom(60)).hexdigest().encode('ascii')
    pwdhash = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'),
                                  salt, 100000)
    pwdhash = binascii.hexlify(pwdhash)
    return (salt + pwdhash).decode('ascii')


def verify_password(stored_password, provided_password):
    """Verify a stored password against one provided by user"""
    salt = stored_password[:64]
    stored_password = stored_password[64:]
    pwdhash = hashlib.pbkdf2_hmac('sha512',
                                  provided_password.encode('utf-8'),
                                  salt.encode('ascii'),
                                  100000)
    pwdhash = binascii.hexlify(pwdhash).decode('ascii')
    return pwdhash == stored_password
def password_check(password : str):
    """
    Verify the strength of 'password'
    Returns a dict indicating the wrong criteria
    A password is considered strong if:
        8 characters length or more
        1 digit or more
        1 symbol or more
        1 uppercase letter or more
        1 lowercase letter or more
   """

    # calculating the length
    length_error = len(password) < 8

    # searching for digits
    digit_error = re.search(r"\d", password) is None

    # searching for lowercase
    lowercase_error = re.search(r"[a-z]", password) is None

    # searching for uppercase
    uppercase_error = re.search(r"[A-Z]", password) is None

    # searching for symbols
    symbol_error = re.search(r"[ !#$%&'()*+,-./[\\\]^_`{|}~"+r'"]', password) is None

    # overall result
    password_ok = not ( length_error or digit_error or uppercase_error or lowercase_error or symbol_error )

    return password_ok

def is_number(s):
    try:
        int(s)
        return True
    except ValueError:
        return False
class User:
    def __init__(self  , passw):
        self.passw = passw
        self.Join_requests = []
class Acount:
    def __init__(self , account_type  : str , amount :str ,  owner :str , integerity :str , confidentialy : str) :
        self.account_type = account_type
        self.amount  = amount
        self.owner = owner
        self.integerity = integerity
        self.confidentialy = confidentialy
        #... etc
    def __str__(self):
        return '(Account type : {} ) (amount : {}) (owner {}) (integrity {}) (confidentially {}) \n'.format(self.account_type ,
                                                                                                self.amount , self.owner ,
                                                                                                self.integerity , self.confidentialy)

'''user_dict = {}

user_dict['john'] = User(1234)
user_dict['joe']  = User(1111)

print(user_dict)

account_dic ={}
#after creating user joe
account_dic['joe']  = {}
#after creating user john
account_dic['john'] = {}

account_dic['joe']['1234']  = Acount('joe' , 'Top_secret' , 'k' , 'k' , 'k')
account_dic['john']['0000'] = Acount('john' , 'High_level' , 'k' , 'k' , 'k')

print(account_dic)

for key in account_dic['joe']: 
    print(key) #1234
'''