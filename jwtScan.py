import base64
import os.path
from hashlib import sha256
from hashlib import sha384
from hashlib import sha512
import hmac
import sys


def get_HmacAES256(data, key):
    key = key.encode('utf-8')
    message = data.encode('utf-8')
    sign = base64.b64encode(hmac.new(key, message, digestmod=sha256).digest())
    sign = str(sign, 'utf-8')
    return sign


def get_HmacAES384(data, key):
    key = key.encode('utf-8')
    message = data.encode('utf-8')
    sign = base64.b64encode(hmac.new(key, message, digestmod=sha384).digest())
    sign = str(sign, 'utf-8')
    return sign


def get_HmacAES512(data, key):
    key = key.encode('utf-8')
    message = data.encode('utf-8')
    sign = base64.b64encode(hmac.new(key, message, digestmod=sha512).digest())
    sign = str(sign, 'utf-8')
    return sign


def Brute_Force(dic, jwt_composition, algorithm):
    jwt_header = jwt_composition[0]
    jwt_payload = jwt_composition[1]
    jwt_signature = jwt_composition[2]
    dic_reader = open(dic, "r")
    jwt_try_signature = jwt_header + "." + jwt_payload
    if algorithm == "-256":
        for row in dic_reader:
            row = row.split()
            row = row[0]
            sign = get_HmacAES256(jwt_try_signature, row)
            sign = sign.replace("=", "")
            sign = sign.replace("+", "-")
            sign = sign.replace("/", "_")
            if sign == jwt_signature:
                return row
    elif algorithm == "-384":
        for row in dic_reader:
            row = row.split()
            row = row[0]
            sign = get_HmacAES384(jwt_try_signature, row)
            sign = sign.replace("=", "")
            sign = sign.replace("+", "-")
            sign = sign.replace("/", "_")
            if sign == jwt_signature:
                return row
    elif algorithm == "-512":
        for row in dic_reader:
            row = row.split()
            row = row[0]
            sign = get_HmacAES512(jwt_try_signature, row)
            sign = sign.replace("=", "")
            sign = sign.replace("+", "-")
            sign = sign.replace("/", "_")
            if sign == jwt_signature:
                return row
    return 0


algorithm, jwt, dic = sys.argv[1:4]
logo = open("./img/logo.txt")
print("Plz Wait For A While...")
logo_string = logo.read()
print(logo_string)
if os.path.isfile(jwt):
    jwt_reader = open(jwt, "r")
    jwt_string = jwt_reader.read()
else:
    jwt_string = jwt
jwt_composition = jwt_string.split(".", -1)
result = Brute_Force(dic, jwt_composition, algorithm)
if result:
    print("Jwt's key is " + result)
else:
    print("Unable to find key for jwt")
