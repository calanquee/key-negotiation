
#!/usr/bin/python
# -*- coding: UTF-8 -*-

import socket# 客户端 发送一个数据，再接收一个数据
import base64
import binascii
import codecs
from gmssl import sm2, func
from gmssl import sm3, func
from gmssl.sm4 import CryptSM4, SM4_ENCRYPT, SM4_DECRYPT

crypt_sm4 = CryptSM4()
client_public_key='C4F0072F8BE009ED349CB2DA9FC48C7C0C19BFD8989AFAB3E8C5D594F1F51BE6BD968B968DDE8D1F0E5BAA893455F1F27440395ECAAB8B7EF802D77E632B660E'
client_private_key='EDA00D26E0D14F2419D52F1AC56ABAD3292A7102E29DE3E3C790A5AD997A6529'
server_public_key='B9C9A6E04E9C91F7BA880429273747D7EF5DDEB0BB2FF6317EB00BEF331A83081A6994B8993F3F5D6EADDDB81872266C87C018FB4162F5AF347B483E24620207'
sm2_crypt = sm2.CryptSM2(public_key=server_public_key, private_key=client_private_key)

client = socket.socket(socket.AF_INET,socket.SOCK_STREAM) #声明socket类型，同时生成链接对象
client.connect(('localhost',8080))
#msg = '欢迎访问菜鸟教程！'  #strip默认取出字符串的头尾空格


print('I am client!')
msg1='key negotiation request'
print('msg1:')
print(msg1)
client.send(msg1.encode())
msg2 = client.recv(1024) #接收一个信息，并指定接收的大小 为1024字节
#assert data == dec_data
if msg2==b'ack':
    print('msg2')
    print(msg2) #输出我接收的信息
    ks=b'1234567890abcdef' #会话密钥16字节
    N1=b'1234'
    enc_msg3 = sm2_crypt.encrypt(ks+N1)
    enc_msg3_len=len(enc_msg3)#116字节
    msg3=b'client1'+b'server1'+N1+enc_msg3
    hash= sm3.sm3_hash(func.bytes_to_list(msg3))
    hash=str.encode(hash)
    hash_len=len(hash)
    #    print(hash_len)#64字节
    random_hex_str = func.random_hex(sm2_crypt.para_len)
    sign = sm2_crypt.sign(hash, random_hex_str)
    sign = str.encode(sign)
    #print(sign)
    sign_len=len(sign)
    #print(sign_len)
    msg3=msg3+sign
    client.send(msg3)  #发送一条信息 python3 只接收btye流
    print('msg3')
    print(msg3)
    msg4 = client.recv(1024)
    crypt_sm4.set_key(ks, SM4_DECRYPT)
    decrypt_value = crypt_sm4.crypt_ecb(msg4)
    print(decrypt_value)
    if decrypt_value==N1+b'1':
        print('negotiation successfully!')
        print('communication key:')
        print(ks)





client.close() #关闭这个链接
