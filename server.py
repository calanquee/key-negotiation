
#!/usr/bin/python
# -*- coding: UTF-8 -*-

import socket
import base64
import binascii
from gmssl import sm2, func
from gmssl import sm3, func
from gmssl.sm4 import CryptSM4, SM4_ENCRYPT, SM4_DECRYPT

crypt_sm4 = CryptSM4()
server_private_key = '00B9AB0B828FF68872F21A837FC303668428DEA11DCD1B24429D0C99E24EED83D5'
server_public_key='B9C9A6E04E9C91F7BA880429273747D7EF5DDEB0BB2FF6317EB00BEF331A83081A6994B8993F3F5D6EADDDB81872266C87C018FB4162F5AF347B483E24620207'
client_public_key='C4F0072F8BE009ED349CB2DA9FC48C7C0C19BFD8989AFAB3E8C5D594F1F51BE6BD968B968DDE8D1F0E5BAA893455F1F27440395ECAAB8B7EF802D77E632B660E'
sm2_crypt = sm2.CryptSM2(public_key=client_public_key, private_key=server_private_key)

# 建立一个服务端
server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
server.bind(('localhost',8080)) #绑定要监听的端口
server.listen(5) #开始监听 表示可以使用五个链接排队
msg_fault=b'negotiation teminated!'
while True:# conn就是客户端链接过来而在服务端为期生成的一个链接实例
    conn,addr = server.accept() #等待链接,多个链接的时候就会出现问题,其实返回了两个值
    #    print(conn,addr)
    try:
        msg1 = conn.recv(1024)  #接收msg1
        print('I am server!')
        if msg1==b'key negotiation request':
            print('msg1')
            print(msg1)
            msg2=b'ack'
            conn.send(msg2) #发送msg2
            print('msg2')
            print(msg2)
            msg3 = conn.recv(1024)  #接收msg3
            print('msg3')
            print(msg3)
            sign = msg3[134:262]
            hash_data = msg3[0:134]
            hash= sm3.sm3_hash(func.bytes_to_list(hash_data))
            hash=str.encode(hash)
            verify = sm2_crypt.verify(sign, hash)
            if verify==True:
                if (msg3[0:7]==b'client1')&(msg3[7:14]==b'server1'):
                    N1=msg3[14:18]
                    enc_msg3=msg3[18:134]
                    dec_msg3=sm2_crypt.decrypt(enc_msg3)
                    Ntmp=dec_msg3[16:20]
                    if Ntmp==N1:
                        N2=N1+b'1'
                        ks=dec_msg3[0:16]
                        print('negotiation successfully!')
                        print('communication key:')
                        print(ks)
                        crypt_sm4.set_key(ks, SM4_ENCRYPT)
                        msg4 = crypt_sm4.crypt_ecb(N2)
                        conn.send(msg4)
                    else:
                        conn.send(msg_fault)
            else:
                conn.send(msg_fault)
            
            conn.close()
    except ConnectionResetError as e:
        print('关闭了正在占线的链接！')
    conn.close()

