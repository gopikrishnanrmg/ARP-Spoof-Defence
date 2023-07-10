import socket
import netifaces as ni
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

def server_program():
    global cipher
    host = socket.gethostname()
    port = 5000

    server_socket = socket.socket()
    server_socket.bind((host, port))
    while True:
        server_socket.listen(2)
        conn, address = server_socket.accept()
        #print("Connection from: " + str(address))
        data = conn.recv(2048)
        #print(data)
        ciphertext = cipher.decrypt(data)
        print("Decrypted", ciphertext)
        conn.send(ciphertext)
        conn.close()

ip = ni.ifaddresses("eth0")[ni.AF_INET][0]["addr"]
key = RSA.import_key(open("keys/private_key_"+str(ip)+".pem").read())
cipher = PKCS1_OAEP.new(key)


server_program()
