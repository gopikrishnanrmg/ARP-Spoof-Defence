from scapy import all as scapy
from io import StringIO
import netifaces as ni
import sys, socket
import os
import subprocess
import sys
import random
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

def authentication(ip):
    key = RSA.import_key(open("keys/public_key_"+ip+".pem").read())
    cipher = PKCS1_OAEP.new(key)
    randomNum = str(random.random())
    randomNum = bytes(randomNum, 'utf-8')
    ciphertext = cipher.encrypt(randomNum)

    host = ip
    port = 5000

    client_socket = socket.socket()
    client_socket.connect((host, port))

    client_socket.send(ciphertext)
    data = client_socket.recv(2048)

    #print(data)
    client_socket.close()


    #print(data,"==" ,randomNum)
    if randomNum == data:
        return True
    else:
        return False


def reverseSpoof(data):
    global honeypotMAC
    ip = ni.ifaddresses('eth0')[ni.AF_INET][0]['addr']
    IP_target    = data[1]
    MAC_target   =  data[0]

    IP_spoofed      = ip
    MAC_spoofed     = honeypotMAC #"02:42:0a:09:00:0f"

    print("SENDING SPOOFED ARP REPLY......")

    ether = scapy.Ether()
    ether.dst = MAC_target
    ether.src = MAC_spoofed

    arp = scapy.ARP()
    arp.psrc  = IP_spoofed
    arp.hwsrc = MAC_spoofed
    arp.pdst  = IP_target
    arp.hwdst = MAC_target
    arp.op = 2
    frame = ether/arp
    scapy.sendp(frame)


def arpReq(data):
    global backup
    results, unanswered = scapy.arping(data[1])
    auth = authentication(data[1])
    if len(results) > 1 or results[0][1].hwsrc != data[0] or auth:
        if len(results) > 1:
            print("ARP spoof detected!, multiple replies")
        elif results[0][1].hwsrc != data[0]:
            print("ARP spoof detected!, mistmatched records!")
        else:
            print("ARP spoof detected!, authentication failed!")
        os.system("ip neighbour delete "+ data[1] +" dev eth0")

        for record in backup:
            record = record.split(" ")
            if record[0] == data[1]:
                os.system("ip neighbour add "+ record[0] +" lladdr "+ record[4] +" dev eth0 nud stale")
                print("Repaired ARP cache!")

        reverseSpoof(data)

    else:
        print("ARP spoof not detected")
        backup = subprocess.run(["ip","neighbour","show"], capture_output=True)
        backup = backup.stdout.decode("utf-8").split("\n")[:-1]


def sniffPackets():
    print("Sniffing...")
    capture = scapy.sniff(filter='arp',count=1)
    list = []
    old_stdout = sys.stdout
    sys.stdout = data = StringIO()
    capture.show()
    sys.stdout = old_stdout
    data = data.getvalue().split(" ")
    if data[4] != "who":
       list.append(data[6])
       list.append(data[8][:-1])
    return list

if len(sys.argv) != 2:
    raise ValueError('Please provide Honeypot MAC address')
 
honeypotMAC = sys.argv[1]

backup = subprocess.run(["ip","neighbour","show"], capture_output=True)
backup = backup.stdout.decode("utf-8").split("\n")[:-1]

while True:
    data = sniffPackets()
    if len(data) == 0:
        continue
    arpReq(data)

