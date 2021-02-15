import socket
import hashlib
import os
import time
import itertools
import threading
import sys
from Des import *
from ECDH import *
from ElGamal import *
import tinyec.ec as ec
import tinyec.registry as reg


# server address and port number input from admin
host = socket.gethostbyname(socket.gethostname())
port = 5050
#boolean for checking server and port
check = False
done = False


def animate(client, address):
    for c in itertools.cycle(['....', '.......', '..........', '............']):
        if done:
            break
        sys.stdout.write('\rCHECKING IP ADDRESS AND NOT USED PORT '+c)
        sys.stdout.flush()
        time.sleep(0.1)
    sys.stdout.write('\r -----SERVER STARTED. WAITING FOR CLIENT-----\n')


try:
    #setting up socket
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen()
    check = True
except BaseException:
    print("-----Check Server Address or Port-----")
    check = False

if check is True:
    # server Quit
    shutdown = False
# printing "Server Started Message"

# binding client and address
client, address = server.accept()
thread_load = threading.Thread(target=animate, args=(client, address))
thread_load.start()
print("CLIENT IS CONNECTED. CLIENT'S ADDRESS ->", address)
print("\n-----WAITING FOR PUBLIC KEY & PUBLIC KEY HASH-----\n")

time.sleep(4)
done = True


#DH elliptic curve
c = reg.get_curve("brainpoolP256r1")

first_msg = client.recv(2048).decode("utf-8")
if first_msg == "lets talk":
    client.send(("Free to talk").encode())
    second_msg = client.recv(1024).decode("utf-8")
if second_msg == "send me your public key":
    # creating session key
    """creating the key pair"""
    bob_private_key, bob_public_key = generate_keys()

    """ Generating and sending ElGamal public key = (p, a, y)"""
    prime, alpha, private, public = egKey(256)
    client.send(str(prime).encode())
    time.sleep(0.5)
    client.send(str(alpha).encode())
    time.sleep(0.5)
    client.send(str(public).encode())
    time.sleep(0.5)
    bob_signature = generate_signature(prime, alpha, private, compress(bob_public_key))
    """ Sending encryption signed key"""
    client.send(str(bob_signature[0]).encode())
    time.sleep(0.5)
    client.send(str(bob_signature[1]).encode())
    time.sleep(0.5)
    client.send(str(bob_public_key.x).encode())
    time.sleep(0.5)
    client.send(str(bob_public_key.y).encode())


    """ Receiving ElGamal public signed key, ElGamal public key = (p, a, y)"""
    alice_prime = client.recv(1024)
    alice_prime = alice_prime.decode("utf-8")
    alice_prime = int(alice_prime)

    alice_alpha = client.recv(1024)
    alice_alpha = alice_alpha.decode("utf-8")
    alice_alpha = int(alice_alpha, 10)

    alice_public = client.recv(1024)
    alice_public = alice_public.decode("utf-8")
    alice_public = int(alice_public, 10)

    elgamal_signature_r = client.recv(1024)
    r = elgamal_signature_r.decode("utf-8")
    r = int(r)

    elgamal_signature_s = client.recv(1024)
    s = elgamal_signature_s.decode("utf-8")
    s = int(s, 10)

    elgamal_signature_m_x = client.recv(1024)
    alice_public_key_x = elgamal_signature_m_x.decode("utf-8")
    alice_public_key_x = int(alice_public_key_x, 10)

    elgamal_signature_m_y = client.recv(1024)
    alice_public_key_y = elgamal_signature_m_y.decode("utf-8")
    alice_public_key_y = int(alice_public_key_y, 10)

    alice_public_key = ec.Point(c, alice_public_key_x, alice_public_key_y)

    # verify ElGamal Signature
    isVerified = egVer(alice_prime, alice_alpha, alice_public, r, s, compress(alice_public_key))
    print("Was Alice's signature verified? ", isVerified)
    print("\n-----HANDSHAKE COMPLETE-----")
    if isVerified:
        print("Signature Verified\nh")
        confirm_msg = "HANDSHAKE COMPLETE"
        client.send(confirm_msg.encode())

        # ECDH shared key (session key)
        new_shared_key = str(compress(bob_private_key * alice_public_key)).encode()
        decrypted_msg=''
        while decrypted_msg != 'Q':
            # get new initialization vector from client
            iv_s1_byte = client.recv(1024)
            iv_s1 = iv_s1_byte.decode("utf-8")
            iv_s1 = int(iv_s1, 10)
            iv_s2_byte = client.recv(1024)
            iv_s2 = iv_s2_byte.decode("utf-8")
            iv_s2 = int(iv_s2, 10)
            # initialization vector from client
            iv = client.recv(1024)
            print("successfully received initialization vector")
            
            msg_s1_byte = client.recv(1024)
            msg_s1 = msg_s1_byte.decode("utf-8")
            msg_s1 = int(msg_s1, 10)
            msg_s2_byte = client.recv(1024) 
            msg_s2 = msg_s2_byte.decode("utf-8")
            msg_s2 = int(msg_s2, 10)
            # message from client
            alice_msg = client.recv(1024)
            
            isVerified = egVer(alice_prime, alice_alpha, alice_public, msg_s1, msg_s2, alice_msg)
            if not isVerified:
                print("Signature verification failed")
            else:
                print("Message Related Signature Verified")
                # decrypting message from the client
                k = des(new_shared_key[0:8], CBC, iv, pad=None, padmode=PAD_PKCS5)
                decrypted_msg=k.decrypt(alice_msg).decode("utf-8")
                print("Decrypted: %r" % decrypted_msg)
        print("The End")
     

else:
    print("\n-----PUBLIC KEY HASH DOESNOT MATCH-----\n")
