import time
import socket
import threading
import hashlib
import itertools
import sys
from Crypto import Random
from Crypto.PublicKey import RSA
from Des import *
from ECDH import *
from ElGamal import *
import tinyec.ec as ec
import tinyec.registry as reg


# host and port input user
HOST = socket.gethostbyname(socket.gethostname())
PORT = 5050

# animating loading
done = False
def animate():
    for c in itertools.cycle(['....', '.......', '..........', '............']):
        if done:
            break
        sys.stdout.write('\rCONFIRMING CONNECTION TO SERVER '+c)
        sys.stdout.flush()
        time.sleep(0.1)


# generate initialization vector
def generate_iv():
    new_iv = bytearray()
    for i in range(8):
        new_iv += bytearray([random.randint(0, 255)])
    return new_iv

# # public key and private key
# random_generator = Random.new().read
# key = RSA.generate(1024, random_generator)
# public = key.publickey().exportKey()
# private = key.exportKey()

# # hashing the public key
# hash_object = hashlib.sha1(public)
# hex_digest = hash_object.hexdigest()

# Setting up socket
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# binding the address and port
server.connect((HOST, PORT))
# printing "Server Started Message"
thread_load = threading.Thread(target=animate)
thread_load.start()

time.sleep(4)
done = True

c = reg.get_curve("brainpoolP256r1")
while True:
    # server.send(public)
    # confirm = server.recv(1024)
    # if confirm.decode("utf-8") == "YES":
    #     server.send(hex_digest.encode())
    
    server.send(("lets talk").encode())
    confirm = server.recv(1024)
    print(confirm.decode("utf-8"))
    if confirm.decode("utf-8") == "Free to talk":
        waiting_msg = "send me your public key"
        server.send(waiting_msg.encode())

    """ Receiving ElGamal public signed key ,
        ElGamal public key = (p, a, y) = (prime, alpha, public),
        ElGamal signature = (r, s),
        Public signed key = point on the elliptic curve = (x, y)
        """
    elgamal_prime = server.recv(1024)
    prime = elgamal_prime.decode("utf-8")
    prime = int(prime, 10)

    elgamal_alpha = server.recv(1024)
    alpha = elgamal_alpha.decode("utf-8")
    alpha = int(alpha, 10)

    elgamal_public = server.recv(1024)
    public_y = elgamal_public.decode("utf-8")
    public_y = int(public_y, 10)

    elgamal_signature_r = server.recv(1024)
    r = elgamal_signature_r.decode("utf-8")
    r = int(r, 10)

    elgamal_signature_s = server.recv(1024)
    s = elgamal_signature_s.decode("utf-8")
    s = int(s, 10)

    elgamal_signature_point_x = server.recv(1024)
    bob_public_key_x = elgamal_signature_point_x.decode("utf-8")
    bob_public_key_x = int(bob_public_key_x, 10)

    elgamal_signature_point_y = server.recv(1024)
    bob_public_key_y = elgamal_signature_point_y.decode("utf-8")
    bob_public_key_y = int(bob_public_key_y, 10)


    # verify ElGamal Signature
    bob_public_key = ec.Point(c, bob_public_key_x, bob_public_key_y)
    print("Was Bob's signature verified? ")
    print(egVer(prime, alpha, public_y, r, s, compress(bob_public_key)))
    if egVer(prime, alpha, public_y, r, s, compress(bob_public_key)):
        print("Signature Verified")
        # create client key pair
        alice_private_key, alice_public_key = generate_keys()
        print(f"Alice private key is: {alice_private_key}\n and the public key is: {compress(alice_public_key)}")

        alice_prime, alice_alpha, alice_private, alice_public = egKey(256)

        alice_signature = generate_signature(alice_prime, alice_alpha, alice_private, compress(alice_public_key))
        print(f"Alice private key is: {alice_signature}")

        server.send(str(alice_prime).encode())
        time.sleep(0.5)
        print("Alice prime is:", str(alice_prime).encode())
        server.send(str(alice_alpha).encode())
        time.sleep(0.5)
        print("Alice alpha is:", str(alice_alpha).encode())
        server.send(str(alice_public).encode())
        time.sleep(0.5)
        print("Alice public is:", str(alice_public).encode())

        server.send(str(alice_signature[0]).encode())
        time.sleep(0.5)
        print("Alice r is:", str(alice_signature[0]).encode())
        server.send(str(alice_signature[1]).encode())
        time.sleep(0.5)
        print("Alice s is:", str(alice_signature[1]).encode())
        server.send(str(alice_public_key.x).encode())
        time.sleep(0.5)
        print("Alice m is:", str(alice_public_key.x).encode())
        server.send(str(alice_public_key.y).encode())
        time.sleep(0.5)
        print("Alice m is:", str(alice_public_key.y).encode())


        confirm_msg = server.recv(1024)
        if confirm_msg.decode("utf-8") == "HANDSHAKE COMPLETE":
            print("\n-----HANDSHAKE COMPLETE-----\n")

            new_shared_key = str(compress(alice_private_key * bob_public_key)).encode()
            msg=''
            while msg!='Q':
                iv = generate_iv()
                k = des(new_shared_key[0:8], CBC, iv, pad=None, padmode=PAD_PKCS5)
                msg = input("Enter message to encrypt: ")
                d = k.encrypt(msg)
                msg_signature = generate_signature(alice_prime, alice_alpha, alice_private, d)
                iv_signature = generate_signature(alice_prime, alice_alpha, alice_private, iv)
                print('Encrypted: %r' % d)
                
                # send initialization vector
                server.send(str(iv_signature[0]).encode())
                time.sleep(0.5)
                server.send(str(iv_signature[1]).encode())
                time.sleep(0.5)
                server.send(iv)
                
                # send msg
                server.send(str(msg_signature[0]).encode())
                time.sleep(0.5)
                server.send(str(msg_signature[1]).encode())
                time.sleep(0.5)
                server.send(d)
        print("End")
        sys.exit(0)
