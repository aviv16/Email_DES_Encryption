from Des import *
from ECDH import *
from ElGamal import *
import tinyec.ec as ec
import tinyec.registry as reg

"""creating the key pairs"""
alice_private_key, alice_public_key = generate_keys()
bob_private_key, bob_public_key = generate_keys()

"""ElGamal signature"""
prime, alpha, private, public = egKey(256)
alice_signature = generate_signature(prime, alpha, private, compress(alice_public_key))
bob_signature = generate_signature(prime, alpha, private, compress(bob_public_key))

"""ElGamal signature verification"""
isValidAlice = egVer(prime, alpha, public, alice_signature[0], alice_signature[1], compress(alice_public_key))
print("Is the sig valid? ", isValidAlice)

new_shared_key = str(compress(alice_private_key * bob_public_key)).encode()
k = des(new_shared_key[0:8], CBC, b"\0\0\0\0\0\0\0\0", pad=None, padmode=PAD_PKCS5)

msg = input("Enter message to encrypt: ")
d = k.encrypt(msg)
print('Encrypted: %r' % d)
print("Decrypted: %r" % k.decrypt(d).decode("utf-8"))
