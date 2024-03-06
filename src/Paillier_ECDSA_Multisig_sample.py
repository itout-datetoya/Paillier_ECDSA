from phe import paillier
from random import randint
from ecc import S256Point, Signature, PrivateKey

A = 0
B = 7
P = 2**256 - 2**32 - 977
N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141

G = S256Point(
    0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
    0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)


sk_a = PrivateKey(randint(0, N))
pk_a = sk_a.point

sk_b = PrivateKey(randint(0, N))
pk_b = sk_b.point

pk = pk_a + pk_b # No need for Alice and Bob to cooperate for compute the public key.
z = randint(0, 2**256)

# Alice
k_a = sk_a.deterministic_k(z)
k_a_inv = pow(k_a, N-2, N)

# Bob
k_b = sk_b.deterministic_k(z)
k_b_inv = pow(k_b, N-2, N)


# Alice
public_key, private_key = paillier.generate_paillier_keypair()
R_a = k_a * G # send to Bob
encrypted_secret_a = public_key.encrypt(sk_a.secret) # send to Bob


# Bob
R = k_b * R_a
r = R.x.num # send to Alice
s_former = ((z + r * sk_b.secret) * k_b_inv) % N
encrypted_s_latter = encrypted_secret_a * (r * k_b_inv % N)
encrypted_s_prime = encrypted_s_latter + s_former # send to Alice


# Alice
s = private_key.decrypt(encrypted_s_prime) * k_a_inv % N
if s > N / 2:
    s = N - s
sig = Signature(r, s)



if pk.verify(z, sig):
    print("Verify")
else:
    print("Fail")