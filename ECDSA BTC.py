# These are the STANDARD Bitcoin parameters based off the Secp256k1 ECDSA standard.

# See [Recommended Elliptic Curve Domain Parameters: page 15](http://www.secg.org/SEC2-Ver-1.0.pdf)

# Also see https://en.bitcoin.it/wiki/Secp256k1

# Elliptic Curve Formula is y**2 = a*x**3 + b*x

import hashlib

# Introduce the standard variable for ECDSA maths: a,b, P, x1, y1, G, N.
a = 0
b = 7

# P is a VERY LARGE PRIME NUMBER
P = 2 ** 256 - 2 ** 32 - 2 ** 9 - 2 ** 8 - 2 ** 7 - 2 ** 6 - 2 ** 4 - 1

# Start off with a random point on the curve known as G
x1 = int("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16)
y1 = int("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)

# Base point is G (VERY IMPORTANT)

# The base point G in compressed form in hex below, you will find is a combination of x1 and y1.

# G = "04 79BE667E F9DCBBAC 55A06295 CE870B07 029BFCDB 2DCE28D9 59F2815B 16F81798 483ADA77 26A3C465 5DA4FBFC 0E1108A8 FD17B448 A6855419 9C47D08F FB10D4B8"

# x1 and y1 are the coordinates on the curve for G
G = (x1, y1)

# N as defined by the secp256k1
# N is a large natural prime number that is ALMOST as big as 2**256
N = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)

# To geta private key, get the hex format of ANY random 256-bit number. Using an example below.
privKey = 0xA0DC65FFCA799873CBEA0AC274015B9526505DAAAED385155425F7337704883E


# The order of the base point which is equal to the order of the curve in this case.
# Note: A and P must share no factor greater than 1.
def modular_inverse(A, P):
    p0, a0 = 1, 0
    p1, a1 = 0, 1
    R0, R1 = P, A % P
    while R1 != 1 and R1 != 0:
        n, R2 = divmod(R0, R1)
        p2 = p0 - n * p1
        a2 = a0 - n * a1
        p0 = p1
        a0 = a1
        p1 = p2
        a1 = a2
        R0 = R1
        R1 = R2
    if R1 == 0:
        return f"Error: A and P share factor {R0}. They must share no factor greater than 1."
    return a1 % P


# G = (x1,y1) where x1,y1 are integers.

# Elliptic curve DOUBLING function (modular math)
def ECdouble(G, a, b, P):
    lambda_mod = (3 * G[0] ** 2 + a) % P * modular_inverse(2 * G[1], P)
    x3 = (lambda_mod * lambda_mod - G[0] - G[0]) % P
    y3 = (lambda_mod * (G[0] - x3) - G[1]) % P
    return (x3, y3)


# Elliptic curve ADDITION function (modular math)
def ECadd(A, B):
    lambda_mod = (B[1] - A[1]) % P * modular_inverse(B[0] - A[0], P)
    x3 = (lambda_mod * lambda_mod - A[0] - B[0]) % P
    y3 = (lambda_mod * (A[0] - x3) - A[1]) % P
    return (x3, y3)


# FINAL FUNCTION of EC Multiplication using the two function above (addition and doubling)

# At the end of the day, this all one big double-and-add operation going over the random bits of the private key

# 1. First take the generator point and double it
# 2. Then following along the random bits of the private key
# 3. If there's a 0 double the point, if there's a 1 double and ADD
# 4. Do this 255 times along the random bits (1's and 0's)

# This is all using modular ECDSA math G, a,b,P,N are all STANDARD ECDSA parameters.
# The last function parameter (private key) is where you multiply whatever you want to multiply.
def ECMultiplication(G, a, b, P, N, privateKey):
    if privateKey < 1 or privateKey >= N: raise Exception(
        "ECMultiplication(G,a,b,P,privateKey), privateKey should >0 and <N.")

    # Take the binary format of the private key which is "1010101010" and convert to a string
    n_binary = str(bin(privateKey))[2:]

    D = G

    # Create a loop going over the 1's and 0's of the BINARY version of the private key
    for i in range(1, len(n_binary)):
        # For extra fun you can print the entire process

        # Double the point (by default) whether it's a 1 or 0
        # If you come across a 0, double and move onto the next bit
        D = ECdouble(D, a, b, P)
        # If you come across a 1, add as well (using ECDSA addition)
        if n_binary[i] == "1":
            D = ECadd(D, G)
    return D


# THE FINAL PRODUCT
# How a public key is derived using the inputs from EC multiplication and point doubling
# You multiply the private key 255 times using double and add (ECDSA style) to retrieve the public key coordinates
pubkey = ECMultiplication(G, a, b, P, N, privKey)

# Follow the formula below to get the uncompressed public key seen in signed transactions on the blockchain
print("Uncompressed Public Key")
print("04" + "%064x" % pubkey[0] + "%064x" % pubkey[1])

# To get the uncompressed Y public key (y coordinate of the public key)
print("Compressed Y Public Key")
print(hex(pubkey[1]))

# To get the uncompressed X public key (x coordinate of the public key)
print("Compressed X Public")
print(hex(pubkey[0]))

# SIGNING A TRANSACTION WITH A PRIVATE KEY
# This is where the magic of ECDSA truly shows itself
# We first create a DIGITAL SIGNATURE with the private key with certain parameters R and S

# 1. Pick a VERY large RANDOM 256-bit random number K. NEVER USE THE SAME RANDOM NONCE TWICE! This is only an example!
random_k = 103126131841958791146404268911178809217925293548762628603419007750312325684063
print(f'Random none: {random_k}')

# 2. Multiply this random number by the Generator point seen earlier in this script
k_times_g = ECMultiplication(G, a, b, P, N, random_k)

# 3. Mod the X-coordinate of the multiplied result by N to get R
r = k_times_g[0] % N
print(f'R is {r}')

# 4. Pick the message you want to sign and convert it to SHA-256
message = b'This is incredibly random'
hashofm = hashlib.sha256(message).hexdigest()
hashofm_int = int(hashofm, 16)
print(f'Mesasge: {message.decode()}, \nHash of message: {hashofm} \nHash int {hashofm_int}\n')

# 5. To get S (signature) follow the formula below
# (Hash of message + R + Private Key) * (Modular Invese of K by N) modded by N
s = ((hashofm_int + r * privKey) * (modular_inverse(random_k, N))) % N
print(f'S is {s}')

# VERIFYING A DIGITAL SIGNATURE WITH THE PUBLIC KEY

# 1. First get W by applying modular inverse of your signature over N
w = modular_inverse(s, N)
print(f'W is {w}')

# Multiply ((hash_of_message * w) % N) using ECDSA multiplication by G to get U1
u1 = ECMultiplication(G, a, b, P, N, (hashofm_int * w) % N)

# Multiply ((r*w) % N) using ECDSA multiplication by your PUBLIC KEY to get u2
u2 = ECMultiplication(pubkey, a, b, P, N, (r * w) % N)

# Add u1 and u2 using elliptic curve ADDITION to create u3
u3 = ECadd(u1, u2)

# Verify that r is equal to X coordinate u3[0] (x coordinate on the curve)
print(f'U1 is {u1}\nU2 is {u2}\nU3 is {u3}')
print(f'R {r} == {u3[0]} ???')

# If R is equal to the X-coordinate of U3 the message is valid !!!
print(r == u3[0])

# You have just completed an ECDSA multiplication, addition, signing, and verification!
# Congratulations!!!
