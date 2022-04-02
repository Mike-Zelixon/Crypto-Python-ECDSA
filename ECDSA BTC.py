#These are Bitcoin parameters. See [Recommended Elliptic Curve Domain Parameters: page 15](http://www.secg.org/SEC2-Ver-1.0.pdf).
# Define a elliptic curve. y**2 = a*x**3 + b*x
a = 0; b = 7
P = 2**256 - 2**32 - 2**9 - 2**8 - 2**7 - 2**6 - 2**4 -1  # A prime.
x1 = int("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",16) 
y1 = int("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8",16)
G = (x1,y1)  # Base point
N = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",16)
privKey = 0xA0DC65FFCA799873CBEA0AC274015B9526505DAAAED385155425F7337704883E


# The order of the base point which is equal to the order of the curve in this case.
# Note: A and P must share no factor greater than 1.
def modular_inverse(A,P):
    p0, a0 = 1, 0
    p1, a1 = 0, 1
    R0, R1 = P, A%P
    while R1 != 1 and R1 != 0:
        n, R2 = divmod(R0, R1)
        p2 = p0 - n*p1 ; a2 = a0 - n*a1
        p0 = p1; a0 = a1; p1 = p2; a1 = a2
        R0 = R1; R1 = R2
    # if R1 == 0:
        # return "Error: A and P share factor "+ str(R0) + ". They must share no factor greater than 1."
    return a1 % P

def ECdouble(G,a,b,P):  # G = (x1,y1) where x1,y1 are integers.
    lambda_mod = (3*G[0]** 2 + a)% P * modular_inverse(2*G[1],P) 
    x3 = (lambda_mod * lambda_mod - G[0] - G[0]) % P
    y3 = (lambda_mod * (G[0]-x3)-G[1]) % P
    return (x3,y3)

def ECadd(A,B):
    lambda_mod = (B[1]-A[1])% P * modular_inverse(B[0]-A[0], P)
    x3 = (lambda_mod * lambda_mod - A[0] - B[0]) % P
    y3 = (lambda_mod * (A[0] - x3) - A[1]) % P
    return (x3,y3)

def ECMultiplication(G,a,b,P,N,privateKey):
    if privateKey < 1 or privateKey >= N: raise Exception("ECMultiplication(G,a,b,P,privateKey), privateKey should >0 and <N.")
    n_binary = str(bin(privateKey))[2:]
    D = G
    for i in range (1, len(n_binary)):
        D = ECdouble(D,a,b,P)
        if n_binary[i] == "1":
            D = ECadd(D, G)
    return D

pubkey = ECMultiplication(G,a,b,P,N,privKey)

print(pubkey)

print("Uncompressed pkey")
print("04" + "%064x" % pubkey[0] + "%064x" % pubkey[1])

print("copmpresed y pkey")
print(hex(pubkey[1]))


print("copmpresed x pkey")
print(hex(pubkey[0]))

print(len(hex(pubkey[0])))

print("02" + str(hex(pubkey[0])[2:]).zfill(64))

msg = 'hello'
print(msg.zfill(10))

print(str(hex(pubkey[0])[2:]).zfill(64))

print(len('791dc70b75aa995213244ad3f4886d74d61ccd3ef658243fcad14c9ccee2b0a'))