# From public key to address
# Reference: https://medium.freecodecamp.org/how-to-create-a-bitcoin-wallet-address-from-a-private-key-eca3ddd9c05f
#            https://docs.python.org/2/library/hashlib.html
import codecs  #If not installed: "pip3 install codecs"
import hashlib
# UK0 is a demo public key.
UK0 = ['0791dc70b75aa995213244ad3f4886d74d61ccd3ef658243fcad14c9ccee2b0a','a762fbc6ac0921b8f17025bb8458b92794ae87a133894d70d7995fc0b6b5ab90']
UK1 = "04" + UK0[0] + UK0[1]
UK2 = hashlib.sha256(codecs.decode(UK1, 'hex'))
h = hashlib.new('ripemd160')
h.update(UK2.digest())
UK3 = h.hexdigest()
UK4 = "00" + UK3
UK5 = hashlib.sha256(codecs.decode(UK4, 'hex'))
UK6 = hashlib.sha256(UK5.digest())
checksum = codecs.encode(UK6.digest(), 'hex')[0:8]
UK7 = UK4 + str(checksum)[2:10]  #I know it looks wierd

vars = [UK0,UK1,UK2,UK3,UK4,UK5,UK6,UK7]

for x in vars:
    print(x)

# Define base58
def base58(address_hex):
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    b58_string = ''
    # Get the number of leading zeros
    leading_zeros = len(address_hex) - len(address_hex.lstrip('0'))
    # Convert hex to decimal
    address_int = int(address_hex, 16)
    # Append digits to the start of string
    while address_int > 0:
        digit = address_int % 58
        digit_char = alphabet[digit]
        b58_string = digit_char + b58_string
        address_int //= 58
    # Add ‘1’ for each 2 leading zeros
    ones = leading_zeros // 2
    for one in range(ones):
        b58_string = '1' + b58_string
    return b58_string

Address = base58(UK7)
print(Address)