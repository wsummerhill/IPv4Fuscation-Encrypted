import sys
import struct, socket
import pyperclip    # clipboard for all OS's
from ipaddress import ip_address # https://docs.python.org/3/library/ipaddress.html

# 16-char XOR key
KEY = 'Some s3cret!'

# Number of times to encrypt each IP address
iteration = 5

# XOR an input integer using a string key
def xor_encrypt_int(num, key):
    key_bytes = key.encode()
    key_len = len(key_bytes)
    encrypted_num = num
    # Perform X iterations of XOR encryption on each input num
    for x in range(iteration):
        for i in range(4):
            encrypted_num ^= key_bytes[i % key_len] << (8 * i)
    return encrypted_num


def xor_decrypt(encrypted_num, key):
    return xor_encrypt_int(encrypted_num, key)


# Convert an IP string to 'long' type
def ip2long(ip):
    packedIP = socket.inet_aton(ip)
    return struct.unpack("!L", packedIP)[0]


# Copy IPs to Clipboard OR print list of input IPs in array format
def get_ips(ip_input):
    ips_string = ("{}const char* IPv4s[] =".format(' '*4))
    ips_string += "    {\n"

    ipsPerLine = 5
    for i in range(0, len(ip_input), ipsPerLine):
        ips_batch = ip_input[i:i + ipsPerLine]
        ips_string += ' '*8
        ips_string += ', '.join(['"{}"'.format(ip) for ip in ips_batch]) + ',\n'

    ips_string = ips_string.rstrip(', \n') # Remove trailing comma and space
    ips_string += ("\n    };")

    # Uncomment line below if you wish to print encrypted IPs to console
    # print(ips_string)
    pyperclip.copy(ips_string)
    print("[+] Encrypted IP addresses have been copied to your Clipboard!")

# Variable to hold IP addresses from input file
IPs = []


if len(sys.argv) < 2:
    print("Usage: %s <shellcode_file>" % sys.argv[0])
    sys.exit(1) 

# Read input shellcode file to get it in IPv4 format
with open(sys.argv[1], "rb") as f:
    chunk = f.read(4)

    while chunk:
        if len(chunk) < 4: 
            padding = 4 - len(chunk)
            chunk = chunk + (b"\x90" * padding)
            IPs.append(str(ip_address(chunk)))
            break
        
        IPs.append(str(ip_address(chunk)))
        chunk = f.read(4)
    

# Variable to hold encrypted IP addresses
IPs_encrypted = []

# Encrypt IP addresses
for ip in IPs:
    # Convert IP to long equivalent
    ip_long = ip2long(ip)

    # XOR encrypt the ip_long
    ip_enc = xor_encrypt_int(ip_long, KEY)
    #ip_dec = xor_decrypt(ip_enc, KEY)

    # Append encrypted IP to array
    IPs_encrypted.append(ip_address(ip_enc))

    # DEBUGGING: Uncomment line below if you want to print IPs to console
    #print(f"IP = {ip}\t Long = {ip_long}\t Encrypted = {ip_address(ip_enc)}\t Encrypted-Int = {ip_enc}\t Decrypted = {ip_address(ip_dec)}")


# Get/Print encrypted IP addresses
print("Getting encrypted IPv4 addresses:")
get_ips(IPs_encrypted)


'''
# DEBUGGING: Used for testing to decrypt IPs and verify decryption worked properly
print("\n//Decrypting IP addresses to original format")

# Get decrypted IP addresses
for ip in IPs_encrypted:
    ip_long_enc = ip2long(format(ip))
    ip_dec = xor_decrypt(ip_long_enc, KEY)
    print(ip_address(ip_dec))
'''
