# IPv4Fuscation-Encrypted

C++ IPv4Fuscation technique to execute XOR encrypted shellcode stored in IP address format to help reduce entopy and detections on the typical hex/base64/other encoding techniques that are frequently used.

### Usage:

XOR encrypt your shellcode into IP address format using `IPv4encrypt-shellcode.py` and whichever XOR key you want to specify in the Python script. <br />
The Python script will output XOR encrypted shellcode in encrypted IP address format and **copied to your Clipboard** (saved in C++ format). 
```
python3 IPv4encrypt-shellcode.py calc-x64.bin
```

Take the encrypted IPv4 shellcode and paste it into the C++ project file `CPP-IPv4Fuscation-Decryption.cpp`, then compile and execute!


### Technical Details:

#### CPP-IPv4Fuscation-Decryption.cpp
1. Read encrypted IPs into a char array
  - Convert each IP to its integer equivalent
  - Decrypt each integer using the XOR encryption key
  - Convert each decrypted int it to its IP address equivalent
2. Initiate new heap space using **HeapCreate()** and **HeapAlloc()** functions from **Kernel32**
3. Loop through decrypted IP addresses and convert each to its binary format using **RtlIpv4StringToAddressA()** function from **Ntdll**
  - This function will also output binary data to the target heap address pointer "ptr"
4. Execute shellcode on heap using the callback function **EnumSystemLocalsEx()** from **Kernel32** (feel free to use any execution technique here)
5. Cleanup: Free up memory addresses, heap space, and encrypted IP address variabels

<br />

--------------
### References:

- https://learn.microsoft.com/en-us/windows/win32/api/ip2string/nf-ip2string-rtlipv4stringtoaddressa
- https://gitlab.com/ORCA000/hellshell/-/blob/main/IPv4Fuscation/Ipv4Fuscation.cpp
- https://github.com/TheD1rkMtr/Shellcode-Hide/blob/main/2%20-%20Encoding/4%20-%20IPv4%20shellcode/IPfuscation/IPfuscation.cpp
- https://github.com/pwn1sher/uuid-loader/blob/main/uuidfromstring.cpp
