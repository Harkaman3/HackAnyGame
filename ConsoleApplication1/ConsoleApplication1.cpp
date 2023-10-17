#include <windows.h>
#include <TlHelp32.h>
#include <tchar.h>
#include <vector>
#include <iostream>

DWORD GetProcessID(const wchar_t* processName)
{
    DWORD processID = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSnap, &pe32))
        {
            do
            {
                if (_wcsicmp(pe32.szExeFile, processName) == 0)
                {
                    processID = pe32.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnap, &pe32));
        }
        CloseHandle(hSnap);
    }
    return processID;
}

DWORD GetModuleBaseAddress(const TCHAR* lpszModuleName, DWORD pID)

{
    DWORD dwModuleBaseAddress = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pID);
    MODULEENTRY32 ModuleEntry32 = { 0 };
    ModuleEntry32.dwSize = sizeof(MODULEENTRY32);
    if (Module32First(hSnapshot, &ModuleEntry32))
    {
        do
        {
            if (_tcscmp(ModuleEntry32.szModule, lpszModuleName) == 0)
            {
                dwModuleBaseAddress = (DWORD)ModuleEntry32.modBaseAddr;
                break;
            }
        } while (Module32Next(hSnapshot, &ModuleEntry32));
    }
    CloseHandle(hSnapshot);
    return dwModuleBaseAddress;
}

DWORD GetPointerAddress(DWORD baseAddress, std::vector<DWORD> offsets, HANDLE hProcess) {
    DWORD pointerAddress = baseAddress;
    for (int i = 0; i < offsets.size(); i++) {
        if (!ReadProcessMemory(hProcess, (LPCVOID)pointerAddress, &pointerAddress, sizeof(pointerAddress), 0)) {
            std::cerr << "Failed to read memory at offset " << i << std::endl;
            break;
        }
        pointerAddress += offsets[i];
    }
    return pointerAddress;
}





int main()
{
  
    const wchar_t* processName = L"ac_client.exe"; 


    DWORD processID = GetProcessID(processName);


    DWORD moduleBaseAddress = GetModuleBaseAddress(_T("ac_client.exe"), processID);

   
    DWORD staticAddress = moduleBaseAddress + 0x17E0A8;

   
    std::vector<DWORD> offsetsAmmo = { 0x364, 0x14, 0x0 }; 
    std::vector<DWORD> offsetsHealth = {0xEC};
 
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);

   
    DWORD pointerAddressAmmo = GetPointerAddress(staticAddress, offsetsAmmo, hProcess);
    DWORD pointerAddressHealth = GetPointerAddress(staticAddress, offsetsHealth, hProcess);
    while (true)
    {
        std::cout << "Process ID: " << processID << "\n";
        std::wcout << "Process Name: " << processName << "\n";
        std::cout << "Ammo Pointer Address: " << std::hex << pointerAddressAmmo << "\n";
        std::cout << "Health Pointer Address: " << std::hex << pointerAddressHealth << "\n";

        int ammoValue, healthValue;


        if (ReadProcessMemory(hProcess, (LPCVOID)pointerAddressAmmo, &ammoValue, sizeof(ammoValue), nullptr))
            std::cout << "Ammo Value: " << ammoValue << "\n";
        else
            std::cout << "Failed to read ammo value\n";
        
        int newAmmoValue = 100;
        int newHealthValue = 100; 

        if (WriteProcessMemory(hProcess, (LPVOID)pointerAddressAmmo, &newAmmoValue, sizeof(newAmmoValue), nullptr))
            std::cout << "Successfully wrote new ammo value\n";
        else
            std::cout << "Failed to write new ammo value\n";

        if (ReadProcessMemory(hProcess, (LPCVOID)pointerAddressHealth, &healthValue, sizeof(healthValue), nullptr))
            std::cout << "Health Value: " << healthValue << "\n";
        else
            std::cout << "Failed to read health value\n";

        if (WriteProcessMemory(hProcess, (LPVOID)pointerAddressHealth, &newHealthValue, sizeof(newHealthValue), nullptr))
            std::cout << "Successfully wrote new health value\n";
        else
            std::cout << "Failed to write new ammo value\n";

        Sleep(1000);
    }
   

 
    CloseHandle(hProcess);

    return 0;
}