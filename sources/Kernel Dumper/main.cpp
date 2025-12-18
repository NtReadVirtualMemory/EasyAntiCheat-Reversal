/*
This is my kernel dumper that I wrote for EAC. 
IMPORTANT: it is not perfect and may contain bugs.
I plan to optimize and improve it over time. however i might make a separate repository in the future to dump drivers in general :p
*/
#include <windows.h>
#include <iostream>
#include <fstream>
#include "DriverCommunication.hpp"

typedef struct _SYSTEM_MODULE_ENTRY {
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} SYSTEM_MODULE_ENTRY, * PSYSTEM_MODULE_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION {
    ULONG Count;
    SYSTEM_MODULE_ENTRY Modules[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

typedef NTSTATUS(NTAPI* NtQuerySystemInformation_t)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

DWORD AlignValue(DWORD value, DWORD alignment) {
    if (alignment == 0) return value;
    return (value + alignment - 1) & ~(alignment - 1);
}

void RepairPE(std::vector<uint8_t>& buffer) {
    if (buffer.size() < sizeof(IMAGE_DOS_HEADER)) {
        std::cout << "ERROR: buffer too small for IMAGE_DOS_HEADER" << std::endl;
        return;
    }

    auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(buffer.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        std::cout << "ERROR: Invalid DOS Signature (e_magic)" << std::endl;
        return;
    }

    if (dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > buffer.size()) {
        std::cout << "ERROR: NT Header outside of buffer" << std::endl;
        return;
    }

    auto nt = reinterpret_cast<PIMAGE_NT_HEADERS64>(buffer.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        std::cout << "ERROR: Invalid NT Signature (PE Header)" << std::endl;
        return;
    }

    std::cout << "-> Lets repair the PE" << std::endl;
    nt->OptionalHeader.FileAlignment = nt->OptionalHeader.SectionAlignment;
    auto section = IMAGE_FIRST_SECTION(nt);
    DWORD oldEntryPoint = nt->OptionalHeader.AddressOfEntryPoint;

    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        section[i].PointerToRawData = section[i].VirtualAddress;
        section[i].SizeOfRawData = AlignValue(section[i].Misc.VirtualSize, nt->OptionalHeader.SectionAlignment);

        if (oldEntryPoint >= section[i].VirtualAddress &&
            oldEntryPoint < section[i].VirtualAddress + section[i].Misc.VirtualSize) {

            if (section[i].Characteristics & IMAGE_SCN_MEM_DISCARDABLE) {
                section[i].Characteristics &= ~IMAGE_SCN_MEM_DISCARDABLE;
            }
        }
    }
    std::cout << "-> fixing PE done.\n";
}

bool WriteFile(std::vector<uint8_t> bytes, std::wstring filename) {

    wchar_t buffer[MAX_PATH] = { 0 };
    DWORD length = GetModuleFileNameW(nullptr, buffer, MAX_PATH);

    std::wstring OutputPath = std::wstring(buffer);

    size_t pos = OutputPath.find_last_of(L"\\/");
    OutputPath = OutputPath.substr(0, pos);
    OutputPath.append(L"\\" + filename);
    std::ofstream file(OutputPath, std::ios::binary);
    if (!file.is_open()) {
        std::cout << "Failed to Create File in Current Directory. weird..." << std::endl;
        return false;
    }
    file.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    file.close();
    return true;
}

int main() {
    if (!Memory::FindDriver()) {
        std::cout << "Driver not found.\n";
        system("pause");
        return 1;
    }
    Memory::TargetProcessId = 4;

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) {
        std::cout << "failed to get ntdll" << std::endl;
        system("pause");
        return 1;
    }
    auto NtQuerySystemInformation = (NtQuerySystemInformation_t)GetProcAddress(ntdll, "NtQuerySystemInformation");
    if (!NtQuerySystemInformation) {
        std::cout << "failed to get NtQuerySystemInformation" << std::endl;
        system("pause");
        return 1;
    }

    ULONG size = 0;
    NtQuerySystemInformation(11, nullptr, 0, &size);
    std::vector<uint8_t> buffer(size);
    if (NtQuerySystemInformation(11, buffer.data(), size, &size) < 0) {
        std::cout << "failed to query system modules you are cooked blud" << std::endl;
        return 1;
    }
    PSYSTEM_MODULE_INFORMATION info = (PSYSTEM_MODULE_INFORMATION)buffer.data();

    for (ULONG i = 0; i < info->Count; i++) {
        PSYSTEM_MODULE_ENTRY m = &info->Modules[i];
        const char* name = (const char*)(m->FullPathName + m->OffsetToFileName);

        if (_stricmp(name, "EasyAntiCheat_EOS.sys") == 0) {
            std::cout << "driver: " << name << "\n";
            std::cout << "Base: " << std::hex << m->ImageBase << " Size: " << m->ImageSize << "\n";

            std::vector<uint8_t> DumpBuffer(m->ImageSize, 0);
            size_t PAGE_SIZE = 0x1000;
            uint64_t base = (uint64_t)m->ImageBase;
            uint8_t* dest = DumpBuffer.data();

            for (size_t offset = 0; offset < m->ImageSize; offset += PAGE_SIZE) {
                size_t chunksize = min(PAGE_SIZE, m->ImageSize - offset);
                read_batch(base + offset, dest + offset, chunksize);
            }

            RepairPE(DumpBuffer);
            WriteFile(DumpBuffer, L"dump.sys");
            break;
        }
    }
    system("pause");
    return 0;
}
