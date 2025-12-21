#include <Windows.h>
#include <iostream>
#include "DriverCommunication.hpp"

// offsets - these offsets are for "NtCreateFile" in the current version (Fall Guys)
// 48 89 5C 24 ?? 48 89 74 24 ?? 55 57 41 54 41 56 41 57 48 8D 6C 24 ?? 48 81 EC ?? ?? ?? ?? 45 33 FF
uint64_t OFFSET_PTR_STORAGE = 0x1C84E8;
uint64_t XOR_KEY = 0xB0DC8D6ABFE9C383uLL;
int      ROR_SHIFT = 0x23;

// these only need to be updated if EAC updates
uint64_t CONST_GLOBAL_MOD = 0x20F798;
uint64_t CONST_MOD_HIGH = 0x226183A9357255B3LL;

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

unsigned __int64 MulMod(unsigned __int64 a, unsigned __int64 b, unsigned __int64 m) {
    unsigned __int64 res = 0;
    a %= m;
    while (b > 0) {
        if (b & 1) res = (res + a) % m;
        a = (a * 2) % m;
        b >>= 1;
    }
    return res;
}

unsigned __int64 ModPow17(unsigned __int64 base, unsigned __int64 mod) {
    unsigned __int64 result = 1;
    unsigned __int64 b = base;
    unsigned __int64 exponent = 0x3; // lets pray this doesnt change

    while (exponent > 0) {
        if (exponent & 1) result = MulMod(result, b, mod);
        exponent >>= 1;
        b = MulMod(b, b, mod);
    }
    return result;
}

unsigned __int64 Ror64(unsigned __int64 value, int shift) {
    return (value >> shift) | (value << (64 - shift));
}


int main() {
    if (!Memory::FindDriver()) {
        std::cout << "[!] Driver not found. Make sure it is loaded.\n";
        getchar();
        return 1;
    }

    // edit: i have no idea why i did that in usermode but i guess it doesn't matter :)
    auto NtQuerySystemInformation = (NtQuerySystemInformation_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
    if (!NtQuerySystemInformation) return 1;

    ULONG size = 0;
    NtQuerySystemInformation(11, nullptr, 0, &size);
    std::vector<uint8_t> buffer(size + 1024);

    if (NtQuerySystemInformation(11, buffer.data(), size, &size) < 0) {
        std::cout << "failed to query system modules you are cooked blud" << std::endl;
        return 1;
    }

    PSYSTEM_MODULE_INFORMATION info = (PSYSTEM_MODULE_INFORMATION)buffer.data();
    uint64_t EACDriverBase = 0;

    const char* TargetDriverName = "EasyAntiCheat_EOS.sys";
    for (ULONG i = 0; i < info->Count; i++) {
        PSYSTEM_MODULE_ENTRY m = &info->Modules[i];
        const char* name = (const char*)(m->FullPathName + m->OffsetToFileName);

        if (_stricmp(name, TargetDriverName) == 0) {
            EACDriverBase = (uint64_t)m->ImageBase;
            break;
        }
    }

    if (EACDriverBase == 0) {
        std::cout << "[-] EAC Driver not loaded" << std::endl;;
        getchar();
        return 1;
    }

    uint64_t encLow = read<uint64_t>(EACDriverBase + OFFSET_PTR_STORAGE);
    uint64_t encHigh = read<uint64_t>(EACDriverBase + OFFSET_PTR_STORAGE + 0x8);
    uint64_t ModLow = read<uint64_t>(EACDriverBase + CONST_GLOBAL_MOD);

    if (encLow == 0 && ModLow == 0) {
        std::cout << "unable to read... check your offsets & driver!" << std::endl;
        getchar();
        return 1;
    }

    uint64_t decLow = ModPow17(encLow, ModLow);
    uint64_t decHigh = ModPow17(encHigh, CONST_MOD_HIGH);

    uint64_t seed = ((decHigh & 0xFFFFFFFF) << 32) | (decLow & 0xFFFFFFFF);
    // seed = ~seed; 
    // ^^ this is only needed when the call (decryption) has the "~" like here:
    // v10 = EAC::BlaBlaBla(&v13, (void *)(__ROR8__(~v9, 0x19) ^ 0x8F6E1DFD5F7DF99DuLL));
    
    uint64_t rotated = Ror64(seed, ROR_SHIFT);
    uint64_t decrypted_function = rotated ^ XOR_KEY;

    std::cout << "Result -> " << std::hex << decrypted_function << std::endl;

    getchar();
    return 0;
}
