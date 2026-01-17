#ifndef CONFIG_H
#define CONFIG_H

// Конфигурационные константы для фильтрации VirtualBox
static const wchar_t* VBOX_REGISTRY_PATHS[] = {
    L"VBoxGuest",
    L"VBoxMouse",
    L"VBoxService",
    L"VBoxSF",
    L"VBoxVideo",
    L"Oracle\\VirtualBox Guest Additions",
    L"VBOX__"
};

static const int VBOX_REGISTRY_PATHS_COUNT = 7;

static const wchar_t* VBOX_DISK_ENUM_CHECKS[] = {
    L"qemu",
    L"virtio",
    L"vmware",
    L"vbox",
    L"xen",
    L"vmw",
    L"virtual"
};

static const int VBOX_DISK_ENUM_CHECKS_COUNT = 7;

// VirtualBox driver files in \\WINDOWS\\system32\\drivers
static const wchar_t* VBOX_DRIVERS_PATHS[] = {
    L"C:\\WINDOWS\\system32\\drivers\\VBoxMouse.sys",
    L"C:\\WINDOWS\\system32\\drivers\\VBoxGuest.sys",
    L"C:\\WINDOWS\\system32\\drivers\\VBoxSF.sys",
    L"C:\\WINDOWS\\system32\\drivers\\VBoxVideo.sys"
};

static const int VBOX_DRIVERS_PATHS_COUNT = 4;

// VirtualBox other system files
static const wchar_t* VBOX_SYSTEM_FILES_PATHS[] = {
    L"C:\\WINDOWS\\system32\\vboxdisp.dll",
    L"C:\\WINDOWS\\system32\\vboxhook.dll",
    L"C:\\WINDOWS\\system32\\vboxmrxnp.dll",
    L"C:\\WINDOWS\\system32\\vboxogl.dll",
    L"C:\\WINDOWS\\system32\\vboxoglarrayspu.dll",
    L"C:\\WINDOWS\\system32\\vboxoglcrutil.dll",
    L"C:\\WINDOWS\\system32\\vboxoglerrorspu.dll",
    L"C:\\WINDOWS\\system32\\vboxoglfeedbackspu.dll",
    L"C:\\WINDOWS\\system32\\vboxoglpackspu.dll",
    L"C:\\WINDOWS\\system32\\vboxoglpassthroughspu.dll",
    L"C:\\WINDOWS\\system32\\vboxservice.exe",
    L"C:\\WINDOWS\\system32\\vboxtray.exe",
    L"C:\\WINDOWS\\system32\\VBoxControl.exe",
    L"C:\\program files\\oracle\\virtualbox guest additions\\"
};

static const int VBOX_SYSTEM_FILES_PATHS_COUNT = 14;

static const wchar_t* VBOX_DEVICE_PATHS[] = {
    L"VBoxMiniRdrDN",
    L"VBoxGuest",
    L"VBoxMiniRdDN", 
    L"VBoxTrayIPC",
    L"VBoxMouse",     
    L"VBoxVideo",
    L"VBoxSF",
    L"VBoxDisp"
};

static const int VBOX_DEVICE_PATHS_COUNT = 8;

const std::wstring VIRTUALBOX_PROVIDER_NAME = L"VirtualBox Shared Folders";

#pragma pack(push, 1)
struct FakeAcpiTable {
    char signature[5] = { 'R', 'S', 'D', ' ', 0 };  // 5 вместо 4
    DWORD length = 36;
    BYTE revision = 0;
    BYTE checksum = 0;
    char oemid[7] = { 'A', 'W', 'A', 'R', 'E', ' ', 0 };  // 7 вместо 6
    char oemtableid[9] = { 'G', 'E', 'N', 'U', 'I', 'N', 'E', ' ', 0 };  // 9 вместо 8
    DWORD oemrevision = 1;
    DWORD creatorid = 0;
    DWORD creatorrevision = 0;
    BYTE data[4] = { 0, 0, 0, 0 };
};

struct FakeSmbiosTable {
    BYTE anchorString[4] = { '_', 'S', 'M', '_' };
    BYTE entryPointLength = 0x1F;
    BYTE majorVersion = 2;
    BYTE minorVersion = 7;
    WORD maxStructureSize = 0;
    BYTE entryPointRevision = 0;
    BYTE formattedArea[5] = { 0 };
    BYTE intermediateAnchorString[5] = { '_', 'D', 'M', 'I', '_' };
    BYTE intermediateChecksum = 0;
    WORD tableLength = 0;
    DWORD tableAddress = 0;
    WORD numberOfStructures = 0;
    BYTE smbiosBCDRevision = 0;
    BYTE padding[15] = { 0 };
};
#pragma pack(pop)

#endif //CONFIG_H