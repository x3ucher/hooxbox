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


#endif //CONFIG_H