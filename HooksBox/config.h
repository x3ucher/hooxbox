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

// MAC-адрес VirtualBox
#define VBOX_MAC_PREFIX "08:00:27"

#endif