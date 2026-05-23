# Проект HooXBox — полная техническая документация

## Оглавление

1. [Введение](#1-введение)
2. [Угроза: методы обнаружения виртуальной среды](#2-угроза-методы-обнаружения-виртуальной-среды)
3. [Общая архитектура](#3-общая-архитектура)
4. [Компонент 1: hooksbox.dll](#4-компонент-1-hooksboxdll)
5. [Компонент 2: DebuggerWrapper.exe](#5-компонент-2-debuggerwrapperexe)
6. [Компонент 3: launcher.exe](#6-компонент-3-launcherexe)
7. [Сборка и зависимости](#7-сборка-и-зависимости)
8. [Запуск и тестирование](#8-запуск-и-тестирование)
9. [Ограничения и нерешённые проверки](#9-ограничения-и-нерешённые-проверки)
10. [История эволюции проекта](#10-история-эволюции-проекта)
11. [Полная структура исходников](#11-полная-структура-исходников)
12. [Глоссарий](#12-глоссарий)

---

## 1. Введение

**HooXBox** — это инструмент для маскировки артефактов виртуальной среды и анализа в Windows-процессах. Его задача — заставить программы, проверяющие наличие виртуальной машины (VirtualBox / VMware / Hyper-V / QEMU), отладчика или sandbox-окружения, отвечать «реальная физическая машина без анализа».

Целевые сценарии:
- Анализ образцов malware, которые отказываются исполняться внутри VM.
- Исследование anti-VM-техник.
- Тестирование детекторов (al-khaser, pafish) — насколько эффективно они различают живую систему от замаскированной.

Проект состоит из трёх взаимодополняющих компонентов:

| Компонент | Тип | Роль |
|---|---|---|
| `hooksbox.dll` | Win32 DLL (x64) | Перехватывает WinAPI / COM / Nt-функции в целевом процессе. Подменяет результаты, скрывает следы VM и отладчика. |
| `DebuggerWrapper.exe` | Win32 PE (x64) | Запускает целевой процесс под Windows Debug API. Перехватывает CPU-инструкции CPUID и RDTSC через программные точки останова (INT 3), эмулирует их с замаскированным результатом. |
| `launcher.exe` | Win32 PE (x64) | Front-end. Интерактивно (или через CLI-флаги) спрашивает у пользователя, какие слои маскировки включить, и запускает цель. |

### 1.1. Почему именно три компонента

Маскировка идёт на разных уровнях абстракции, для каждого нужны разные инструменты:

- **API-уровень** (`hooksbox.dll`) — большинство anti-VM-проверок ходят через стандартные WinAPI (`RegOpenKeyEx`, `GetFileAttributes`, `Process32Next`, WMI COM-интерфейсы и т.д.). Их можно перехватить пользовательским DLL через MinHook trampolines.
- **CPU-инструкции** (`DebuggerWrapper.exe`) — `CPUID` возвращает hypervisor-vendor (`VBoxVBoxVBox`, `Microsoft Hv`, …) и HV-бит, `RDTSC` измеряет такты, и эти проверки идут *в обход* user-mode API. Перехватить их можно только через kernel-debug (тут — через user-mode Debug API + INT 3).
- **Уровень оркестрации** (`launcher.exe`) — пользователю нужно одной командой выбрать комбинацию слоёв. Без launcher пришлось бы вручную запускать `DebuggerWrapper.exe` и заботиться об инжекции DLL.

---

## 2. Угроза: методы обнаружения виртуальной среды

Прежде чем разбирать код, нужно понять, *что* именно мы маскируем. Современные anti-VM проверки используют десятки независимых сигналов. Если замаскировать один, ещё три выстрелят. Все они делятся на пять больших категорий:

### 2.1. Артефакты гостевых дополнений

Установленные «Guest Additions» VirtualBox оставляют следы:
- Ключи реестра: `HKLM\SOFTWARE\Oracle\VirtualBox Guest Additions`, `HKLM\SYSTEM\CurrentControlSet\Services\VBox*`, `HKLM\HARDWARE\ACPI\DSDT\VBOX__`.
- Файлы: `C:\WINDOWS\system32\drivers\VBox*.sys`, `C:\WINDOWS\system32\vbox*.dll/exe`.
- Окна: `VBoxTrayToolWnd`, `VBoxTrayToolWndClass`.
- Процессы: `VBoxService.exe`, `VBoxTray.exe`.
- Сетевые провайдеры: `VirtualBox Shared Folders`.
- Устройства: `\\.\VBoxMiniRdrDN`, `\\.\VBoxTrayIPC`.
- MAC-адреса с OUI `08:00:27`.

Pafish и al-khaser проверяют это всё.

### 2.2. Атрибуты SMBIOS, ACPI, WMI

Прошивка виртуальной машины пишет узнаваемые строки в SMBIOS (`VirtualBox`, `innotek GmbH`, `Oracle Corporation`) и ACPI-таблицы. Через `GetSystemFirmwareTable` или WMI-классы (`Win32_BIOS.SerialNumber`, `Win32_ComputerSystem.Model`, `Win32_VideoController.Caption` и т.д.) это можно прочитать.

Кроме того, VM-провайдеры WMI часто возвращают **пустые** результаты для классов, которые на физической машине должны иметь данные: `Win32_Fan`, `Win32_PhysicalMemory`, `MSAcpi_ThermalZoneTemperature`. Само отсутствие данных — сигнал «это VM».

### 2.3. CPU-инструкции

- `CPUID` с EAX=1: бит 31 регистра ECX — флаг «hypervisor present».
- `CPUID` с EAX=0x40000000..0x400000FF: hypervisor-vendor string в EBX/ECX/EDX (`VBoxVBoxVBox`, `Microsoft Hv`, `VMwareVMware`, …).
- `RDTSC`: на bare-metal такт одиночный; в VM `RDTSC` после `CPUID` (вызывающего VM-exit) показывает аномально большую дельту.
- `SLDT/SGDT/SIDT/STR` — читают регистры дескрипторных таблиц, в VM значения отличаются.
- `IN/OUT` на VMware-специфичный порт `0x5658` — возвращает магическое значение в VMware-госте.

### 2.4. Детектирование отладчика

- `IsDebuggerPresent()` — kernel32-функция, читает `PEB->BeingDebugged`.
- Прямое чтение `PEB->BeingDebugged` (offset 0x02) через `gs:[0x60]+0x02`.
- `PEB->NtGlobalFlag` (offset 0xBC на x64) — установленные debug-флаги при запуске под отладчиком.
- `ProcessHeap->Flags / ForceFlags` (offsets 0x70/0x74 в _HEAP) — debug-heap флаги.
- `CheckRemoteDebuggerPresent` API.
- `NtQueryInformationProcess` с `ProcessDebugPort` / `ProcessDebugFlags` / `ProcessDebugObjectHandle`.
- `NtQueryObject(ObjectAllTypesInformation)` — проверяет, есть ли `DebugObject` в системе.
- `CloseHandle(invalid_handle)` под отладчиком кидает `STATUS_INVALID_HANDLE` exception.
- `UnhandledExceptionFilter` — kernel32-функция, которая бывает не вызывается из-за раннего exit по debug-port.

### 2.5. Признаки sandbox-окружения

- Малое uptime системы (только что включена → sandbox).
- Малый диск (< 60 GB).
- Мало памяти (< 1 GB).
- Малое кол-во ядер CPU (< 2).
- Отсутствие пользовательской активности (`GetLastInputInfo`).
- Имя пользователя/хоста в чёрном списке (`SANDBOX`, `MALWARE`, `VIRUS`).

---

## 3. Общая архитектура

```
┌────────────────────┐  user runs   ┌─────────────────┐
│  launcher.exe      │ ──────────► │  pafish.exe /   │
│  - interactive UI  │              │  al-khaser.exe  │
│  - mode selection  │              │  (target)       │
└────────┬───────────┘              └────▲────────────┘
         │                               │
         │ spawns                        │ events
         ▼                               │
┌────────────────────────────────────┐   │
│  DebuggerWrapper.exe (optional)    │   │
│  - DEBUG_ONLY_THIS_PROCESS         │◄──┘
│  - INT 3 BP on CPUID/RDTSC         │
│  - CreateRemoteThread → LoadLib    │
└────────┬───────────────────────────┘
         │ inject (LoadLibraryW)
         ▼
┌────────────────────────────────────┐
│  hooksbox.dll (inside target)      │
│  - MinHook trampolines on WinAPI   │
│  - PEB/heap in-place patches       │
│  - PEB.Ldr unlink (hide self)      │
│  - WMI vtable hooks                │
└────────────────────────────────────┘
```

Три комбинируемых сценария:

1. **Только hooksbox** (`launcher.exe --inject`): `CreateProcess(CREATE_SUSPENDED)` → ремоут-инжекция DLL → `ResumeThread`. Нет отладчика, нет CPUID-маскировки.
2. **Только DebuggerWrapper** (`launcher.exe --debug`): целевой процесс под отладчиком, только маскировка `RDTSC` (CPUID опционально через `--cpuid`).
3. **Оба слоя** (`launcher.exe --debug-inject`): отладчик и DLL вместе. Маскировка работает максимально полно.

Pafish обычно достаточно режима `--inject` (он не делает RDTSC-тайминги). Al-khaser требует `--debug-inject` для прохождения большинства проверок.

---

## 4. Компонент 1: hooksbox.dll

### 4.1. Назначение и общая структура

`hooksbox.dll` — это Win32 DLL, который инжектируется в целевой процесс через `LoadLibraryW`. Внутри он использует библиотеку **MinHook** (статическая `libMinHook.x64.lib`) для установки трамплинов на функции Windows API.

Архитектурно DLL разделён на **модули хуков** — по одному на каждое подсемейство WinAPI:

| Модуль | Файл | Цели хука |
|---|---|---|
| Реестр | `hooks/registry_hooks.{h,cpp}` | `RegOpenKeyExW/A`, `RegQueryValueExW/A`, `RegEnumKeyExW/A` |
| Файлы | `hooks/file_hooks.{h,cpp}` | `GetFileAttributesW/A` |
| Устройства | `hooks/device_hooks.{h,cpp}` | `CreateFileW/A` |
| Окна | `hooks/window_hooks.{h,cpp}` | `FindWindowW/A`, `FindWindowExW/A` |
| Процессы | `hooks/processes_hooks.{h,cpp}` | `Process32FirstW/A`, `Process32NextW/A` |
| Сеть | `hooks/network_hooks.{h,cpp}` | `WNetGetProviderNameW/A`, `GetAdaptersInfo`, `GetAdaptersAddresses` |
| Прошивка | `hooks/firmwaretable_hooks.{h,cpp}` | `GetSystemFirmwareTable`, `EnumSystemFirmwareTables` |
| Hyper-V dir | `hooks/hypervobj_hooks.{h,cpp}` | `NtOpenDirectoryObject`, `NtQueryDirectoryObject` |
| Системные | `hooks/system_hooks.{h,cpp}` | `SetupDiEnumDeviceInfo`, `GetDiskFreeSpaceExW` |
| Питание | `hooks/power_hooks.{h,cpp}` | `GetPwrCapabilities` |
| Службы | `hooks/services_hooks.{h,cpp}` | `EnumServicesStatusExW` |
| WMI | `hooks/wmi_hooks.{h,cpp}` | `IWbemServices::ExecQuery`, `IEnumWbemClassObject::Next`, `IWbemClassObject::Get` |
| Отладчик | `hooks/debugger_hooks.{h,cpp}` | `IsDebuggerPresent`, `CheckRemoteDebuggerPresent` + PEB patch |
| Время | `hooks/time_hooks.{h,cpp}` | `GetTickCount`, `GetTickCount64` |
| Ввод | `hooks/input_hooks.{h,cpp}` | `GetLastInputInfo` |
| Process info | `hooks/process_info_hooks.{h,cpp}` | `NtQueryInformationProcess`, `NtClose`, `CloseHandle` |
| Object info | `hooks/object_info_hooks.{h,cpp}` | `NtQueryObject` |
| Module hide | `hooks/module_hide_hooks.{h,cpp}` | `NtQueryVirtualMemory`, `GetMappedFileNameW/A` + PEB.Ldr unlink |

Каждый модуль:
- Объявляет `extern` указатели на оригинальные функции (`original_XxxW`, `original_XxxA`).
- Реализует `hook_XxxW`, `hook_XxxA` — детуры с той же сигнатурой.
- Активируется через `Initialize{Module}Hooks()` в `hook_manager.cpp`, которая делает `MH_CreateHook` + `MH_EnableHook`.

### 4.2. Точка входа: `hook_dll_main.cpp`

```cpp
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);

        if (!InitializeHooks()) {
            WriteFileLog(L"ERROR", L"DllMain: InitializeHooks() failed");
            return FALSE;
        }
        if (!InstallWmiHooks()) {
            WriteFileLog(L"WARN", L"DllMain: InstallWmiHooks() failed (continuing)");
        }
        if (!InitializeModuleHideHooks(hModule)) {
            WriteFileLog(L"WARN", L"DllMain: InitializeModuleHideHooks() failed (continuing)");
        }
        WriteFileLog(L"INFO", L"DllMain: hooksbox.dll attached");
        break;

    case DLL_PROCESS_DETACH:
        CleanupHooks();
        WriteFileLog(L"INFO", L"DllMain: hooksbox.dll detached");
        break;
    }
    return TRUE;
}
```

Порядок действий критичен:
1. **`DisableThreadLibraryCalls`** — отключаем `DLL_THREAD_ATTACH` / `_DETACH`, ускоряет создание потоков и снижает риск re-entrance.
2. **`InitializeHooks()`** — синхронно устанавливает все API-хуки (включая `IsDebuggerPresent` и патч PEB).
3. **`InstallWmiHooks()`** — НЕ устанавливает сами WMI-хуки сразу (это вызовет deadlock на loader-lock). Вместо этого ставит ОДИН маленький патч на `CoCreateInstance` — trampoline, который сработает, когда target позже сам позовёт `CoCreateInstance(CLSID_WbemLocator)`. Подробнее в разделе 4.13.
4. **`InitializeModuleHideHooks(hModule)`** — отвязывает hooksbox.dll от `PEB->Ldr` и ставит хук на `NtQueryVirtualMemory`. Делается ПОСЛЕ всех других хуков, потому что после отвязки никто не сможет найти DLL по имени.

### 4.3. `hook_manager.{cpp,h}` — оркестратор

`hook_manager.cpp` — большой файл, содержащий:
- `InitializeHooks()` — главный вход, по очереди вызывает все `Initialize*Hooks()`.
- Отдельные `InitializeRegistryHooks()`, `InitializeFileHooks()`, и т.д. — каждая делает несколько `MH_CreateHook` + `MH_EnableHook`.
- `InstallWmiHooks()` — устанавливает trampoline на `CoCreateInstance` (bootstrap).
- `DoWmiInstall(IWbemLocator*)` — реальная установка WMI-хуков, вызывается из trampoline.
- `Install{Class}Hook(IWbemClassObject*)` / `Remove{Class}Hook()` — установка/снятие per-class spoof через единый shared dispatcher.
- `CleanupHooks()` — разворачивает все хуки при выгрузке DLL.

#### 4.3.1. Порядок установки

```cpp
bool InitializeHooks() {
    if (MH_Initialize() != MH_OK) return false;

    if (!InitializeRegistryHooks())     return false;  // Reg*
    if (!InitializeFileHooks())         return false;  // GetFileAttributes
    if (!InitializeDeviceHooks())       return false;  // CreateFile
    if (!InitializeProcessHooks())      return false;  // Process32*
    if (!InitializeWndHooks())          return false;  // FindWindow*
    if (!InitializeNetworkHooks())      return false;  // WNetGetProviderName
    if (!InitializeMacAddresHooks())    return false;  // GetAdapters*
    if (!InitializeFirmwareTableHooks())return false;  // SMBIOS/ACPI
    if (!InitializeHyperVObjHooks())    return false;  // NtQueryDirectoryObject
    if (!InitializeSystemHooks())       return false;  // SetupDi, disk
    if (!InitializePowerHooks())        return false;  // GetPwrCapabilities
    if (!InitializeServicesHooks())     return false;  // EnumServicesStatusEx
    if (!InitializeDebuggerHooks())     return false;  // IsDebuggerPresent + PEB
    if (!InitializeTimeHooks())         return false;  // GetTickCount
    if (!InitializeProcessInfoHooks())  return false;  // NtQueryInformationProcess
    if (!InitializeInputHooks())        return false;  // GetLastInputInfo
    if (!InitializeObjectInfoHooks())   return false;  // NtQueryObject
    return true;
}
```

`InitializeModuleHideHooks(hModule)` зовётся отдельно из DllMain — нужно `HMODULE` самого hooksbox.dll.

### 4.4. Модуль реестра (`registry_hooks`)

Перехватывает три функции в W и A вариантах:
- `RegOpenKeyExW/A`
- `RegQueryValueExW/A`
- `RegEnumKeyExW/A`

#### 4.4.1. `RegOpenKeyExW/A`

```cpp
LSTATUS WINAPI hook_RegOpenKeyExW(HKEY hKey, LPCWSTR lpSubKey, ...) {
    if (IsVBoxRegistryKey(hKey, lpSubKey)) {
        return ERROR_FILE_NOT_FOUND;
    }
    return original_RegOpenKeyExW(hKey, lpSubKey, ...);
}
```

Проверяет, содержит ли `lpSubKey` подстроки `VBoxGuest`, `VBoxMouse`, `Oracle\VirtualBox Guest Additions`, `VBOX__` и др. (см. `config.h`, массив `VBOX_REGISTRY_PATHS`). Если да — возвращает `ERROR_FILE_NOT_FOUND` (ключ «не существует»).

ANSI-вариант делает то же через `IsVBoxRegistryKeyA` (массив `kVBoxRegistryPathsA` в `vbox_filters.cpp`).

#### 4.4.2. `RegQueryValueExW/A`

Сложнее: сначала читаем значение в **локальный временный буфер**, проверяем, что внутри (VBOX в `SystemBiosVersion`, `VIRTUALBOX` в `VideoBiosVersion`, `06/23/99` в `SystemBiosDate`, и т.д.). Если детектируется — формируем маскированный ответ и пишем в буфер вызывающего:

| Имя значения | Лук-ап | Маскированное значение |
|---|---|---|
| `SystemBiosVersion` | `VBOX` | `ALASKA - 1072009` |
| `Identifier` (на disk enum) | `VBOX` | `ATA HARDDISK` |
| `VideoBiosVersion` | `VIRTUALBOX` | `ERROR_FILE_NOT_FOUND` |
| `SystemBiosDate` | `06/23/99` | `ERROR_FILE_NOT_FOUND` |
| Числовое имя (`0`, `1`, …) в Disk\Enum, значение содержит `qemu`/`virtio`/`vmware`/`vbox`/`xen`/`vmw`/`virtual` | — | `ATA Device` |

Маскированное значение записывается в `lpData` (буфер caller'а), `*lpcbData` обновляется. Если буфер caller'а меньше нужного — возвращается `ERROR_MORE_DATA` с правильным размером.

Если маскировать нечего — вызывается оригинальная функция повторно с буфером caller'а (два чтения — функция stateless, для `RegQueryValueEx` это безопасно).

#### 4.4.3. `RegEnumKeyExW/A`

При перечислении подключей фильтрует те, чьи имена содержат `qemu`/`virtio`/`vmware`/`vbox`/`xen`/`vmw`/`virtual`. Возвращает `ERROR_NO_MORE_ITEMS` (как будто перечисление кончилось) — это скрывает виртуальный диск из enum'а контроллера.

#### 4.4.4. Почему W *и* A варианты

Pafish собран без определения макроса `UNICODE`, поэтому его `RegOpenKeyEx`, `GetFileAttributes`, `FindWindow`, `Process32First`, `WNetGetProviderName` — это ANSI-функции напрямую. Windows их **не** проксирует через W-варианты. Поэтому без ANSI-хуков pafish бы видел реальную систему.

Это было главным прорывом отладки во время разработки: изначально все хуки были только W, и pafish их не замечал.

### 4.5. Модуль файлов (`file_hooks`)

Перехватывает только `GetFileAttributesW/A`. Этой функцией pafish и al-khaser проверяют существование драйверов VBox (`C:\WINDOWS\system32\drivers\VBoxGuest.sys` и т.д.) и других VBox-файлов.

```cpp
DWORD WINAPI hook_GetFileAttributesW(LPCWSTR lpFileName) {
    if (IsVBoxFilePath(lpFileName)) {
        SetLastError(ERROR_FILE_NOT_FOUND);
        return INVALID_FILE_ATTRIBUTES;
    }
    return original_GetFileAttributesW(lpFileName);
}
```

`IsVBoxFilePath` сравнивает (case-insensitive substring) с массивами `VBOX_DRIVERS_PATHS` и `VBOX_SYSTEM_FILES_PATHS` из `config.h`. Это 5 драйверов и 14 системных файлов.

### 4.6. Модуль устройств (`device_hooks`)

`CreateFileW/A` — pafish открывает device-пути типа `\\.\VBoxMiniRdrDN`, `\\.\VBoxTrayIPC` через `CreateFile` с конкретной комбинацией флагов (`GENERIC_READ | FILE_SHARE_READ | OPEN_EXISTING | FILE_ATTRIBUTE_NORMAL`).

```cpp
HANDLE WINAPI hook_CreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
                                ..., DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, ...) {
    if (IsVBoxDetectionAttempt(lpFileName, dwDesiredAccess, dwShareMode,
                                dwCreationDisposition, dwFlagsAndAttributes)) {
        SetLastError(ERROR_FILE_NOT_FOUND);
        return INVALID_HANDLE_VALUE;
    }
    return original_CreateFileW(...);
}
```

`IsVBoxDetectionAttempt` срабатывает только при ТОЧНОМ совпадении flagов — чтобы не сломать легитимный доступ к этим устройствам.

ANSI-вариант (`hook_CreateFileA`) конвертирует имя в широкое и идёт по той же логике.

### 4.7. Модуль окон (`window_hooks`)

`FindWindowW/A` и `FindWindowExW/A` — pafish использует `FindWindow(NULL, "VBoxTrayToolWnd")` и `FindWindow("VBoxTrayToolWndClass", NULL)` для определения присутствия трея VirtualBox Guest Additions.

```cpp
HWND WINAPI hook_FindWindowW(LPCWSTR lpClassName, LPCWSTR lpWindowName) {
    // Проверка обоих строк против VBoxTrayToolWndClass / VBoxTrayToolWnd / VirtualBox
    if (checkAndBlock(...)) return NULL;
    return original_FindWindowW(lpClassName, lpWindowName);
}
```

Возврат `NULL` означает «такого окна нет».

### 4.8. Модуль процессов (`processes_hooks`)

Перехватывает `Process32FirstW/A`, `Process32NextW/A`. Когда target итерирует процессы (через `CreateToolhelp32Snapshot` + `Process32First/Next`), мы пропускаем те, чьё имя совпадает с `VBoxService.exe`, `VBoxTray.exe`.

```cpp
BOOL WINAPI hook_Process32NextW(HANDLE hSnapshot, LPPROCESSENTRY32W lppe) {
    do {
        BOOL result = original_Process32NextW(hSnapshot, lppe);
        if (!result) return FALSE;
        if (!IsHiddenProcessW(lppe->szExeFile)) return TRUE;
    } while (true);
}
```

Цикл нужен, потому что мы делаем «прозрачное» скрытие — caller'у выглядит так, будто VBoxService просто отсутствует в системе.

Для ANSI: SDK с UNICODE не предоставляет отдельный `PROCESSENTRY32`-тип, аналог — `PROCESSENTRY32` aliased к `PROCESSENTRY32W`. Чтобы не менять `CharacterSet` проекта, в `processes_hooks.h` определён локальный `struct ProcessEntry32Ansi`, дублирующий бинарный layout (`CHAR szExeFile[MAX_PATH]` вместо `WCHAR`).

### 4.9. Модуль сети (`network_hooks`)

Перехватывает три функции:

- **`WNetGetProviderNameW/A`** — pafish вызывает её с `WNNC_NET_RDR2SAMPLE` и проверяет, не возвращается ли `"VirtualBox Shared Folders"`. Если возвращается — возвращаем `ERROR_NO_NETWORK`.
- **`GetAdaptersInfo`** — для каждого адаптера сравниваем первые три байта MAC с `08:00:27` (OUI VirtualBox). Если совпадает — переписываем MAC на нули и заменяем Description с `virtualbox`/`vbox` на `Realtek PCIe GbE Family Controller`.
- **`GetAdaptersAddresses`** — то же, но для расширенной структуры. Помимо MAC и Description маскируются `FriendlyName` (на `Ethernet`), `AdapterName` (на `Realtek Controller`) и `DnsSuffix` (на пустую строку).

Маскировка MAC: первые 3 байта (OUI) меняем на нули — это «нейтральный» OUI, не привязанный ни к какому вендору.

### 4.10. Модуль прошивки (`firmwaretable_hooks`)

Самый объёмный сценарий. Поддерживает два API:
- `GetSystemFirmwareTable(Provider, TableID, Buffer, Size)` — получить таблицу.
- `EnumSystemFirmwareTables(Provider, Buffer, Size)` — перечислить таблицы.

#### 4.10.1. Провайдеры

Provider — это 4-байтовая сигнатура:
- `'ACPI'` — ACPI таблицы (RSDP, FACP, DSDT, …)
- `'RSMB'` — SMBIOS (raw)
- `'FIRM'` / `'RAW '` — другие firmware-данные

#### 4.10.2. ACPI

Для ACPI используется *подмена*: мы возвращаем синтетический `FakeAcpiTable` (определён в `config.h`):

```cpp
#pragma pack(push, 1)
struct FakeAcpiTable {
    char signature[5] = { 'R', 'S', 'D', ' ', 0 };
    DWORD length = 36;
    BYTE revision = 0;
    BYTE checksum = 0;
    char oemid[7] = { 'A', 'W', 'A', 'R', 'E', ' ', 0 };
    char oemtableid[9] = { 'G', 'E', 'N', 'U', 'I', 'N', 'E', ' ', 0 };
    DWORD oemrevision = 1;
    DWORD creatorid = 0;
    DWORD creatorrevision = 0;
    BYTE data[4] = { 0, 0, 0, 0 };
};
#pragma pack(pop)
```

Checksum пересчитывается на лету (`fakeTable.checksum = (BYTE)(0x100 - sum)`).

`EnumSystemFirmwareTables` для ACPI возвращает фиксированный набор «обычных» сигнатур: `RSD `, `FACP`, `MSWS`, `DSDT`, `FACP`, `SSDT`.

#### 4.10.3. SMBIOS

Для SMBIOS используется **двухступенчатый pass-through**:
1. Сначала вызываем оригинал, получаем настоящие данные.
2. Сканируем буфер на наличие строк `VirtualBox`, `vbox`, `VBOX`, `Oracle VM VirtualBox`, `Virtual Machine`, `VMware`, `QEMU`, `Xen` и заменяем их (через `FilterVirtualBoxStrings` в `vbox_filters.cpp`).
3. Увеличиваем кол-во SMBIOS таблиц до **45+**, добавляя «пустышки» (SMBIOS type 40) перед маркером End-Of-Table (type 127).

Зачем третий шаг: al-khaser проверяет, что таблиц **больше 40**. На bare-metal обычно ~50, в VBox ~6-8. Без инфляции проверка дала бы BAD.

Код инфляции (`firmwaretable_hooks.cpp:75-105`):

```cpp
const int kTargetMinTables = 45;   // >40 al-khaser threshold
// найти end-of-table, посчитать реальные таблицы
// если меньше kTargetMinTables — впихнуть нужное число пустышек
int need = kTargetMinTables - realCount;
DWORD growBytes = need * 6;  // каждая пустышка 6 байт (header + null/null strings)
// сдвинуть end-of-table, записать пустышки на освободившееся место
```

### 4.11. Модуль Hyper-V Object Directory (`hypervobj_hooks`)

Перехватывает `NtOpenDirectoryObject` и `NtQueryDirectoryObject`. Через них al-khaser/pafish могут проверять наличие объектов в `\Device\` namespace, специфичных для Hyper-V/VBox: `VMBUS`, `VDRVROOT`, `VmGenerationCounter`, `VmGid`, `VPCI`, `VID`, `HvSocket`, `Hyper-V`, `VBox*`.

Хук пост-обрабатывает результат `NtQueryDirectoryObject`: для каждого `OBJECT_DIRECTORY_INFORMATION` зануляет `Name.Length` и `TypeName.Length`, если имя матчит чёрный список. Это эффективно «прячет» элемент.

### 4.12. Модуль системы (`system_hooks`)

Два хука:

- **`SetupDiEnumDeviceInfo`** — при перечислении устройств через SetupAPI скрывает виртуальные. На первом вызове перечисляет всё, через `IsVirtualDevice` (читает `SPDRP_HARDWAREID` и ищет `vbox`/`vmware`/`qemu`/`virtual`) помечает виртуальные. Затем remap'ает индексы так, чтобы виртуальные пропускались.
- **`GetDiskFreeSpaceExW`** — если суммарный размер диска меньше 80 GB, переписывает на 100 GB. Иначе оставляет как есть.

### 4.13. Модуль питания (`power_hooks`)

Перехватывает `GetPwrCapabilities`. Al-khaser проверяет: если `(SystemS1 | S2 | S3 | S4) == 0 && ThermalControl == 0` — это VM. Хук принудительно ставит `SystemS3 = TRUE` и `ThermalControl = TRUE`, разрушая условие.

### 4.14. Модуль служб (`services_hooks`)

Перехватывает `EnumServicesStatusExW`. После вызова оригинала пробегается по списку служб и для имён из чёрного списка (`VBoxWddm`, `VBoxSF`, `VBoxMouse`, `VBoxGuest`, `VBoxService`, `VBoxVideo`, `vmci`, `vmhgfs`, `vmmouse`, `vmmemctl`, `vmusb`, `vmusbmouse`, `vmx_svga`, `vmxnet`, `vmx86`) меняет первый символ на `_`. Это ломает case-insensitive сравнение в детекторе.

### 4.15. Модуль WMI (`wmi_hooks`) — отдельная глава

WMI — это COM-интерфейсы, их нельзя перехватить классическим `MH_CreateHook` по имени функции. Вместо этого мы патчим **vtable-слоты** соответствующих интерфейсов.

#### 4.15.1. Какие vtable-слоты

```cpp
constexpr int kVtblSlot_Next      = 4;   // IEnumWbemClassObject::Next
constexpr int kVtblSlot_WbemGet   = 4;   // IWbemClassObject::Get
constexpr int kVtblSlot_ExecQuery = 20;  // IWbemServices::ExecQuery
```

Эти числа соответствуют позициям методов в C-style vtable (`lpVtbl`):
- `IUnknown` занимает первые 3 слота (`QueryInterface`, `AddRef`, `Release`).
- `IEnumWbemClassObject::Next` — 5-й метод (index 4).
- `IWbemClassObject::Get` — 5-й метод (index 4).
- `IWbemServices::ExecQuery` — 21-й метод (index 20).

#### 4.15.2. Проблема loader-lock

WMI требует COM (`CoInitializeEx` + `CoCreateInstance(CLSID_WbemLocator)`). `CoCreateInstance` внутри делает `LoadLibrary("wbemprox.dll")`, что **deadlock**ит loader-lock, если выполняется из `DllMain`. Поэтому установка WMI-хуков НЕ может быть синхронной из DllMain.

Решение — **trampoline на `CoCreateInstance`**:
1. В DllMain мы только ставим MinHook на `ole32!CoCreateInstance` (или `combase!CoCreateInstance` на новых Windows). Это безопасно — никаких COM-вызовов.
2. Когда target позже сам зовёт `CoCreateInstance(CLSID_WbemLocator, ...)`, наш `hook_CoCreateInstance` ловит вызов.
3. Внутри `hook_CoCreateInstance` мы вызываем оригинал, получаем `IWbemLocator*`, затем синхронно делаем `ConnectServer` → получаем `IWbemServices*` → `ExecQuery` → получаем `IEnumWbemClassObject*` → `Next` → получаем `IWbemClassObject*`. С этими тремя seed-объектами мы можем извлечь адреса vtable-методов и установить хуки.
4. Все последующие WMI-вызовы target'а идут через уже-патченные функции.

Используется `InterlockedCompareExchange` для гарантии одного выполнения bootstrap.

```cpp
static HRESULT WINAPI hook_CoCreateInstance(REFCLSID rclsid, ..., REFIID riid, LPVOID* ppv) {
    HRESULT hr = original_CoCreateInstance(rclsid, ..., ppv);
    if (SUCCEEDED(hr) && IsEqualCLSID(rclsid, CLSID_WbemLocator) &&
        InterlockedCompareExchange(&s_wmiBootstrapped, 1, 0) == 0) {
        IWbemLocator* pLocator = ...;
        DoWmiInstall(pLocator);
    }
    return hr;
}
```

#### 4.15.3. Pin-патч модуля

После установки хука на vtable-функцию мы вызываем `PinModuleContaining(target_address)` — это `GetModuleHandleExW` с флагом `GET_MODULE_HANDLE_EX_FLAG_PIN`. Этот флаг увеличивает счётчик ссылок модуля так, что он **никогда не выгружается** (даже если `CoFreeUnusedLibraries` решит почистить).

Без пина: после очередного `CoUninitialize` `fastprox.dll` или `wbemprox.dll` может выгрузиться, и наш патч окажется в памяти, которая больше не используется. Все следующие вызовы пойдут на perekompiled-адрес (если DLL пере-загрузится) — мимо нашего хука.

#### 4.15.4. Один shared dispatcher на все `Get`-хуки

Все `IWbemClassObject` в `ROOT\CIMV2` резолвят `Get` к **одному** адресу. MinHook может поставить только одну точку патча на адрес. Поэтому мы используем единый `Hook_DispatcherGet`, который читает `__CLASS` объекта и диспетчеризует на per-class логику в зависимости от глобальных флагов:

```cpp
bool g_BaseBoardEnabled, g_BusEnabled, g_PnPDeviceEnabled, g_BiosEnabled,
     g_ComputerSystemEnabled, g_VideoEnabled, g_ProcessorEnabled,
     g_LogicalDiskEnabled, g_ThermalEnabled, g_EventLogEnabled;
```

`Install{Class}Hook` ставит соответствующий флаг в true (и активирует диспетчер при первом вызове). `Remove{Class}Hook` снимает флаг (и удаляет диспетчер, когда все флаги off).

#### 4.15.5. Per-class spoof'ы

| Класс | Свойство | Спуфленное значение |
|---|---|---|
| `Win32_BaseBoard` | `Product` | `Standard PC` |
| `Win32_BaseBoard` | `Manufacturer` | `Microsoft Corporation` |
| `Win32_Bus` | `Name` | `ACPIBus_BUS_0` → `_1`, `PCI_BUS_0` → `_1`, `PNP_BUS_0` → `_1` |
| `Win32_PnPDevice` | `Name`/`Caption`/`PNPDeviceID` | `VBOX` → `Generic`, `VEN_VBOX` → `VEN_GENERIC` |
| `Win32_BIOS` | `SerialNumber` | `System Serial` |
| `Win32_ComputerSystem` | `Model` | `Standard PC` |
| `Win32_ComputerSystem` | `Manufacturer` | `Microsoft Corporation` |
| `Win32_VideoController` | `Caption` | `Generic VGA` |
| `Win32_Processor` | `NumberOfCores` | `4` |
| `Win32_Processor` | `ProcessorId` | `BFEBFBFF000906E9` |
| `Win32_LogicalDisk` | `Size` | `128000000000` (~119 GiB) |
| `MSAcpi_ThermalZoneTemperature` | `CurrentTemperature` | `300` |
| `Win32_NTEventlogFile` | `Sources[]` | элементы из `{vboxvideo, VBoxVideoW8, VBoxWddm, VBoxSF, VBoxMouse, VBoxGuest, VBoxService}` → `Generic` |

#### 4.15.6. Fake-row injection для пустых классов

Анти-VM проверка: «если `Win32_Fan` пустой → это VM». Решение — впрыснуть синтетический `FakeWbemObject` (наш C++ класс, реализующий `IWbemClassObject`) при первом `Next`, если оригинал ничего не вернул.

Список «критических» классов:
```cpp
static const wchar_t* kCriticalClasses[] = {
    L"Win32_Fan", L"Win32_CacheMemory", L"Win32_PhysicalMemory",
    L"Win32_MemoryDevice", L"Win32_MemoryArray", L"Win32_VoltageProbe",
    L"Win32_PortConnector", L"Win32_SMBIOSMemory",
    L"Win32_PerfFormattedData_Counters_ThermalZoneInformation",
    L"CIM_Memory", L"CIM_NumericSensor", L"CIM_PhysicalConnector",
    L"CIM_Sensor", L"CIM_Slot", L"CIM_TemperatureSensor",
    L"CIM_VoltageSensor", L"MSAcpi_ThermalZoneTemperature",
};
```

Когда `Hook_ExecQuery` видит WQL `SELECT * FROM <критический класс>`, он регистрирует получившийся enumerator в `s_enumStates[pEnum] = EnumState{ cls, false, false }`.

Когда `Hook_Next_FilterPnP` получает 0 объектов И enumerator в `s_enumStates` И ещё не инжектил — он создаёт `new FakeWbemObject(cls)`, кладёт в `apObjects[0]`, ставит `*puReturned = 1`, возвращает `WBEM_S_NO_ERROR`.

`FakeWbemObject` реализует `IWbemClassObject::Get`:
- `__CLASS` → класс, под который мы маскируемся.
- `MSAcpi_ThermalZoneTemperature.CurrentTemperature` → `300`.
- Всё остальное → пустой BSTR `L""`.

`AddRef/Release` через `InterlockedIncrement/Decrement`. Все остальные методы возвращают `E_NOTIMPL`.

#### 4.15.7. Фильтрация PnP

`Hook_Next_FilterPnP` (для `Win32_PnPEntity` enumerator'а) пробегает каждый объект и через `ShouldFilterPnPObject` проверяет:
- `Name` содержит `82801FB` / `82441FX` / `82371SB` / `OpenHCD` / `VBOX` → отфильтровать.
- `DeviceID` содержит `PCI\VEN_80EE&DEV_CAFE` (VBox vendor ID) → отфильтровать.

Отфильтрованный объект `Release`-ится, остальные сдвигаются в `apObjects`. Если после фильтрации в батче 0 объектов — повторяем `Next` (цикл `do { ... } while (out == 0)`), чтобы caller не получил неожиданное 0.

### 4.16. Модуль детектора отладчика (`debugger_hooks`)

Состоит из API-хуков и **прямого патча PEB/heap**:

#### 4.16.1. `IsDebuggerPresent`

```cpp
BOOL WINAPI hook_IsDebuggerPresent(void) {
    return FALSE;
}
```

Просто возвращает FALSE. Это покрывает pafish `debug_isdebuggerpresent` и al-khaser `Checking IsDebuggerPresent API`.

#### 4.16.2. `CheckRemoteDebuggerPresent`

```cpp
BOOL WINAPI hook_CheckRemoteDebuggerPresent(HANDLE hProcess, PBOOL pbDebuggerPresent) {
    BOOL ok = original_CheckRemoteDebuggerPresent(hProcess, pbDebuggerPresent);
    if (pbDebuggerPresent) *pbDebuggerPresent = FALSE;
    return ok;
}
```

Зовём оригинал (чтобы корректно отработать невалидный handle с `GetLastError()`), затем безусловно обнуляем out-параметр.

#### 4.16.3. `PatchPebDebuggerFlags()`

Это **не** API-хук, а прямая запись в PEB и heap:

```cpp
void PatchPebDebuggerFlags() {
    PBYTE peb = (PBYTE)__readgsqword(0x60);  // PEB на x64
    __try {
        peb[0x02] = 0;                                          // BeingDebugged
        *(PULONG)(peb + 0xBC) = 0;                              // NtGlobalFlag (x64)
        PBYTE pHeap = *(PBYTE*)(peb + 0x30);                    // PEB->ProcessHeap
        if (pHeap) {
            *(PULONG)(pHeap + 0x70) = 2;   // _HEAP.Flags = HEAP_GROWABLE
            *(PULONG)(pHeap + 0x74) = 0;   // _HEAP.ForceFlags = 0
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // на случай drift'а layout'а в будущих версиях Windows
    }
}
```

Что мы делаем:
- `PEB+0x02` (`BeingDebugged`): обнуляем. Pafish читает этот байт напрямую через `gs:[0x60]+0x02`. После патча видит 0.
- `PEB+0xBC` (`NtGlobalFlag`): обнуляем. Под отладчиком там стоят `FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS`. Al-khaser проверяет эти биты.
- `PEB->ProcessHeap->Flags` и `ForceFlags`: обнуляем (точнее, `Flags = 2 = HEAP_GROWABLE`). Под отладчиком там стоят debug-heap флаги. Al-khaser читает их напрямую и проверяет `Flags > 2`.

**Safety**: запись в `_HEAP` после инициализации — стандартная anti-anti-debug практика. Heap manager использует эти поля только при создании heap'а, дальше они только для проверки. Не сломает работу heap'а.

**Совместимость с DebuggerWrapper**: kernel debug port (`EPROCESS.DebugPort`) находится в kernel-space и нашими user-mode записями не затрагивается. Отладчик продолжает корректно получать debug-events.

`PatchPebDebuggerFlags()` вызывается из `InitializeDebuggerHooks()` после установки `IsDebuggerPresent` хука.

### 4.17. Модуль времени (`time_hooks`)

```cpp
static constexpr DWORD     kTickOffsetMs   = 1'800'000;       // 30 min
static constexpr ULONGLONG kTickOffsetMs64 = 1'800'000ULL;

DWORD     WINAPI hook_GetTickCount(void)    { return original_GetTickCount()    + kTickOffsetMs; }
ULONGLONG WINAPI hook_GetTickCount64(void)  { return original_GetTickCount64()  + kTickOffsetMs64; }
```

Pafish `gensandbox_uptime`: `GetTickCount() < 0xAFE74 ? TRUE : FALSE` (~12 минут). Если uptime меньше 12 мин — sandbox.

Сдвиг на 30 минут гарантирует прохождение. **Дельта между двумя вызовами `GetTickCount` остаётся корректной** (потому что offset константный), так что pafish `gensandbox_sleep_patched` (проверка `Sleep(500)` → дельта ≥ 450 мс) продолжает работать.

### 4.18. Модуль ввода (`input_hooks`)

```cpp
BOOL WINAPI hook_GetLastInputInfo(PLASTINPUTINFO plii) {
    BOOL ok = original_GetLastInputInfo(plii);
    if (ok && plii) plii->dwTime = GetTickCount() - 50;
    return ok;
}
```

Al-khaser `lack_user_input`: цикл `for (i=0; i<128; ++i)`, в каждом итере `Sleep(11)`; затем `if (GetTickCount() - dwTime < 100) counter++`; если `counter >= 10` — пользователь активен. Без хука этого модуля наш `GetTickCount + 30мин` ломает арифметику (дельта зашкаливает), al-khaser возвращает BAD.

Решение: `GetLastInputInfo` возвращает `dwTime = (наш hooked GetTickCount) - 50`. Дельта = 50 < 100 — пройдено. Через `GetTickCount()` тут зовётся **наш хук** (не оригинал), что симметризует значения.

### 4.19. Модуль process-info (`process_info_hooks`)

Перехватывает три функции на ntdll/kernel32:

#### 4.19.1. `NtQueryInformationProcess`

Маскирует три класса информации:

| Класс | Значение | Как маскируем |
|---|---|---|
| `ProcessDebugPort` (7) | HANDLE debug port | в out-буфер пишем 0 |
| `ProcessDebugFlags` (0x1F) | ULONG (1=не отлаживается) | в out-буфер пишем 1 |
| `ProcessDebugObjectHandle` (0x1E) | HANDLE debug object | пишем 0 в out-буфер, ВТОРЫМ — `ProcessInformationLength` в `ReturnLength`. Возвращаем `STATUS_PORT_NOT_SET = 0xC0000353` |

Важный момент с `ProcessDebugObjectHandle`: al-khaser передаёт **один и тот же указатель** на `ProcessInformation` и `ReturnLength` (overlapping) и проверяет три условия:
1. `Status == STATUS_PORT_NOT_SET`
2. `hDebugObject != NULL` (то есть какая-то запись произошла)
3. `(ULONG)hDebugObject == ProcessInformationLength` (то есть последняя запись была в `ReturnLength`)

Чтобы все три условия совпали, наш хук пишет в нужном порядке: сначала handle = 0, потом length = piLen. С overlapping буферами final-значение по адресу содержит `piLen` в младших 32 битах (что и проверяет al-khaser).

#### 4.19.2. Self-handle detection без рекурсии

```cpp
static bool IsSelfPseudoHandle(HANDLE h) {
    return h == GetCurrentProcess();   // (HANDLE)-1, ноль syscall'ов
}
```

**Критически важно**: НЕ зовём `GetProcessId(h)` для проверки. `GetProcessId` внутри делает `NtQueryInformationProcess(handle, ProcessBasicInformation)`, что снова вызовет наш хук → бесконечная рекурсия → `STATUS_STACK_OVERFLOW` (0xC00000FD).

Это была реальная проблема при разработке: первая версия хука использовала `GetProcessId`, и al-khaser падал на тесте `IsParentExplorerExe` (который открывает реальный handle родительского процесса).

Дополнительная защита — `thread_local int g_inQueryInformationHook` как guard от ре-вхождений, если в будущем добавятся helper-вызовы.

#### 4.19.3. `NtClose` и `CloseHandle`

Под отладчиком вызов `CloseHandle(invalid_handle)` приводит к kernel-генерируемому исключению `STATUS_INVALID_HANDLE` в процесс. Al-khaser оборачивает вызов в `__try/__except` и по факту срабатывания делает вывод о наличии отладчика.

Решение: оборачиваем оригинал в свой `__try/__except`:

```cpp
LONG NTAPI hook_NtClose(HANDLE Handle) {
    __try { return original_NtClose(Handle); }
    __except (EXCEPTION_EXECUTE_HANDLER) { return STATUS_INVALID_HANDLE; }
}

BOOL WINAPI hook_CloseHandle(HANDLE Handle) {
    __try { return original_CloseHandle(Handle); }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }
}
```

Exception, выброшенный из kernel, проходит через DebuggerWrapper (DBG_EXCEPTION_NOT_HANDLED), доходит до нашего `__except`, гасится. До al-khaser-кого `__except` уже не доходит.

### 4.20. Модуль object-info (`object_info_hooks`)

Перехватывает `NtQueryObject` с классом `ObjectAllTypesInformation = 3`. Эта функция возвращает массив всех типов объектов в kernel-space системы. Один из элементов — `DebugObject`. Под активной отладкой `TotalNumberOfObjects` у `DebugObject` > 0, что детектируется.

Хук пост-обрабатывает буфер: проходит по массиву `OBJECT_TYPE_INFORMATION`, ищет элемент с `TypeName.Buffer == L"DebugObject"`, обнуляет `TotalNumberOfObjects` и `TotalNumberOfHandles`.

Логика прохода по массиву нетривиальна — каждый элемент содержит inline-указатель на `TypeName.Buffer`, после буфера выровненный padding до `sizeof(void*)`. Идём `[record][buffer][align]…`.

### 4.21. Модуль module-hide (`module_hide_hooks`)

Два слоя: PEB.Ldr unlink + хуки на `GetMappedFileName`/`NtQueryVirtualMemory`.

#### 4.21.1. `HideHooksboxModule(HMODULE hSelf)`

Алгоритм:
1. Сохраняем `g_hooksboxBase = hSelf`, читаем PE-заголовок (DOS + NT), вычисляем `g_hooksboxEnd = base + SizeOfImage`.
2. Через `gs:[0x60]+0x18` (x64) находим `PEB->Ldr` — указатель на `PEB_LDR_DATA`.
3. Идём по `InLoadOrderModuleList`. Для каждого `LDR_DATA_TABLE_ENTRY` сравниваем `DllBase == hSelf`. Когда находим — отвязываем из ВСЕХ списков:
   - `InLoadOrderLinks`
   - `InMemoryOrderLinks`
   - `InInitializationOrderLinks`
   - `HashLinks` (Win7+)
4. Очищаем поля `DllBase`, `SizeOfImage`, `FullDllName.Buffer`, `BaseDllName.Buffer` — чтобы memory-scanner'ы не нашли по сигнатуре.

После этого:
- `EnumProcessModulesEx` (любой режим) нас не видит.
- `Module32First/Next` (CreateToolhelp32Snapshot) нас не видит.
- `LdrEnumerateLoadedModules` нас не видит.
- Прямой walk через `PEB->Ldr` нас не видит.
- `GetModuleHandleEx(..., GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, ourAddr, ...)` возвращает FALSE.

Что **не** покрывается одним только LDR-unlink — `GetMappedFileNameW`. Эта функция использует kernel-side `NtQueryVirtualMemory(MemorySectionName)`, который читает из таблицы маппингов секций, а не из PEB.Ldr.

#### 4.21.2. Хук `NtQueryVirtualMemory`

```cpp
LONG NTAPI hook_NtQueryVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress,
    ULONG MemoryInformationClass, PVOID MemoryInformation,
    SIZE_T MemoryInformationLength, PSIZE_T ReturnLength) {

    if (MemoryInformationClass == kMemorySectionName &&   // 2
        ProcessHandle == GetCurrentProcess() &&
        BaseAddress >= g_hooksboxBase && BaseAddress < g_hooksboxEnd) {
        if (ReturnLength) *ReturnLength = 0;
        return STATUS_INVALID_ADDRESS;   // 0xC0000141
    }
    return original_NtQueryVirtualMemory(...);
}
```

Когда target вызывает `GetMappedFileNameW(GetCurrentProcess(), addr_in_hooksbox, …)` — функция внутри делает syscall `NtQueryVirtualMemory(class=2, addr_in_hooksbox)`. Наш хук на ntdll-уровне видит, что адрес наш, возвращает `STATUS_INVALID_ADDRESS`. Снаружи это выглядит как «по этому адресу нет маппинга файла».

#### 4.21.3. Почему хук именно на ntdll

Раньше были хуки на `psapi!GetMappedFileNameW/A`. Но на Win10/11 эта функция — forwarder в цепочке `psapi → kernel32 → kernelbase`. В зависимости от того, к какому линку привязал линкер каждого вызывающего, MinHook-патч на одном линке мог быть в обход. Хук на нижнем уровне (`ntdll!NtQueryVirtualMemory`) гарантирует, что любой путь через `GetMappedFileName*` проходит через нас.

Старые хуки на `GetMappedFileNameW/A` оставлены как defense-in-depth — overhead нулевой, дополнительная страховка.

### 4.22. `vbox_filters` — общие предикаты

Файл `filters/vbox_filters.{h,cpp}` содержит общие функции-проверки, которые использует несколько модулей хуков:

| Функция | Назначение |
|---|---|
| `IsVBoxRegistryKey(hKey, lpSubKey)` | Wide: содержит ли путь VBox-имя |
| `IsVBoxFilePath(lpFileName)` | Wide: путь к VBox-файлу |
| `IsVBoxDetectionAttempt(lpFileName, flags…)` | Wide: detection-pattern для CreateFile |
| `IsHiddenProcessW(processName)` | Wide: имя процесса в чёрном списке |
| `IsVirtualBoxMAC(mac, len)` | MAC начинается с `08:00:27` |
| `MaskMACAddress(mac, len)` | Обнулить первые 3 байта |
| `ContainsVirtualBoxString(data, size)` | В буфере есть VBox-строка |
| `FilterVirtualBoxStrings(data, size)` | Заменить VBox-строки в буфере in-place |
| `IsVirtualDevice(hDevInfo, devData)` | Setup-устройство virtual |
| `IsVBoxRegistryKeyA(hKey, lpSubKey)` | ANSI mirror |
| `IsVBoxFilePathA(lpFileName)` | ANSI mirror |
| `IsVBoxDetectionAttemptA(...)` | ANSI mirror |
| `IsHiddenProcessA(processName)` | ANSI mirror |

ANSI-зеркала имеют отдельные таблицы паттернов в `vbox_filters.cpp` (`kVBoxRegistryPathsA`, `kVBoxFilePathsA`, `kVBoxDevicePathsA`).

### 4.23. Логирование (`utils/log_utils`)

```cpp
void DebugPrint(const char* text);         // OutputDebugStringA
void DebugPrintW(const wchar_t* text);     // OutputDebugStringW
void WriteFileLog(const wchar_t* level, const std::wstring& msg);
bool EqualsCaseInsensitive(const std::wstring& a, const std::wstring& b);
```

`WriteFileLog` пишет в файл `sandbox_evasion.log` в текущей директории процесса. Формат:
```
2026-05-24 12:34:56 [INFO] message text
```
UTF-8 + BOM при первой записи. Thread-safe через `CRITICAL_SECTION`, инициализируемую лениво через `InterlockedCompareExchange`.

WMI-хуки используют макросы:
```cpp
#define WMIHOOK_INFO(msg)  WriteFileLog(L"INFO",  (msg))
#define WMIHOOK_WARN(msg)  WriteFileLog(L"WARN",  (msg))
#define WMIHOOK_ERROR(msg) WriteFileLog(L"ERROR", (msg))
```

### 4.24. `hooksbox.def` и экспортируемая функция

Файл `hooksbox.def`:
```
LIBRARY hooksbox
EXPORTS
    InitializeMyHooks
```

Экспортирует одну функцию для ручной инициализации (если кому-то нужно реинжектировать DLL после загрузки):

```cpp
extern "C" __declspec(dllexport) void InitializeMyHooks() {
    InitializeHooks();
}
```

В нормальном сценарии не используется — DllMain делает всё сам.

### 4.25. `config.h` — таблицы

Содержит массивы строк-паттернов:
- `VBOX_REGISTRY_PATHS` — 9 wide-строк для матчинга путей реестра.
- `VBOX_DISK_ENUM_CHECKS` — 7 строк для матчинга в Disk\Enum.
- `VBOX_DRIVERS_PATHS` — 5 драйверов в system32\drivers.
- `VBOX_SYSTEM_FILES_PATHS` — 14 файлов (DLL, EXE).
- `VBOX_DEVICE_PATHS` — 8 device-имён.
- `VIRTUALBOX_PROVIDER_NAME = L"VirtualBox Shared Folders"`.
- Структуры `FakeAcpiTable`, `FakeSmbiosTable`.

### 4.26. Полный список перехваченных функций

**kernel32.dll**: `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, `CloseHandle`, `GetTickCount`, `GetTickCount64`, `Process32First`, `Process32Next` (+ W варианты), `GetFileAttributesW`, `GetFileAttributesA`, `CreateFileW`, `CreateFileA`, `FindWindowW`, `FindWindowExW`, `FindWindowA`, `FindWindowExA`, `GetDiskFreeSpaceExW`, `GetSystemFirmwareTable`, `EnumSystemFirmwareTables`, `K32GetMappedFileNameW`, `K32GetMappedFileNameA`.

**ntdll.dll**: `NtClose`, `NtOpenDirectoryObject`, `NtQueryDirectoryObject`, `NtQueryInformationProcess`, `NtQueryObject`, `NtQueryVirtualMemory`.

**user32.dll**: `GetLastInputInfo`.

**advapi32.dll**: `RegOpenKeyExW`, `RegOpenKeyExA`, `RegQueryValueExW`, `RegQueryValueExA`, `RegEnumKeyExW`, `RegEnumKeyExA`, `EnumServicesStatusExW`.

**setupapi.dll**: `SetupDiEnumDeviceInfo`.

**iphlpapi.dll**: `GetAdaptersInfo`, `GetAdaptersAddresses`.

**mpr.dll**: `WNetGetProviderNameW`, `WNetGetProviderNameA`.

**powrprof.dll**: `GetPwrCapabilities`.

**ole32.dll / combase.dll**: `CoCreateInstance` (bootstrap для WMI).

**COM vtable patches**: `IWbemServices::ExecQuery` (slot 20), `IEnumWbemClassObject::Next` (slot 4), `IWbemClassObject::Get` (slot 4).

---

## 5. Компонент 2: DebuggerWrapper.exe

### 5.1. Назначение

CPU-инструкции `CPUID` и `RDTSC` не проходят через user-mode WinAPI, их нельзя перехватить через MinHook. Чтобы замаскировать их, мы запускаем целевой процесс **под отладчиком** (через Windows Debug API), сканируем `.text` секцию на байт-паттерны этих инструкций (`0F A2` и `0F 31`), пишем `INT 3` (`0xCC`) поверх первого байта, и в debug-event loop обрабатываем `EXCEPTION_BREAKPOINT`:
- Если адрес BP — наш, эмулируем оригинальную инструкцию с подменёнными результатами, восстанавливаем регистры, продвигаем `RIP` за инструкцию, продолжаем.
- Иначе — отдаём управление дальше (target обрабатывает сам или падает).

### 5.2. Архитектура

```
main.cpp
  ├─ ParseCommandLine()                   [config.cpp]
  ├─ Logger::Init()                       [logger.cpp]
  └─ RunDebuggerLoop()                    [debugger_core.cpp]
       ├─ CreateProcess(DEBUG_ONLY_THIS_PROCESS)
       ├─ В CREATE_PROCESS_DEBUG_EVENT:
       │     ├─ ScanAndInstallBreakpoints()  [instruction_scanner.cpp + breakpoint_manager.cpp]
       │     └─ InjectDllViaRemoteThread()   [+ SuspendThread main]
       ├─ Loop: WaitForDebugEvent
       │     ├─ LOAD_DLL_DEBUG_EVENT
       │     ├─ EXCEPTION_DEBUG_EVENT (EXCEPTION_BREAKPOINT)
       │     │     ├─ bps.Find(addr)
       │     │     ├─ if cpuid → HandleCpuidBp()  [cpuid_handler.cpp]
       │     │     └─ if rdtsc → HandleRdtscBp()  [rdtsc_handler.cpp]
       │     ├─ EXIT_THREAD (injector) → ResumeThread main
       │     └─ EXIT_PROCESS → break
       └─ Cleanup, print summary
```

### 5.3. CLI и конфигурация (`main.cpp`, `config.{h,cpp}`)

Структура `Config`:

```cpp
struct Config {
    std::wstring targetPath;
    std::wstring targetArgs;
    std::wstring logPath    = L"debugger_wrapper.log";
    LogLevel     logLevel   = LogLevel::Info;
    bool         alsoStdout = true;
    bool         enableCpuid = false;   // off by default!
    bool         enableRdtsc = true;
    uint32_t     jitterMin = 80;
    uint32_t     jitterMax = 200;
    bool         scanDlls   = false;
    std::wstring injectDll;             // --inject path/to/hooksbox.dll
};
```

Флаги CLI:

| Флаг | Эффект |
|---|---|
| `--target <path>` | (обязательный) что запускать |
| `--args <str>` | аргументы целевому процессу |
| `--log <path>` | путь к логу (по умолчанию `debugger_wrapper.log`) |
| `--level ERROR\|INFO\|DEBUG` | детальность лога |
| `--no-stdout` | не дублировать лог в stdout |
| `--cpuid` | включить маскировку CPUID (по умолчанию OFF) |
| `--no-cpuid` | явное OFF (по умолчанию уже OFF, для совместимости) |
| `--no-rdtsc` | выключить маскировку RDTSC |
| `--scan-dlls` | сканировать загруженные DLL (опасно — много false positive) |
| `--jitter-min N`, `--jitter-max N` | разброс приращения virtual TSC за один RDTSC |
| `--inject <dll>` | инжектировать DLL через CreateRemoteThread+LoadLibrary |
| `--help` | usage |

**Почему CPUID off по умолчанию**: наивный байт-паттерн скан `0F A2` иногда находит false positive (когда эти байты — часть другой инструкции или данных). `INT 3` на таком адресе при срабатывании ломает выполнение, исключение «протекает» через debugger как `STATUS_BREAKPOINT (0x80000003)`, процесс падает. Эти CPU-проверки (`cpuid_is_hypervisor`, `cpuid_hypervisor_vendor`) на bare-metal хостах и так возвращают OK (HV-бит = 0, vendor пустой). Маскировка нужна только в реальном hypervisor-госте — туда включается через `--cpuid`.

### 5.4. Логгер (`logger.{h,cpp}`)

Класс-синглтон `Logger`. Методы:
- `Init(path, level, alsoStdout)`
- `Shutdown()`
- `Log(level, component, fmt, ...)` — printf-like

Уровни: `Error`, `Info`, `Debug`. По умолчанию `Info`.

Формат: `[YYYY-MM-DD HH:MM:SS.mmm][LEVEL][component] message`

Thread-safe (`CRITICAL_SECTION`), UTF-8 + BOM. Дублирование в stdout опционально.

Макросы:
```cpp
#define DBG_LOG_E(comp, fmt, ...) Logger::Instance().Log(LogLevel::Error, comp, fmt, __VA_ARGS__)
#define DBG_LOG_I(comp, fmt, ...) Logger::Instance().Log(LogLevel::Info,  comp, fmt, __VA_ARGS__)
#define DBG_LOG_D(comp, fmt, ...) Logger::Instance().Log(LogLevel::Debug, comp, fmt, __VA_ARGS__)
```

### 5.5. Сканер инструкций (`instruction_scanner.{h,cpp}`)

`ScanAndInstallBreakpoints(hProcess, imageBase, bps, wantCpuid, wantRdtsc, moduleName)`:

1. Через `ReadProcessMemory` читает DOS-header → NT-header образа.
2. Перечисляет секции (`IMAGE_SECTION_HEADER[]`).
3. Для каждой секции с флагом `IMAGE_SCN_MEM_EXECUTE`:
   - Читает данные секции чанками 64 KiB (с перекрытием 1 байт — на случай паттерна на границе).
   - Сканирует на `0F A2` (CPUID) и `0F 31` (RDTSC):
     ```cpp
     for (size_t i = 0; i + 1 < got; ++i) {
         if (buf[i] != 0x0F) continue;
         uint8_t b1 = buf[i + 1];
         uintptr_t addr = base + offset + i;
         if (wantCpuid && b1 == 0xA2) bps.Install(hProcess, addr, BpKind::Cpuid, 0x0F, 0xA2);
         else if (wantRdtsc && b1 == 0x31) bps.Install(hProcess, addr, BpKind::Rdtsc, 0x0F, 0x31);
     }
     ```
4. Логирует кол-во найденных паттернов и успешно установленных BP.

### 5.6. Менеджер точек останова (`breakpoint_manager.{h,cpp}`)

`BreakpointManager`:
```cpp
struct BpInfo { BpKind kind; uint8_t origByte; uint8_t secondByte; };

bool Install(HANDLE hProcess, uintptr_t address, BpKind kind, uint8_t origByte, uint8_t secondByte);
const BpInfo* Find(uintptr_t address) const;
```

Установка BP:
1. `VirtualProtectEx(addr, 1, PAGE_EXECUTE_READWRITE, &oldProt)` — снимаем защиту записи.
2. `WriteProcessMemory(addr, &0xCC, 1)` — пишем `INT 3`.
3. `VirtualProtectEx(addr, 1, oldProt, ...)` — возвращаем защиту.
4. `FlushInstructionCache(hProcess, addr, 1)` — сбрасываем кеш инструкций.
5. Запоминаем `bps_[address] = BpInfo{kind, origByte, secondByte}`.

Восстановления оригинального байта нет — мы эмулируем инструкцию и продвигаем `RIP`, оригинал никогда не выполняется.

### 5.7. Основной debug-event loop (`debugger_core.{h,cpp}`)

#### 5.7.1. Запуск

```cpp
CreateProcessW(nullptr, cmdBuf.data(), nullptr, nullptr, FALSE,
               DEBUG_ONLY_THIS_PROCESS, nullptr, nullptr, &si, &pi);
```

`DEBUG_ONLY_THIS_PROCESS` — флаг, делающий наш процесс debugger'ом для target. Все debug-event-ы (создание потоков, загрузка DLL, исключения) поступают нам через `WaitForDebugEvent`.

#### 5.7.2. Основной цикл

```cpp
while (running) {
    DEBUG_EVENT de{};
    WaitForDebugEvent(&de, INFINITE);
    DWORD continueStatus = DBG_CONTINUE;
    switch (de.dwDebugEventCode) {
    case CREATE_PROCESS_DEBUG_EVENT: ... break;
    case LOAD_DLL_DEBUG_EVENT:       ... break;
    case UNLOAD_DLL_DEBUG_EVENT:     ... break;
    case CREATE_THREAD_DEBUG_EVENT:  ... break;
    case EXIT_THREAD_DEBUG_EVENT:    ... break;
    case OUTPUT_DEBUG_STRING_EVENT:  ... break;
    case EXCEPTION_DEBUG_EVENT:      ... break;
    case EXIT_PROCESS_DEBUG_EVENT:   running = false; break;
    }
    ContinueDebugEvent(de.dwProcessId, de.dwThreadId, continueStatus);
}
```

#### 5.7.3. `CREATE_PROCESS_DEBUG_EVENT`

При создании процесса:
1. Сканируем target.exe на CPUID/RDTSC паттерны через `ScanAndInstallBreakpoints`.
2. Если `--inject` задан — `InjectDllViaRemoteThread`. **Сразу после** успешного `CreateRemoteThread` делаем `SuspendThread(info.hThread)` — это ключ от race condition (см. 5.7.5).
3. Запоминаем main thread в `threadHandles[de.dwThreadId] = info.hThread`.
4. `mainTid = de.dwThreadId; mainThreadHandle = info.hThread;`

#### 5.7.4. `EXCEPTION_DEBUG_EVENT` (`EXCEPTION_BREAKPOINT`)

```cpp
if (er.ExceptionCode == EXCEPTION_BREAKPOINT) {
    const BpInfo* info = bps.Find(addr);
    if (info && hThread) {
        bool ok = false;
        if (info->kind == BpKind::Cpuid) ok = HandleCpuidBp(hThread, stats);
        else if (info->kind == BpKind::Rdtsc) ok = HandleRdtscBp(hThread, vtsc, stats);
        if (!ok) continueStatus = DBG_EXCEPTION_NOT_HANDLED;
    } else {
        // foreign BP — passing through
        continueStatus = DBG_EXCEPTION_NOT_HANDLED;
    }
}
```

Особый случай — первое срабатывание после старта: ntdll-loader всегда генерирует системный BP в `LdrDoDebuggerBreak`. Мы его специально пропускаем (`sawInitialSystemBp` флаг), потому что это нормальное поведение.

#### 5.7.5. Inject-race fix

Без фикса: после `ContinueDebugEvent` на `CREATE_PROCESS_DEBUG_EVENT` И главный поток target'а, И только что созданный injector-поток с `LoadLibraryW` становятся runnable. Они бегут параллельно. Быстрые target'ы (pafish — минимальный CRT, баннер сразу → `IsDebuggerPresent`) успевают исполнить anti-debug проверки **до** того, как DllMain нашего DLL завершится.

Решение: после `CreateRemoteThread` мы поднимаем suspend count главного потока на 1 через `SuspendThread`. Kernel при `ContinueDebugEvent` уменьшает его на 1 (он был = 1 из-за debug-event), итог: главный поток **всё ещё** suspended. Бежит только injector. Когда injector выходит (`EXIT_THREAD_DEBUG_EVENT` с его TID) — мы делаем `ResumeThread(mainThreadHandle)`. К этому моменту `LoadLibraryW` уже вернул, значит все цепочные DllMain (hooksbox + его зависимости) отработали, хуки на месте, PEB обнулён.

Код в `EXIT_THREAD_DEBUG_EVENT`:
```cpp
if (de.dwThreadId == injectorTid && mainThreadSuspended && mainThreadHandle) {
    ResumeThread(mainThreadHandle);
    mainThreadSuspended = false;
}
```

### 5.8. CPUID handler (`cpuid_handler.{h,cpp}`)

```cpp
CpuidRegs EmulateAndMaskCpuid(uint32_t leaf, uint32_t subleaf, CpuidRegs& hostRaw) {
    int regs[4] = {0};
    __cpuidex(regs, leaf, subleaf);
    hostRaw = { regs[0], regs[1], regs[2], regs[3] };

    CpuidRegs out = hostRaw;

    if (leaf == 0x00000001u) {
        out.ecx &= ~(1u << 31);   // снять HV-бит
    }
    if (leaf >= 0x40000000u && leaf <= 0x400000FFu) {
        out.eax = out.ebx = out.ecx = out.edx = 0;   // обнулить vendor leaves
    }
    return out;
}
```

`HandleCpuidBp` (`debugger_core.cpp:HandleCpuidBp`):
1. `GetThreadContext(hThread, &ctx)` (с `CONTEXT_FULL`).
2. Читаем `leaf = (uint32_t)ctx.Rax`, `subleaf = (uint32_t)ctx.Rcx`.
3. Вычисляем `masked = EmulateAndMaskCpuid(leaf, subleaf, raw)`.
4. Записываем `ctx.Rax = masked.eax`, `ctx.Rbx = masked.ebx`, `ctx.Rcx = masked.ecx`, `ctx.Rdx = masked.edx`.
5. `ctx.Rip += 1` (см. ниже).
6. `SetThreadContext(hThread, &ctx)`.
7. `stats.cpuidIntercepts++`.

**Почему `Rip += 1`, а не `+= 2`**: оригинальная инструкция CPUID — 2 байта (`0F A2`). После замены первого байта на `INT 3` (`CC`), при срабатывании BP kernel `auto-advance`-ит RIP на 1 (за `CC`). Получается RIP указывает на второй байт оригинала (`A2`). Чтобы пропустить остаток (1 байт), добавляем 1. Итог: RIP смотрит на инструкцию **после** оригинальной CPUID. Правильно.

### 5.9. RDTSC handler (`rdtsc_handler.{h,cpp}`)

#### 5.9.1. `VirtualTsc`

```cpp
class VirtualTsc {
public:
    void Init(uint32_t jitterMin, uint32_t jitterMax);
    uint64_t Tick();             // вернуть следующее значение
    uint64_t Current() const { return current_; }
private:
    uint64_t current_ = 0;
    uint32_t jitterMin_, jitterMax_;
    uint64_t rngState_ = 0;
};
```

`Init` сэмплит `__rdtsc()` как начальную точку и seedит RNG из (TSC ^ GetTickCount64 ^ PID).

`Tick()` приращивает `current_` на случайное число в диапазоне `[jitterMin, jitterMax]` (по умолчанию `[80, 200]`). Использует SplitMix64 RNG. Возвращает новое значение.

#### 5.9.2. `HandleRdtscBp`

```cpp
bool HandleRdtscBp(HANDLE hThread, VirtualTsc& vtsc, RunStats& stats) {
    CONTEXT ctx{}; ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(hThread, &ctx);
    uint64_t now = vtsc.Tick();
    ctx.Rax = now & 0xFFFFFFFFull;
    ctx.Rdx = (now >> 32) & 0xFFFFFFFFull;
    ctx.Rip += 1;   // та же логика, что и для CPUID
    SetThreadContext(hThread, &ctx);
    stats.rdtscIntercepts++;
    return true;
}
```

Каждый RDTSC возвращает виртуальное значение, которое всегда монотонно растёт на случайное число тактов. Это разрушает RDTSC-тайминг проверки: разница `t2 - t1` всегда в пределах `[jitterMin, jitterMax]`, независимо от того, что произошло между ними. CPUID-внутри-RDTSC проверка не сможет различить «VM-exit от CPUID занял много тактов» от «обычная инструкция».

### 5.10. Inject (`InjectDllViaRemoteThread`)

Стандартный CreateRemoteThread paradigm:
1. `GetFullPathNameW` — резолвим в абсолютный путь (относительный путь target не найдёт).
2. `VirtualAllocEx(hProcess, ..., PAGE_READWRITE)` — выделяем память в target'е.
3. `WriteProcessMemory` — копируем туда путь к DLL.
4. `GetProcAddress(kernel32, "LoadLibraryW")` — адрес функции (один и тот же во всех процессах с одинаковым ASLR-сидом, что верно для kernel32 в одном logon session).
5. `CreateRemoteThread(hProcess, ..., pLoadLibraryW, remoteMem, 0, &remoteTid)` — стартует поток, который выполнит `LoadLibraryW(remoteMem)`.
6. Закрываем свой handle потока, путь освободим в EXIT_THREAD.

`remoteTid` запоминается, в loop-е мы знаем, что `EXIT_THREAD` с этим TID — наш injector.

### 5.11. Подтверждение успешной инжекции

Раньше мы ждали `GetExitCodeThread(injectorTid)` и проверяли != 0 (предполагая, что LoadLibraryW вернёт HMODULE). На современных Windows это не работает — kernel zero-ит RAX в exit-thunk потока как mitigation от info-disclosure. Поэтому `code` всегда 0.

Решение: проверяем `LOAD_DLL_DEBUG_EVENT` — kernel шлёт его, когда DLL действительно смаплен. Сравниваем имя загруженного DLL (через `ReadRemoteImageName`) с тем, что мы пытались инжектить. Если совпало — успех:

```cpp
if (!injectedDllPathLower.empty() && lowered == injectedDllPathLower) {
    injectedDllLoaded = true;
    DBG_LOG_I(COMP_CORE, L"Confirmed inject DLL is mapped at 0x%p", info.lpBaseOfDll);
}
```

При `EXIT_THREAD` injector'а проверяем `injectedDllLoaded` — это и есть authoritative signal.

---

## 6. Компонент 3: launcher.exe

### 6.1. Назначение

Front-end. Без launcher'а пользователю пришлось бы:
1. Знать про `DebuggerWrapper.exe` и его CLI-флаги.
2. Знать про `hooksbox.dll` и как его инжектить.
3. Запускать руками в правильной последовательности.

Launcher либо интерактивно спрашивает («Inject?», «Debug?»), либо принимает флаги.

### 6.2. Режимы

| Inject | Debug | Режим | Что делается |
|---|---|---|---|
| n | n | **raw** | `CreateProcess(target)` — как есть |
| y | n | **inject** | `CreateProcess(CREATE_SUSPENDED)` → `InjectIntoProcess` → `ResumeThread` |
| n | y | **debug** | `DebuggerWrapper.exe --target <path>` |
| y | y | **debug+inject** | `DebuggerWrapper.exe --target <path> --inject <hooksbox.dll>` |

### 6.3. Раскладка CLI

```
launcher.exe                              # интерактивные prompts
launcher.exe <target.exe>                 # интерактивные prompts на режим
launcher.exe --inject <target.exe>        # явно inject
launcher.exe --debug <target.exe> [...]   # явно debug, остальное → DebuggerWrapper
launcher.exe --debug-inject <target.exe>  # debug + inject
```

Всё после target в `--debug` / `--debug-inject` форвардится в `DebuggerWrapper.exe`:
```
launcher.exe --debug-inject pafish.exe --cpuid --level DEBUG --log run.log
                                       └────── forwarded ────────┘
```

### 6.4. Архитектурная проверка (`ReadPeMachineArch`)

Перед injection launcher читает PE-headers и target.exe, и hooksbox.dll. Если архитектуры не совпадают — сразу ошибка:
```
*** ARCH MISMATCH: cannot inject x64 (64-bit) DLL into x86 (32-bit) process.
    This is exactly the case that surfaces as Windows error 0xC0000020
    ("the program is not designed to run on this Windows version").
    Rebuild HooksBox for the matching architecture, or pick a target with
    the matching arch.
```

Это предотвращает запутанные диагностики после неудачной инжекции.

### 6.5. `InjectIntoProcess` (для не-debug режима)

```cpp
LPVOID remoteMemory = VirtualAllocEx(hProcess, NULL, pathSize, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
WriteProcessMemory(hProcess, remoteMemory, dllPath.c_str(), pathSize, NULL);
HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
LPVOID loadLibraryAddr = GetProcAddress(kernel32, "LoadLibraryW");
HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, loadLibraryAddr, remoteMemory, 0, NULL);
WaitForSingleObject(hThread, INFINITE);
// Проверяем через IsModuleLoadedInProcess (snapshot-based) — exit code НЕ информативен.
```

Та же причина для проверки через `Module32First/Next`, что и в DebuggerWrapper'е (kernel zero-ит RAX).

### 6.6. `RunDebugMode`

Составляется команда:
```
"<launcherDir>\DebuggerWrapper.exe" --target "<targetPath>" [--inject "<dllPath>"] [forwardedArgs...]
```

`CreateProcessW` без debug-флагов (DebuggerWrapper сам себе debugger), затем `WaitForSingleObject` и `GetExitCodeProcess` — пробрасываем код выхода как наш код выхода.

---

## 7. Сборка и зависимости

### 7.1. Структура solution

`HooksBox.sln` — три проекта:
- `HooksBox.vcxproj` → `hooksbox.dll`
- `Launcher.vcxproj` → `launcher.exe`
- `DebuggerWrapper.vcxproj` → `DebuggerWrapper.exe`

### 7.2. Версии

- Visual Studio 2022, PlatformToolset v143
- Windows SDK 10.0 (любая актуальная подверсия)
- Стандарт C++17
- Конфигурации: Debug|x64, Release|x64 (Win32 не поддерживается)

### 7.3. Препроцессорные определения (Debug|x64)

```
_DEBUG;_CONSOLE;WIN32_LEAN_AND_MEAN;NOMINMAX;_WINSOCKAPI_;WINDOWS_IGNORE_PACKING_MISMATCH;
```

`WIN32_LEAN_AND_MEAN` + `_WINSOCKAPI_` — исключают `winsock.h` из дефолтного `windows.h` includes. Иначе он конфликтует с `winsock2.h`, который тянется через `wbemidl.h` → `wmi_hooks.h`.

`NOMINMAX` — отключает `min`/`max` макросы из windows.h, иначе ломается `std::min`/`std::max`.

### 7.4. Линковка

`HooksBox.vcxproj`:
```xml
<AdditionalLibraryDirectories>$(SolutionDir)tools\MinHook\lib</AdditionalLibraryDirectories>
<AdditionalDependencies>libMinHook.x64.lib;powrprof.lib;%(AdditionalDependencies)</AdditionalDependencies>
<ModuleDefinitionFile>$(ProjectDir)hooksbox.def</ModuleDefinitionFile>
```

Кроме того, `#pragma comment(lib, "...")` в .cpp:
- `wbemuuid.lib`, `ole32.lib`, `oleaut32.lib` — в `hook_manager.cpp`
- `setupapi.lib`, `shlwapi.lib`, `psapi.lib` — в `vbox_filters.h`
- `iphlpapi.lib`, `ws2_32.lib`, `mpr.lib` — в `network_hooks.cpp`
- `shlwapi.lib` — в `services_hooks.cpp` и `wmi_hooks.cpp`

### 7.5. MinHook

Vendored как статическая `tools/MinHook/lib/libMinHook.x64.lib` + headers в `tools/MinHook/include/MinHook.h`.

Препроцессор-define `MH_STATIC` обязателен (иначе CRT думает, что MinHook DLL-импорт). Объявлен `#define MH_STATIC` непосредственно перед `#include "MinHook.h"` в `hook_manager.cpp`.

### 7.6. Особенности сборки

**Сборка через `.sln`, не через `.vcxproj`**: переменная `$(SolutionDir)` определена только при сборке через solution. При `msbuild HooksBox.vcxproj …` напрямую путь `$(SolutionDir)tools\MinHook\include` резолвится в пустоту, MinHook.h не находится.

Правильно:
```
msbuild HooksBox.sln /p:Configuration=Debug /p:Platform=x64
```

Или из VS: Build → Build Solution.

### 7.7. Выходные артефакты

В `x64\Debug\` (или `x64\Release\`):
- `hooksbox.dll` (+ `hooksbox.exp`, `hooksbox.lib` для линковки)
- `launcher.exe`
- `DebuggerWrapper.exe`

Все три должны лежать в одной директории — launcher ищет `hooksbox.dll` и `DebuggerWrapper.exe` рядом с собой.

---

## 8. Запуск и тестирование

### 8.1. Подготовка

1. Соберите solution в `Debug|x64` (или `Release|x64`).
2. Скопируйте 3 файла (`hooksbox.dll`, `launcher.exe`, `DebuggerWrapper.exe`) в одну директорию вместе с целевым `.exe` (pafish, al-khaser, или любой другой).

### 8.2. Интерактивный запуск

```
C:\Users\user\Desktop> launcher.exe
=== HooksBox Launcher ===

Target executable path (full or relative): pafish64.exe
Inject hooksbox.dll (API-hook layer)?               [Y/n]: y
Mask CPUID/RDTSC via DebuggerWrapper (instruction layer)? [y/N]: y
   target arch : x64 (64-bit)
   hooksbox.dll: x64 (64-bit)

[mode: debug] Spawning DebuggerWrapper:
   "...\DebuggerWrapper.exe" --target "pafish64.exe" --inject "...\hooksbox.dll"
[2026-05-24 12:34:56.789][INFO ][main] DebuggerWrapper starting. ...
...
* Pafish (Paranoid Fish) *
...
[-] Debuggers detection
[*] Using IsDebuggerPresent() ... OK
[*] Using BeingDebugged via PEB access ... OK
...
```

### 8.3. CLI

```powershell
.\launcher.exe --inject pafish64.exe
.\launcher.exe --debug-inject al-khaser_x64.exe
.\launcher.exe --debug-inject some.exe --cpuid --level DEBUG --log run.log
```

### 8.4. Проверочные детекторы

**Pafish** ([github.com/a0rtega/pafish](https://github.com/a0rtega/pafish)):
- Конкретно нацелен на anti-sandbox / anti-VM проверки.
- Тонкий CRT, минимальная инициализация.
- Запускать с `--inject` (без DebuggerWrapper) или `--debug-inject`.

**al-khaser** ([github.com/ayoubfaouzi/al-khaser](https://github.com/ayoubfaouzi/al-khaser)):
- Более широкий набор: anti-VM, anti-sandbox, anti-debug, anti-disasm, anti-dump.
- Тяжёлый CRT, много категорий перед debug-секцией.
- Запускать с `--debug-inject` (нужны и хуки, и DebuggerWrapper для RDTSC).

### 8.5. Ожидаемые результаты

После всех маскировок:

**Pafish** — все debug-проверки, VM-проверки, файловые/registry проверки проходят OK. Остаются `traced!` только проверки, физически нерешаемые из user-mode (вроде RDTSC-тайминга, если DebuggerWrapper не активен).

**al-khaser** — большинство [GOOD]. Остаются [BAD]:
- `Checking Local Descriptor Table location` — sldt инструкция, не имеет API.
- `Checking If Parent Process is explorer.exe` — артефакт запуска через launcher chain.
- ещё пара экзотических проверок в timing-секции.

См. раздел 9.

### 8.6. Логи для диагностики

`hooksbox.dll` пишет:
- `sandbox_evasion.log` (UTF-8 + BOM) в CWD процесса — все WMI-хуки и важные операции.
- `OutputDebugStringA/W` — все DebugPrint'ы (видны в DebugView).

`DebuggerWrapper.exe`:
- `debugger_wrapper.log` (UTF-8 + BOM) — по умолчанию.
- Параллельно — stdout (если не `--no-stdout`).
- Уровень регулируется через `--level`.

---

## 9. Ограничения и нерешённые проверки

### 9.1. `Local Descriptor Table location` (al-khaser)

`ldt_trick()` в al-khaser использует CPU-инструкцию `sldt` для чтения LDTR. На x64 user-mode эта инструкция **не вызывает trap** и нет API-обёртки.

Технически возможно патчить `sldt` в `.text` target'а аналогично тому, как DebuggerWrapper делает с CPUID. Но это **invasive patching чужого .text** с теми же рисками false-positive BP, что и CPUID (см. 5.3).

Дополнительная проблема: сам al-khaser тест **некорректен** — он сравнивает результат с магическим значением `0xdead0000`. На реальной bare-metal Windows `sldt` тоже не возвращает `0xdead0000`. То есть тест возвращает BAD даже без VM. Это баг al-khaser, не наш.

### 9.2. `IsParentExplorerExe` (al-khaser)

`IsParentExplorerExe()` проверяет, является ли родительский процесс `explorer.exe`. Получает родительский PID через `NtQueryInformationProcess(GetCurrentProcess(), ProcessBasicInformation)` → `pbi.ParentProcessId`. Затем `OpenProcess` + `GetModuleFileNameExW` для пути.

При запуске через `launcher.exe → DebuggerWrapper.exe → al-khaser`, родительский процесс — `DebuggerWrapper.exe`, не `explorer.exe`. Результат BAD.

Это **не недостаток маскировки**, а артефакт runner-цепочки. Чтобы пройти эту проверку, нужно либо:
- Запускать target напрямую из explorer'а (без launcher'а).
- Спуфить `ParentProcessId` в `ProcessBasicInformation` (нужно расширить `process_info_hooks` для этого класса) + спуфить путь в `GetModuleFileNameExW` для конкретного handle.

Не сделано, потому что низкий приоритет (узкоспецифичная проверка одного детектора).

### 9.3. CPUID маскировка off by default

См. 5.3.

### 9.4. RDTSC false positive

Скан байт `0F 31` тоже может встретить false-positive (например, внутри строки или в data-секции, если она помечена как exec). Сейчас в проекте не наблюдалось проблем, но теоретически возможно.

Защита от утечки `STATUS_BREAKPOINT` (для CPUID мы её увидели и отключили маскировку): DebuggerWrapper в случае foreign BP делает `DBG_EXCEPTION_NOT_HANDLED` и kernel дальше доставляет исключение target'у. Если target не обрабатывает — крэш.

### 9.5. Packed/unpacked payloads

Скан `.text` происходит один раз при `CREATE_PROCESS_DEBUG_EVENT`. Если target позже распакует код в новую страницу и выполнит CPUID/RDTSC оттуда — мы это не отловим.

Решение (не реализовано): хук на `VirtualProtect` с `PAGE_EXECUTE_*` для повторного сканирования.

### 9.6. CR4.TSD user-mode trap

Если target использует `CR4.TSD = 1`, то RDTSC в user-mode будет вызывать `#GP`. Маскировать это можно только из kernel-driver — out of scope.

---

## 10. История эволюции проекта

### 10.1. Этап 1: базовая маскировка (стартовая версия)

Изначальная версия проекта содержала:
- `hooksbox.dll` с хуками на: реестр (W only), файлы (W only), окна (W only), процессы (W only), сеть (Get*Adapters + WNetGetProviderNameW), firmware (SMBIOS/ACPI), Hyper-V dir, system (SetupDi + disk), power, services, WMI (полный набор vtable-хуков с fake-row injection — это была самая сложная часть).
- `Launcher.exe` — простой, только режим `inject` (CREATE_SUSPENDED + LoadLibrary).
- WMI bootstrap уже через trampoline на CoCreateInstance.

DebuggerWrapper уже существовал с базовой CPUID/RDTSC маскировкой и поддержкой `--inject`.

В этом состоянии **al-khaser** проходил основную часть VM-проверок, но pafish детектировал почти всё — потому что pafish собран без UNICODE и зовёт только A-варианты функций, которых не было.

### 10.2. Этап 2: ANSI-поддержка и debug-маскировка

Что добавлено:
- **ANSI-зеркала** во всех существующих модулях: `RegOpenKeyExA`/`RegQueryValueExA`/`RegEnumKeyExA`, `GetFileAttributesA`, `FindWindowA`/`Ex`, `Process32First/NextA`, `WNetGetProviderNameA`. Соответственно появились ANSI-предикаты в `vbox_filters` (`IsVBoxRegistryKeyA` и др.).
- Новый модуль **`debugger_hooks`** — `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, `PatchPebDebuggerFlags`.
- Новый модуль **`time_hooks`** — `GetTickCount`, `GetTickCount64` с offset на 30 минут.
- Фиксы: `MH_EnableHook(&RegEnumKeyExW)` без `!= MH_OK` (косметика), `Process32First/Next` ANSI-struct alias.

Результат: pafish стал проходить почти все проверки.

### 10.3. Этап 3: al-khaser debug + process-info

Что добавлено:
- Новый модуль **`process_info_hooks`** — `NtQueryInformationProcess` (DebugPort, DebugFlags, DebugObjectHandle) + `NtClose` + `CloseHandle` с `__try/__except`.
- В `PatchPebDebuggerFlags` добавлен патч `ProcessHeap->Flags/ForceFlags`.
- Новый модуль **`object_info_hooks`** — `NtQueryObject(ObjectAllTypesInformation)` с маскировкой `DebugObject`.

Это решило крэш `UnhandledExcepFilterTest` (через маскировку DebugPort `kernel32!UnhandledExceptionFilter` начал звать пользовательский фильтр).

Был обнаружен и исправлен баг: первая версия `IsSelfHandle` в process_info_hooks использовала `GetProcessId`, что приводило к бесконечной рекурсии. Заменено на сравнение псевдо-handle.

### 10.4. Этап 4: input + module-hide

Что добавлено:
- Новый модуль **`input_hooks`** — `GetLastInputInfo` (для синхронизации с hooked GetTickCount).
- Новый модуль **`module_hide_hooks`** — LDR-unlink + `GetMappedFileName{W,A}` + `NtQueryVirtualMemory`.
- `firmwaretable_hooks` — `kTargetMinTables` 12 → 45.

Первая итерация `GetMappedFileName*` не сработала на Win10/11 из-за psapi forwarder-цепочки. Добавлен хук на `ntdll!NtQueryVirtualMemory` — нижний уровень, через который ходят все варианты `GetMappedFileName*`.

### 10.5. Этап 5: DebuggerWrapper фиксы

Что сделано:
- **CPUID off by default**. Утечка false-positive BP крэшила цель.
- **Inject-race fix**: SuspendThread главного потока между CreateRemoteThread и EXIT_THREAD injector'а. Pafish (тонкий CRT) теперь успевает дождаться установки хуков.

### 10.6. Текущее состояние

Pafish — все проверки OK (за исключением физически нерешаемых из user-mode).
Al-khaser — большинство [GOOD]. Остаются [BAD]:
- `Local Descriptor Table location` (sldt — нет API)
- `Parent Process is explorer.exe` (runner-цепочка)
- ещё пара экзотических проверок в timing-секции

---

## 11. Полная структура исходников

```
hooxbox/
├── HooksBox.sln                          # Solution: 3 проекта
├── README.md                             # Проектный README
├── .gitignore                            # .claude/, x64/, Debug/, Release/ исключены
│
├── HooksBox/                             # → hooksbox.dll
│   ├── HooksBox.vcxproj                  # x64 DLL (DynamicLibrary)
│   ├── HooksBox.vcxproj.filters
│   ├── HooksBox.vcxproj.user
│   ├── hooksbox.def                      # Module-definition: EXPORTS InitializeMyHooks
│   ├── packages.config                   # NuGet: Microsoft.Windows.CppWinRT
│   │
│   ├── hook_dll_main.cpp                 # DllMain — entry point
│   ├── hook_dll_main.h
│   ├── hook_manager.cpp                  # Все Initialize*Hooks + WMI bootstrap (большой файл)
│   ├── hook_manager.h
│   ├── config.h                          # Таблицы паттернов VBox, FakeAcpiTable, FakeSmbiosTable
│   ├── filter_engine.cpp / .h            # (заглушка, не используется)
│   │
│   ├── filters/
│   │   ├── vbox_filters.cpp              # IsVBoxRegistryKey, IsHiddenProcess, MaskMACAddress и т.д.
│   │   └── vbox_filters.h
│   │
│   ├── hooks/                            # По одному файлу на семейство WinAPI
│   │   ├── registry_hooks.{cpp,h}        # Reg{Open,QueryValue,EnumKey}Ex{W,A}
│   │   ├── file_hooks.{cpp,h}            # GetFileAttributes{W,A}
│   │   ├── device_hooks.{cpp,h}          # CreateFile{W,A}
│   │   ├── window_hooks.{cpp,h}          # FindWindow{,Ex}{W,A}
│   │   ├── processes_hooks.{cpp,h}       # Process32{First,Next}{W,A}
│   │   ├── network_hooks.{cpp,h}         # GetAdapters{Info,Addresses}, WNetGetProviderName{W,A}
│   │   ├── firmwaretable_hooks.{cpp,h}   # SMBIOS + ACPI
│   │   ├── hypervobj_hooks.{cpp,h}       # NtQueryDirectoryObject (Hyper-V dir)
│   │   ├── system_hooks.{cpp,h}          # SetupDiEnumDeviceInfo, GetDiskFreeSpaceExW
│   │   ├── power_hooks.{cpp,h}           # GetPwrCapabilities
│   │   ├── services_hooks.{cpp,h}        # EnumServicesStatusExW
│   │   ├── wmi_hooks.{cpp,h}             # IWbemServices::ExecQuery + IEnumWbemClassObject::Next + IWbemClassObject::Get + FakeWbemObject
│   │   ├── debugger_hooks.{cpp,h}        # IsDebuggerPresent + PEB patch
│   │   ├── time_hooks.{cpp,h}            # GetTickCount{,64}
│   │   ├── input_hooks.{cpp,h}           # GetLastInputInfo
│   │   ├── process_info_hooks.{cpp,h}    # NtQueryInformationProcess + NtClose + CloseHandle
│   │   ├── object_info_hooks.{cpp,h}     # NtQueryObject (DebugObject mask)
│   │   └── module_hide_hooks.{cpp,h}     # PEB.Ldr unlink + GetMappedFileName + NtQueryVirtualMemory
│   │
│   └── utils/
│       ├── log_utils.cpp                 # DebugPrint, WriteFileLog (sandbox_evasion.log)
│       └── log_utils.h
│
├── Launcher/                             # → launcher.exe
│   ├── Launcher.vcxproj
│   ├── Launcher.vcxproj.filters
│   └── launcher.cpp                      # Все 3 режима + arch check
│
├── DebuggerWrapper/                      # → DebuggerWrapper.exe
│   ├── DebuggerWrapper.vcxproj
│   ├── DebuggerWrapper.vcxproj.filters
│   ├── README.md                         # Module-уровневая deep-dive дока
│   │
│   ├── main.cpp                          # wmain → ParseCommandLine → RunDebuggerLoop
│   ├── config.cpp / .h                   # CLI parser, Config struct
│   ├── logger.cpp / .h                   # Levelled UTF-8 logger
│   ├── debugger_core.cpp / .h            # Debug-event loop, CPUID/RDTSC dispatching
│   ├── breakpoint_manager.cpp / .h       # INT 3 install + lookup by addr
│   ├── instruction_scanner.cpp / .h      # PE walk + 0F A2 / 0F 31 byte scan
│   ├── cpuid_handler.cpp / .h            # __cpuidex + EmulateAndMaskCpuid
│   └── rdtsc_handler.cpp / .h            # VirtualTsc class (jitter via SplitMix64)
│
├── tools/
│   └── MinHook/
│       ├── include/MinHook.h             # Header API
│       └── lib/libMinHook.x64.lib        # Статическая lib
│
├── x64/                                  # build output (gitignored)
│   ├── Debug/
│   │   ├── hooksbox.dll
│   │   ├── launcher.exe
│   │   └── DebuggerWrapper.exe
│   └── Release/
│
└── .claude/                              # local settings (gitignored)
    └── settings.local.json
```

---

## 12. Глоссарий

| Термин | Значение |
|---|---|
| **PEB** | Process Environment Block. Структура в user-mode, описывающая процесс. Расположена по адресу `gs:[0x60]` на x64. |
| **TEB** | Thread Environment Block. Аналогично для потока, `gs:[0x30]` на x64. |
| **LDR** | Loader Data — `PEB->Ldr` указатель на `PEB_LDR_DATA`, описывающий загруженные модули. |
| **HV-бит** | Бит 31 регистра ECX результата CPUID с EAX=1. Установлен в 1, если процесс работает под гипервизором. |
| **MinHook** | Open-source библиотека для inline hooking (запись JMP в начало функции с trampoline для оригинала). |
| **BP** | Breakpoint. INT 3 (0xCC) в коде вызывает `EXCEPTION_BREAKPOINT`, которое отладчик может обработать. |
| **WMI** | Windows Management Instrumentation. COM-based API для запросов о системе через WQL. |
| **WQL** | WMI Query Language. Подобие SQL: `SELECT * FROM Win32_BIOS`. |
| **vtable** | Virtual Table. Массив указателей на методы C++/COM объекта, лежащий первым полем экземпляра. |
| **TSC** | Time Stamp Counter. 64-битный счётчик тактов CPU, читается инструкцией RDTSC. |
| **NtGlobalFlag** | Поле PEB по offset 0xBC (x64), хранит FLG_* флаги. При запуске под отладчиком там стоят debug-heap флаги. |
| **DLL injection** | Загрузка DLL в чужой процесс (обычно через CreateRemoteThread + LoadLibrary). |
| **Loader-lock** | `LdrpLoaderLock` — критическая секция Windows-loader. Захватывается на время DllMain. COM/LoadLibrary внутри DllMain → deadlock. |
| **Trampoline** | Маленький фрагмент кода, который восстанавливает оригинальные инструкции (которые MinHook затёр JMP'ом) и переходит обратно в оригинал. |
| **Forwarder** | DLL export, который перенаправляет вызов в другую DLL/функцию. На Win10+ многие kernel32 функции — forwarder'ы в kernelbase. |

---

*Документ описывает состояние проекта на 2026-05-24. Все приведённые имена файлов и функций соответствуют коммиту `master HEAD` репозитория `github.com/x3ucher/hooxbox`.*
