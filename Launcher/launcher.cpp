#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>  // Добавьте этот заголовочный файл!
#include <iostream>
#include <string>

#pragma comment(lib, "kernel32.lib")  // Для функций ToolHelp

// Функция для создания приостановленного процесса
HANDLE CreateSuspendedProcess(const std::wstring& exePath) {
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;

    // Создаем процесс в приостановленном состоянии
    if (!CreateProcessW(
        NULL,                    // Имя модуля (NULL = из командной строки)
        (LPWSTR)exePath.c_str(), // Командная строка
        NULL,                    // Атрибуты процесса
        NULL,                    // Атрибуты потока
        FALSE,                   // Наследование дескрипторов
        CREATE_SUSPENDED,        // Флаги создания (ВАЖНО!)
        NULL,                    // Окружение
        NULL,                    // Текущий каталог
        &si,
        &pi)) {

        std::wcerr << L"Failed to create process. Error: " << GetLastError() << std::endl;
        return INVALID_HANDLE_VALUE;
    }

    CloseHandle(pi.hThread); // Дескриптор потока не нужен
    return pi.hProcess;      // Возвращаем дескриптор процесса
}

// Функция инжекта в приостановленный процесс
bool InjectIntoProcess(HANDLE hProcess, const std::wstring& dllPath) {
    // Выделяем память в целевом процессе
    size_t pathSize = (dllPath.length() + 1) * sizeof(wchar_t);
    LPVOID remoteMemory = VirtualAllocEx(hProcess, NULL, pathSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!remoteMemory) {
        std::wcerr << L"Failed to allocate memory. Error: " << GetLastError() << std::endl;
        return false;
    }

    // Пишем путь к DLL в память процесса
    if (!WriteProcessMemory(hProcess, remoteMemory, dllPath.c_str(), pathSize, NULL)) {
        std::wcerr << L"Failed to write memory. Error: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        return false;
    }

    // Получаем адрес LoadLibraryW
    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    LPVOID loadLibraryAddr = (LPVOID)GetProcAddress(kernel32, "LoadLibraryW");

    // Создаем удаленный поток для загрузки DLL
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)loadLibraryAddr, remoteMemory, 0, NULL);

    if (!hThread) {
        std::wcerr << L"Failed to create remote thread. Error: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        return false;
    }

    // Ждем завершения потока загрузки DLL
    WaitForSingleObject(hThread, INFINITE);

    // Проверяем результат
    DWORD exitCode;
    GetExitCodeThread(hThread, &exitCode);

    if (exitCode == 0) {
        std::wcerr << L"DLL failed to load (exit code 0)" << std::endl;
        CloseHandle(hThread);
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        return false;
    }

    // Очистка
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);

    return true;
}

// Упрощенная функция возобновления процесса
bool ResumeProcess(HANDLE hProcess) {
    // Более простой способ: находим поток через NtQueryInformationProcess
    // или просто используем ResumeThread если знаем handle потока

    // Альтернативный подход: находим главный поток через ToolHelp32
    DWORD processId = GetProcessId(hProcess);

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        std::wcerr << L"Failed to create snapshot. Error: " << GetLastError() << std::endl;
        return false;
    }

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);

    HANDLE hMainThread = NULL;

    if (Thread32First(hSnapshot, &te32)) {
        do {
            if (te32.th32OwnerProcessID == processId) {
                // Нашли поток нашего процесса
                hMainThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te32.th32ThreadID);
                if (hMainThread) {
                    ResumeThread(hMainThread);
                    CloseHandle(hMainThread);
                    CloseHandle(hSnapshot);
                    return true;
                }
            }
        } while (Thread32Next(hSnapshot, &te32));
    }

    CloseHandle(hSnapshot);
    return false;
}

// Еще более простой вариант: храним handle потока при создании
struct SuspendedProcessInfo {
    HANDLE hProcess;
    HANDLE hMainThread;
};

SuspendedProcessInfo CreateSuspendedProcessWithThread(const std::wstring& exePath) {
    SuspendedProcessInfo info = { INVALID_HANDLE_VALUE, INVALID_HANDLE_VALUE };

    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;

    if (CreateProcessW(
        NULL,
        (LPWSTR)exePath.c_str(),
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED,
        NULL,
        NULL,
        &si,
        &pi)) {

        info.hProcess = pi.hProcess;
        info.hMainThread = pi.hThread; // Сохраняем handle потока
    }

    return info;
}

int main(int argc, char* argv[]) {
    std::wcout << L"=== Launcher with Early Injection ===\n" << std::endl;

    // Пути к файлам
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    std::wstring launcherDir(exePath);
    size_t pos = launcherDir.find_last_of(L"\\/");
    launcherDir = launcherDir.substr(0, pos + 1);

    // std::wstring testAppPath = launcherDir + L"TestApp.exe";
    std::wstring dllPath = launcherDir + L"hooksbox.dll";
    std::wstring testAppPath;
    std::wcin >> testAppPath;

    // Проверяем существование файлов
    if (GetFileAttributesW(testAppPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        std::wcerr << testAppPath << L" not found!" << std::endl;
        std::wcerr << L"Looking in: " << testAppPath << std::endl;
        return 1;
    }

    if (GetFileAttributesW(dllPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        std::wcerr << L"hooksbox.dll not found!" << std::endl;
        std::wcerr << L"Looking in: " << dllPath << std::endl;
        return 1;
    }

    std::wcout << L"1. Creating suspended process: " << testAppPath << std::endl;

    // Используем улучшенную функцию, которая сохраняет handle потока
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;

    if (!CreateProcessW(
        NULL,
        (LPWSTR)testAppPath.c_str(),
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED,
        NULL,
        NULL,
        &si,
        &pi)) {

        std::wcerr << L"Failed to create suspended process. Error: " << GetLastError() << std::endl;
        return 1;
    }

    DWORD pid = pi.dwProcessId;
    HANDLE hProcess = pi.hProcess;
    HANDLE hMainThread = pi.hThread;

    std::wcout << L"   Process created. PID: " << pid << std::endl;

    std::wcout << L"\n2. Injecting DLL: " << dllPath << std::endl;
    if (!InjectIntoProcess(hProcess, dllPath)) {
        std::wcerr << L"   Injection failed!" << std::endl;
        TerminateProcess(hProcess, 1);
        CloseHandle(hMainThread);
        CloseHandle(hProcess);
        return 1;
    }

    std::wcout << L"   DLL injected successfully!" << std::endl;

    std::wcout << L"\n3. Resuming process..." << std::endl;

    // Возобновляем главный поток
    if (ResumeThread(hMainThread) == (DWORD)-1) {
        std::wcerr << L"   Failed to resume thread. Error: " << GetLastError() << std::endl;
    }
    else {
        std::wcout << L"   Process resumed successfully!" << std::endl;
    }

    // Ждем немного, чтобы процесс успел инициализироваться
    Sleep(100);

    std::wcout << L"\n4. Process is now running with injected DLL!" << std::endl;
    std::wcout << L"   PID: " << pid << std::endl;
    std::wcout << L"   You can now interact with TestApp.exe" << std::endl;

    // Закрываем дескрипторы (сам процесс продолжит работать)
    CloseHandle(hMainThread);
    CloseHandle(hProcess);

    std::wcout << L"\nPress Enter to close launcher...";
    std::cin.get();

    return 0;
}