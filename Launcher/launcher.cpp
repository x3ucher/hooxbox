#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h> 
#include <iostream>
#include <string>

#pragma comment(lib, "kernel32.lib")

HANDLE CreateSuspendedProcess(const std::wstring& exePath) {
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;

    if (!CreateProcessW(
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

        std::wcerr << L"Failed to create process. Error: " << GetLastError() << std::endl;
        return INVALID_HANDLE_VALUE;
    }

    CloseHandle(pi.hThread); 
    return pi.hProcess;     
}

bool InjectIntoProcess(HANDLE hProcess, const std::wstring& dllPath) {
    size_t pathSize = (dllPath.length() + 1) * sizeof(wchar_t);
    LPVOID remoteMemory = VirtualAllocEx(hProcess, NULL, pathSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!remoteMemory) {
        std::wcerr << L"Failed to allocate memory. Error: " << GetLastError() << std::endl;
        return false;
    }

    if (!WriteProcessMemory(hProcess, remoteMemory, dllPath.c_str(), pathSize, NULL)) {
        std::wcerr << L"Failed to write memory. Error: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        return false;
    }

    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    LPVOID loadLibraryAddr = (LPVOID)GetProcAddress(kernel32, "LoadLibraryW");

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)loadLibraryAddr, remoteMemory, 0, NULL);

    if (!hThread) {
        std::wcerr << L"Failed to create remote thread. Error: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        return false;
    }

    WaitForSingleObject(hThread, INFINITE);

    DWORD exitCode;
    GetExitCodeThread(hThread, &exitCode);

    if (exitCode == 0) {
        std::wcerr << L"DLL failed to load (exit code 0)" << std::endl;
        CloseHandle(hThread);
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        return false;
    }

    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);

    return true;
}

bool ResumeProcess(HANDLE hProcess) {
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
        info.hMainThread = pi.hThread; 
    }

    return info;
}

int main(int argc, char* argv[]) {
    std::wcout << L"=== Launcher with Early Injection ===\n" << std::endl;

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

    if (ResumeThread(hMainThread) == (DWORD)-1) {
        std::wcerr << L"   Failed to resume thread. Error: " << GetLastError() << std::endl;
    }
    else {
        std::wcout << L"   Process resumed successfully!" << std::endl;
    }

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