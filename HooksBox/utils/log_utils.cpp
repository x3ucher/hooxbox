#include "log_utils.h"
#include <iostream>

void DebugPrint(const char* text) {
    OutputDebugStringA(text);
    OutputDebugStringA("\n");
    //std::cout << text << std::endl;
}

void DebugPrintW(const wchar_t* text) {
    OutputDebugStringW(text);
    OutputDebugStringW(L"\n");
    //std::cout << text << std::endl;
}

bool EqualsCaseInsensitive(const std::wstring& str1, const std::wstring& str2) {
    if (str1.length() != str2.length())
        return false;

    for (size_t i = 0; i < str1.length(); ++i)
    {
        if (std::towlower(str1[i]) != std::towlower(str2[i]))
            return false;
    }
    return true;
}