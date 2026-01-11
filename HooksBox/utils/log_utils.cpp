#include "log_utils.h"
//#include <iostream>

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