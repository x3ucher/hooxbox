#include "log_utils.h"

void DebugPrint(const char* text) {
    OutputDebugStringA(text);
    OutputDebugStringA("\n");
}

void DebugPrintW(const wchar_t* text) {
    OutputDebugStringW(text);
    OutputDebugStringW(L"\n");
}