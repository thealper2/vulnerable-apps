#define __STDC_WANT_LIB_EXT1__ 1
#include <stdio.h>
#include <wchar.h>
#include <locale.h>

void safe_function2(const wchar_t* input) {
    wchar_t buffer[10];
    
    if (wcscpy_s(buffer, sizeof(buffer)/sizeof(wchar_t), input) != 0) {
        wprintf(L"Err!\n");
        return;
    }
    
    wprintf(L"Buffer: %ls\n", buffer);
}

int main() {
    setlocale(LC_ALL, "en_US.utf8");
    
    safe_function2(L"abc");
    
    safe_function2(L"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    
    return 0;
}