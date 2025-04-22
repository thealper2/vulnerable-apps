#include <stdio.h>
#include <wchar.h>
#include <locale.h>

void safe_function1(const wchar_t* input) {
    wchar_t buffer[10];
    size_t max_len = sizeof(buffer)/sizeof(wchar_t) - 1;
    
    if (wcslen(input) > max_len) {
        wprintf(L"Err, max_len = %zu\n", max_len);
        return;
    }
    
    wcsncpy(buffer, input, max_len);
    buffer[max_len] = L'\0';
    wprintf(L"Buffer: %ls\n", buffer);
}

int main() {
    setlocale(LC_ALL, "en_US.utf8");
    
    safe_function1(L"abc");
    
    safe_function1(L"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    
    return 0;
}