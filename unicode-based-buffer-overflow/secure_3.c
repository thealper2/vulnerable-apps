#include <stdio.h>
#include <wchar.h>
#include <stdlib.h>
#include <locale.h>

void safe_function3(const wchar_t* input) {
    size_t input_len = wcslen(input);
    wchar_t* buffer = (wchar_t*)malloc((input_len + 1) * sizeof(wchar_t));
    
    if (buffer == NULL) {
        wprintf(L"Err!\n");
        return;
    }
    
    wcscpy(buffer, input);
    wprintf(L"Buffer: %ls\n", buffer);
    
    free(buffer);
}

int main() {
    setlocale(LC_ALL, "en_US.utf8");
    safe_function3(L"abc");
    safe_function3(L"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    
    return 0;
}