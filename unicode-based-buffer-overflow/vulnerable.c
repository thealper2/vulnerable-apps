#include <stdio.h>
#include <string.h>
#include <wchar.h>

void vulnerable_function(const wchar_t* input) {
    wchar_t buffer[10];
    wcscpy(buffer, input);
    wprintf(L"Buffer: %ls\n", buffer);
}

int main() {
    vulnerable_function(L"abc");
    vulnerable_function(L"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    return 0;
}