#define __STDC_WANT_LIB_EXT1__ 1
#include <stdio.h>
#include <string.h>

// Safe C Lib
void safe_function(char *input) {
    char buffer[16];
    
    if(strcpy_s(buffer, sizeof(buffer), input) != 0) {
        printf("Err!\n");
        return;
    }
    
    printf("Buffer: %s\n", buffer);
}

int main(int argc, char *argv[]) {
    if(argc != 2) {
        printf("Usage: %s <input_string>\n", argv[0]);
        return 1;
    }
    safe_function(argv[1]);
    return 0;
}