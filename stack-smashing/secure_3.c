// protected_full.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void safe_function(const char *input) {
    size_t input_len = strlen(input);
    char *buffer = malloc(input_len + 1);
    if(buffer == NULL) {
        printf("Err!\n");
        exit(1);
    }
    
    memcpy(buffer, input, input_len);
    buffer[input_len] = '\0';
    
    printf("Buffer: %s\n", buffer);
    
    free(buffer);
}

int main(int argc, char *argv[]) {
    if(argc != 2) {
        printf("Usage: %s <input_string>\n", argv[0]);
        return 1;
    }
    safe_function(argv[1]);
    return 0;
}