#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

void safe_function2(int size) {
    if(size <= 0 || size > INT_MAX - 1) {
        printf("Geçersiz ! Pozitif ve INT_MAX'ten küçük olmalı.\n");
        return;
    }
    
    char *buffer = (char *)malloc(size);
    
    if(buffer == NULL) {
        printf("Err!\n");
        return;
    }
    
    memset(buffer, 'A', size);
    
    printf("Size: %d\n", size);
    free(buffer);
}

int main(int argc, char *argv[]) {
    if(argc != 2) {
        printf("Usage: %s <size>\n", argv[0]);
        return 1;
    }
    
    int size = atoi(argv[1]);
    safe_function2(size);
    
    return 0;
}