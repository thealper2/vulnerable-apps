#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void vulnerable_function(int size) {
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
    vulnerable_function(size);
    
    return 0;
}