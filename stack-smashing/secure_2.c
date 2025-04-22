#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ASLR + NX
void safe_function(char *input) {
    char *buffer = malloc(16);
    if (buffer == NULL) {
        printf("Err!\n");
        exit(1);
    }

    strncpy(buffer, input, 15);
    buffer[15] = '\0';
    printf("Buffer: %s\n", buffer);

    free(buffer);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <input_string>\n", argv[0]);
        return 1;
    }

    safe_function(argv[1]);
    return 0;
}