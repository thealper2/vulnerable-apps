#include <stdio.h>
#include <string.h>

void vulnerable_function(char *input) {
    char buffer[16];
    strcpy(buffer, input);
    printf("Buffer: %s\n", buffer);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <input_string>\n", argv[0]);
        return 1;
    }

    vulnerable_function(argv[1]);
    return 0;
}