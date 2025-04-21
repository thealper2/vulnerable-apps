#include <stdio.h>
#include <string.h>

void secure_function(char *input) {
    char buffer[10];
    // Fix
    for (int i = 0; i < 10 && input[i] != '\0'; i++) {
        buffer[i] = input[i];
    }
    buffer[9] = '\0'; // Null-terminator
    printf("Buffer: %s\n", buffer);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <input_string>\n", argv[0]);
        return 1;
    }

    // Check input length
    if (strlen(argv[1]) > 9) {
        printf("Error: Entry is too long.\n");
        return 1;
    }

    secure_function(argv[1]);
    return 0;
}