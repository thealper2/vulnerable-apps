#include <stdio.h>
#include <string.h>
#include <stdbool.h>

bool is_input_safe(const char* input, size_t max_len) {
    size_t len = strlen(input);
    if (len >= max_len) {
        return false;
    }

    for (size_t i = 0; i < len; i++) {
        if (input[i] < 32 || input[i] > 126) {
            return false;
        } 
    }
    
    return true;
}

void safe_function_with_checks() {
    char buffer[64];
    printf("Enter a text:");

    if (fgets(buffer, sizeof(buffer), stdin) == NULL) {
        printf("Err!\n");
        return;
    }

    buffer[strcspn(buffer, "\n")] = '\0';

    if (!is_input_safe(buffer, sizeof(buffer) - 1)) {
        printf("Err!\n");
        return;
    }

    printf("Text: %s\n", buffer);
}

int main() {
    safe_function_with_checks();
    return 0;
}