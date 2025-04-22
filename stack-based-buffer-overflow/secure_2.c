#include <stdio.h>
#include <string.h>

void safe_function_protections() {
    char buffer[64];
    printf("Enter a text:");

    if (fgets(buffer, sizeof(buffer), stdin) == NULL) {
        printf("Err!\n");
        return;
    }

    if (strlen(buffer) >= sizeof(buffer)) {
        printf("Err!\n");
        return;
    }

    printf("Text: %s\n", buffer);
}

int main() {
    safe_function_protections();
    return 0;
}