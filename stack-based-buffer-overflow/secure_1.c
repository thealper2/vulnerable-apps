#include <stdio.h>
#include <string.h>

void safe_function_fgets() {
    char buffer[64];
    printf("Enter a text:");
    fgets(buffer, sizeof(buffer), stdin);
    buffer[strcspn(buffer, "\n")] = '\0';
    printf("Text: %s\n", buffer);
}

int main() {
    safe_function_fgets();
    return 0;   
}