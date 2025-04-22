#include <stdio.h>
#include <string.h>

void vulnerable_function() {
    char buffer[64];
    printf("Enter a text:");
    gets(buffer); // Vulnerable
    printf("Text: %s\n", buffer);
}

int main() {
    vulnerable_function();
    return 0;
}