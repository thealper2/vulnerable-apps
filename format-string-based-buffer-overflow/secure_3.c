#include <stdio.h>
#include <string.h>

void secure_function3() {
    char buffer[100];
    char output[200];
    
    printf("Enter a text: ");
    
    if (fgets(buffer, sizeof(buffer), stdin) == NULL) {
        printf("Err!\n");
        return;
    }
    
    buffer[strcspn(buffer, "\n")] = '\0';
    
    snprintf(output, sizeof(output), "%s", buffer);
    printf("%s\n", output);
}

int main() {
    secure_function3();
    return 0;
}