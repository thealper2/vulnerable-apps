#include <stdio.h>

void secure_function1() {
    char buffer[100];
    printf("Enter a text: ");
    
    if (fgets(buffer, sizeof(buffer), stdin) == NULL) {
        printf("Err!\n");
        return;
    }

    printf("%s", buffer);
}

int main() {
    secure_function1();
    return 0;
}