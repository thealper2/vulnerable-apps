#include <stdio.h>

void vulnerable_function() {
    char buffer[100];
    printf("Enter a text: ");
    gets(buffer); 
    
    printf(buffer);
    
    printf("\n");
}

int main() {
    vulnerable_function();
    return 0;
}