#include <stdio.h>
#include <string.h>

// Fortify Source
void safe_function(char *input) {
    char buffer[16];
    strcpy(buffer, input);
    printf("Buffer içeriği: %s\n", buffer);
}

int main(int argc, char *argv[]) {
    if(argc != 2) {
        printf("Kullanım: %s <input_string>\n", argv[0]);
        return 1;
    }
    safe_function(argv[1]);
    return 0;
}