#include <stdio.h>
#include <string.h>
#include <stdbool.h>

bool is_valid_format(const char *str) {
    const char *p = str;
    while (*p) {
        if (*p == '%') {
            if (*(p+1) == '%') {
                p += 2;
                continue;
            }
            return false;
        }
        p++;
    }
    return true;
}

void secure_function2() {
    char buffer[100];
    printf("Enter a text: ");
    
    if (fgets(buffer, sizeof(buffer), stdin) == NULL) {
        printf("Err!\n");
        return;
    }
    
    buffer[strcspn(buffer, "\n")] = '\0';
    
    if (is_valid_format(buffer)) {
        printf("%s\n", buffer);
    } else {
        printf("Err!\n");
    }
}

int main() {
    secure_function2();
    return 0;
}