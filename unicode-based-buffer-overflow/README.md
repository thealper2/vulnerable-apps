# Unicode-based Buffer Overflow

Compile:

```bash
gcc -o vulnerable.out vulnerable.c 
gcc -o secure_1.out secure_1.c
gcc -o secure_2.out secure_2.c
gcc -o secure_3.out secure_3.c -std=c11 -Wall -Wextra -Werror -fstack-protector-strong -D_FORTIFY_SOURCE=2 -O2
```