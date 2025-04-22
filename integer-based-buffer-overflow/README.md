# Integer-based Buffer Overflow

Compile:

```bash
gcc -o vulnerable.out vulnerable.c -fno-stack-protector -z execstack
gcc -o secure_1.out secure_1.c
gcc -o secure_2.out secure_2.c
```