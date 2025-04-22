# Stack-based Buffer Overflow


Compile:

```bash
gcc -fno-stack-protector -z execstack vulnerable.c -o vulnerable.out
gcc -fstack-protector-strong -D_FORTIFY_SOURCE=2 -O2 secure_1.c -o secure_1.out

echo 2 | sudo tee /proc/sys/kernel/randomize_va_space
gcc -z noexecstack secure_2.c -o secure_2.out
```