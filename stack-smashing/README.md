# Stack Smashing

Compile:

```bash
gcc -fno-stack-protector -z execstack -o vulnerable.out vulnerable.c
gcc -fstack-protector -o secure_1.out secure_1.c
gcc -o secure_2.out secure_2.c
gcc -fstack-protector-strong -D_FORTIFY_SOURCE=2 -O2 -Wformat -Wformat-security -o secure_3.out secure_3.c -pie -fPIE
gcc -o secure_4.out secure_4.c
gcc -D_FORTIFY_SOURCE=2 -O2 -o secure_5.out secure_5.c
```