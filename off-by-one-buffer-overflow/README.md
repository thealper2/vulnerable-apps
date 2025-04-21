# Off-by-One Buffer Overflow

Compile:

```bash
gcc vulnerable.c -o vulnerable && ./vulnerable.out AAAAAAAAAAA
gcc secure.c -o secure && ./secure.out AAAAAAAAAAA

gcc -fstack-protector -z execstack -D_FORTIFY_SOURCE=2 -O2 secure_code.c -o secure_program.out
```