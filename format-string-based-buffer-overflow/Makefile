# Makefile

# Default goal
.DEFAULT_GOAL := run

# Run app
run:
	gcc -fno-stack-protector -z execstack -no-pie -o vulnerable.out vulnerable.c
	gcc -fstack-protector-strong -pie -fPIE -D_FORTIFY_SOURCE=2 -O2 -o secure_1.out secure_1.c
	gcc -fstack-protector -o secure_2.out secure_2.c

# Remove cache
clean:
	find . -type f -name "*.out" -delete

.PHONY: run clean