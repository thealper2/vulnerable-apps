# Makefile

# Default goal
.DEFAULT_GOAL := run

# Run app
run:
	gcc -fno-stack-protector -z execstack vulnerable.c -o vulnerable.out
	gcc -fstack-protector-strong -D_FORTIFY_SOURCE=2 -O2 secure_1.c -o secure_1.out

# Remove cache
clean:
	find . -type f -name "*.out" -delete

.PHONY: run clean