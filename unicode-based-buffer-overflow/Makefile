# Makefile

# Default goal
.DEFAULT_GOAL := run

# Run app
run:
	gcc -o vulnerable.out vulnerable.c
	gcc -o secure_1.out secure_1.c
	gcc -o secure_2.out secure_2.c -std=c11
	gcc -o secure_3.out secure_3.c

# Remove cache
clean:
	find . -type f -name "*.out" -delete

.PHONY: run clean