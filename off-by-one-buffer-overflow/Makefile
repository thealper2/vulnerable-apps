# Makefile

# Default goal
.DEFAULT_GOAL := run

# Run app
run:
	gcc vulnerable.c -o vulnerable.out
	gcc secure.c -o secure.out
	gcc -fstack-protector -z execstack -D_FORTIFY_SOURCE=2 -O2 secure.c -o secure_program.out

# Remove cache
clean:
	find . -type f -name "*.out" -delete

.PHONY: run clean