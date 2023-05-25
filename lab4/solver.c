#include <stdio.h>

typedef int (*printf_ptr_t)(const char *format, ...);

void solver(printf_ptr_t fptr) {
	char msg[8] = {};
	for(int i = 0; i <= 0x18; i += 8) {
		// leak the information of msg, canary, rbp, return addr of solver
		// fptr("%02x: %016lx\n", i, *(unsigned long *)&msg[i]);
		fptr("%016lx\n", *(unsigned long *)&msg[i]);
	}
}

int main() {
	char fmt[16] = "** main = %p\n";
	printf(fmt, main);
	solver(printf);
	return 0;
}
