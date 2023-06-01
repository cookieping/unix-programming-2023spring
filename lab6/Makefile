# yasm -f elf64 -DYASM -D__x86_64__ -DIPC merge_sort.asm -o merge_sort.o
# nasm -f elf64 merge_sort.asm -o merge_sort.o

all: 
	yasm -f elf64 -DYASM -D__x86_64__ -DIPC quick_sort.asm -o quick_sort.o
	ar rcs libquick_sort.a quick_sort.o
	gcc -g call_quick_sort.c -L. -lquick_sort -o call_quick_sort
