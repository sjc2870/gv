# gv
1. gv is used to handle vmcore which is generated when linux crashed, accordingly you can debug vmcore with gdb
2. usage: 
	1. gcc gv.c -o gv && gv your_vmcore. And gv will print the kernel image offset if ASLR enabled.
	2. gdb empty_elf your_vmcore. After enter gdb, and then run source kernel image -o $offset which was printed by gv.

# note
1. gv will modify your vmcore, so you may need to back up your vmcore(cp vmcore vmcorebak)


<img width="1074" alt="b18df1b784f6fd358864ed896e12971" src="https://github.com/sjc2870/gv/assets/51011799/4ad57c39-c623-4afd-bea6-61836bde1968">

