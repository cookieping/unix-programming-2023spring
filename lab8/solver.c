#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>

void errquit(const char *msg) {
	perror(msg);
	exit(-1);
}

int magic_cnt = 0;
void generateMagicArrays(char all_magic[][10], char magic[], int index) {
	if (index == 10) {
		for (int i = 0; i < 10; i++) {
			all_magic[magic_cnt][i] = magic[i];
		}
		magic_cnt++;
		return;
	}
	// recursive
	magic[index] = 0;
	generateMagicArrays(all_magic, magic, index + 1);
	magic[index] = 1;
	generateMagicArrays(all_magic, magic, index + 1);
}

int main(int argc, char *argv[]) {
	char all_magic[1024][10] = { 0 };
	char my_magic[10] = { 0 };
  	generateMagicArrays(all_magic, my_magic, 0);

	int is_bingo = 0;

	for(int cnt = 0; cnt < 1024; cnt++) {
		pid_t child;
		int cc_count = 0;
		if((child = fork()) < 0) errquit("fork");
		if(child == 0) {
			if(ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) errquit("ptrace@child");
			execvp(argv[1], argv+1);
			errquit("execvp");
		} else {
			int wait_status;
			if(waitpid(child, &wait_status, 0) < 0) errquit("waitpid");
			ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL);

			while (WIFSTOPPED(wait_status)) {
				long ret;
				unsigned long long rip, rax;
				struct user_regs_struct regs;
				unsigned char *ptr = (unsigned char *) &ret;
				cc_count++;

				if(cc_count == 3) {  // number 2: changing the content of magic
					// get rip and rax
					if(ptrace(PTRACE_GETREGS, child, 0, &regs) == 0) {
						rip = regs.rip;
						rax = regs.rax;
					}
					// read rip
					ret = ptrace(PTRACE_PEEKTEXT, child, rip, 0);
					// fprintf(stderr, "0x%llx: %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x\n",
					// 		rip,
					// 		ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5], ptr[6], ptr[7]);
					
					// read rax
					// ret = ptrace(PTRACE_PEEKTEXT, child, rax, 0);
					// fprintf(stderr, "rax content: %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x\n",
					// 		ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5], ptr[6], ptr[7]);
					ret = ptrace(PTRACE_PEEKTEXT, child, rax + 8, 0);
					// fprintf(stderr, "rax content: %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x %2.2x\n\n",
					// 		ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5], ptr[6], ptr[7]);
					unsigned char back_up[8];
					for(int k = 0; k < 8; k++) back_up[k] = ptr[k];
					
					// build the code array
					unsigned char code[16] = {};
					for(int k = 0; k < 10; k++) {
						if(all_magic[cnt][k] == 0) code[k] = 0x30;
						if(all_magic[cnt][k] == 1) code[k] = 0x31;
					}
					for(int k = 2; k < 8; k++) {
						code[8 + k] = back_up[k];
					}
					// change the content of magic
					unsigned long *lcode = (unsigned long*) code;
					if(ptrace(PTRACE_POKETEXT, child, rax, *lcode) != 0) errquit("poketext");
					lcode = (unsigned long*)(code + 8);
					if(ptrace(PTRACE_POKETEXT, child, rax + 8, *lcode) != 0) errquit("poketext");
					
					ptrace(PTRACE_SINGLESTEP, child, 0, 0);
					if(waitpid(child, &wait_status, 0) < 0) errquit("waitpid");

				} else if(cc_count == 6) {  // number 5: get the return value of oracle_get_flag
					if(ptrace(PTRACE_GETREGS, child, 0, &regs) == 0) {
						rax = regs.rax;
					}
					if(rax == 0) is_bingo = 1;
				} else if(cc_count == 7) {  // number 6: check whether it is bingo!
					if(is_bingo) exit(0);
				}

				if(ptrace(PTRACE_CONT, child, 0, 0) < 0) errquit("ptrace@parent");
				if(waitpid(child, &wait_status, 0) < 0) errquit("waitpid");
			}
		}
	}
    return 0;
}