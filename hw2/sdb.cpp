#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <capstone/capstone.h>
#include <libgen.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <filesystem>
#include <algorithm>
using namespace std;

typedef struct proc_info_s {
	unsigned long base_addr;
	unsigned long text_sec_start;
	unsigned long text_sec_end;
	unsigned long text_sec_size;
} proc_info_t;

// breakpoint information
typedef struct bp_s {
    unsigned long addr;
    unsigned long old_code;
	bool is_active;  // if the breakpoint is hit by someone, it will become inactive (be eliminated)
} bp_t;

// snapshot information
typedef struct snapshot_s {
	unsigned long start_addr;
	unsigned long end_addr;
	vector<unsigned long> content;  // need to use unsigned long!
} snapshot_t;

char* code = NULL;  // need to use global variable! Otherwise it will segmentation fault qwq

void errquit(const char *msg) {
	perror(msg);
	exit(-1);
}

vector<string> get_command(string str) {
	string pattern = " ";
	vector<string> ans;
	size_t begin, end;
	end = str.find(pattern);
	begin = 0;
	while(end != string::npos) {
		if(end - begin != 0) ans.push_back(str.substr(begin, end - begin));
		begin = end + pattern.size();
		end = str.find(pattern, begin);
	}
    if (begin != str.length()) {
        ans.push_back(str.substr(begin));
    }
    return ans;        
}

void store_elf_info(string exec_path) {
	string file_name = exec_path.substr(2);
    string cmd = "readelf -S " + file_name + " > elf_result.txt";
    if(system(cmd.c_str()) == -1) exit(EXIT_FAILURE);
}

void get_elf_info(pid_t child, char* file_path, proc_info_t& proc_info) {
	// get base address from /proc/[pid]/maps
	char file_name[128];
	snprintf(file_name, sizeof(file_name), "/proc/%u/maps", child);
	ifstream proc_file(file_name);
	if (proc_file.is_open()) {
		string line;
		getline(proc_file, line);
		
		string delimeter = "-";
		size_t pos = line.find(delimeter);
		proc_info.base_addr = strtol(line.substr(0, pos).c_str(), NULL, 16);
		// cout << "* base_addr: " << hex << proc_info.base_addr << dec << endl;
    	proc_file.close();
	}
	// get .text info in the elf file with readelf
	store_elf_info(file_path);
	ifstream elf_file("elf_result.txt");
	if(elf_file.is_open()) {
		string line;
		while(getline(elf_file, line)) {
			if(line.find(".text") != string::npos) {
				stringstream ss(line);
				string tmp, tmp_str;
				ss >> tmp >> tmp >> tmp >> tmp >> tmp_str >> tmp;
				proc_info.text_sec_start = strtol(tmp_str.c_str(), NULL, 16);

				// next line
				elf_file >> tmp_str;
				proc_info.text_sec_size = strtol(tmp_str.c_str(), NULL, 16);
				proc_info.text_sec_end = proc_info.text_sec_start + proc_info.text_sec_size;
				break;
			}
		}
		elf_file.close();
		// cout << "* elf text info: start = " << hex << proc_info.text_sec_start << ", size = " << proc_info.text_sec_size << dec << endl;
	}
}

int get_code(char* file_path) {
	FILE* fp = fopen(file_path, "rb");
    if (fp == NULL) errquit("fopen@get_code");
    fseek(fp, 0, SEEK_END);
    int size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if((code = (char*)malloc(sizeof(char) * size)) == NULL) {
		fclose(fp);
		errquit("malloc@get_close");
	}
    fread(code, sizeof(char), size, fp);
    fclose(fp);
    return size;
}


void disassemble(pid_t child, struct user_regs_struct& regs, proc_info_t& proc_info, int& code_size) {
	if(ptrace(PTRACE_GETREGS, child, 0, &regs) != 0) errquit("ptrace_getregs");
	unsigned long rip = regs.rip;

	unsigned long curr_offset = rip - proc_info.base_addr;
	char* curr_code = code + curr_offset;
	// cout << "code: " << &code << endl;
	// cout << "rip: " << hex << rip << dec << endl;
	// cout << "curr_offset: " << hex << curr_offset << dec << endl;

	unsigned long addr_lower = proc_info.text_sec_start;
	unsigned long addr_upper = proc_info.text_sec_end;
	// cout << "addr_lower: " << hex << addr_lower << ", addr_upper: " << addr_upper << dec << endl;

	// disassemble the code with capstone
	csh handle;
	cs_insn *insn;
	size_t count;
	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) errquit("cs_open@disassemble");
	count = cs_disasm(handle, (uint8_t*)curr_code, code_size, rip, 5, &insn);

	if(count > 0) {
		for(int i = 0; i < (int)count; i++) {
			// check whether the instruction is out of the range of the text section in ELF
			if((insn[i].address < addr_lower) || (insn[i].address >= addr_upper)) {
				fprintf(stderr, "** the address is out of the range of the text section.\n");
				break;
			}
			// get raw instructions
			char bytes[128] = "";
			for(int j = 0; j < insn[i].size; j++) {
				snprintf(&bytes[j*3], 4, "%2.2x ", insn[i].bytes[j]);
			}
			fprintf(stderr, "\t%lx: %-32s\t%-10s%s\n", insn[i].address, bytes, insn[i].mnemonic, insn[i].op_str);
		}
		cs_free(insn, count);
	} else {
		fprintf(stderr, "ERROR: Failed to disassemble given code!\n");
	}
	cs_close(&handle);
}

void check_breakpoint(pid_t child, vector<bp_t>& breakpoints) {
	struct user_regs_struct regs;
	if(ptrace(PTRACE_GETREGS, child, 0, &regs) != 0) errquit("ptrace_getregs");

	for(int i = 0; i < (int)breakpoints.size(); i++) {
		// restore breakpoints after running them
		if((!breakpoints[i].is_active) && breakpoints[i].addr != regs.rip) {
			unsigned long ret;
			ret = ptrace(PTRACE_PEEKTEXT, child, breakpoints[i].addr, 0);
			if(ptrace(PTRACE_POKETEXT, child, breakpoints[i].addr, ((ret & (~0xff)) | 0xcc)) != 0) errquit("ptrace_poketext");
			breakpoints[i].is_active = true;
		}
	}
}

void check_status(pid_t child, int& wait_status, vector<bp_t>& breakpoints, string cmd) {
	if(waitpid(child, &wait_status, 0) < 0) errquit("waitpid");
	if(WIFEXITED(wait_status)) {
		// fprintf(stderr, "* in WIFEXITED\n");
		fprintf(stderr, "** the target program terminated.\n");
		exit(0);
    }
	struct user_regs_struct regs;
	if(ptrace(PTRACE_GETREGS, child, 0, &regs) != 0) errquit("ptrace_getregs");

	// to avoid print the same instruction when si to a breakpoint
	if(cmd == "si") {
		bool has_breakpoint = false;
		for(int i = 0; i < (int)breakpoints.size(); i++) {
			if(regs.rip == breakpoints[i].addr) {
				if((ptrace(PTRACE_SINGLESTEP, child, 0, 0)) < 0) errquit("ptrace_singlestep");
				has_breakpoint = true;
				break;
			}
		}
		if(has_breakpoint) {
			if(waitpid(child, &wait_status, 0) < 0) errquit("waitpid");
			if(ptrace(PTRACE_GETREGS, child, 0, &regs) != 0) errquit("ptrace_getregs");
		}
	}

	if(WIFSTOPPED(wait_status)) {
		// fprintf(stderr, "* in WIFSTOPPED\n");
		// check breakpoint address
		for(int i = 0; i < (int)breakpoints.size(); i++) {
			if(regs.rip - 1 == breakpoints[i].addr) {
			// if(regs.rip == breakpoints[i].addr) {
				fprintf(stderr, "** hit a breakpoint 0x%lx\n", breakpoints[i].addr);
				// restore breakpoint (** avoid changing other breakpoints!)
				unsigned long curr_code = ptrace(PTRACE_PEEKTEXT, child, breakpoints[i].addr, 0);
				unsigned long new_code = (breakpoints[i].old_code & 0x00000000000000ff) | (curr_code & ~(0xff));

				if(ptrace(PTRACE_POKETEXT, child, breakpoints[i].addr, new_code) != 0) errquit("ptrace_poketext");
				breakpoints[i].is_active = false;
				
				// set registers
				regs.rip = regs.rip - 1;
				if(ptrace(PTRACE_SETREGS, child, 0, &regs) != 0) errquit("ptrace_setregs");
				break;
			}
		}
	}
}

void cmd_si(pid_t child) {
	if((ptrace(PTRACE_SINGLESTEP, child, 0, 0)) < 0) errquit("ptrace_singlestep");
}

void cmd_cont(pid_t child) {
	if(ptrace(PTRACE_CONT, child, 0, 0) < 0) errquit("ptrace_cont");
}

void cmd_break(pid_t child, unsigned long target, vector<bp_t>& breakpoints) {
	// 1. get original text to back up the code
	unsigned long ret;
	ret = ptrace(PTRACE_PEEKTEXT, child, target, 0);

	// 2. set break point
	if(ptrace(PTRACE_POKETEXT, child, target, ((ret & (~0xff)) | 0xcc)) != 0) errquit("ptrace_poketext");
	fprintf(stderr, "** set a breakpoint at 0x%lx\n", target);
	bp_t curr_bp = {target, ret, true};  // addr, old_code
	breakpoints.push_back(curr_bp);
}

void cmd_anchor(pid_t child, struct user_regs_struct& regs_snapshot, vector<snapshot_t>& memory_snapshot, unsigned long& anchor_addr, bool& has_anchor, char* file_name) {
	// snapshot registers
	if(ptrace(PTRACE_GETREGS, child, 0, &regs_snapshot) != 0) errquit("ptrace_getregs");
	
	// snapshot the process memory
	memory_snapshot.clear();
	char proc_name[128];
	snprintf(proc_name, sizeof(proc_name), "/proc/%u/maps", child);
	ifstream proc_file(proc_name);
	if (proc_file.is_open()) {
		string addr_range, permission, name, tmp;
		while(proc_file >> addr_range >> permission >> tmp >> tmp >> tmp >> name) {
			// cout << "* name: " << name << endl;
			size_t found_w = permission.find("w");
			size_t found_name = name.find(((string)file_name).substr(2));
			size_t found_stack = name.find("stack");
			size_t found_heap = name.find("heap");
			bool correct_name = ((found_name != string::npos) || (found_stack != string::npos) || (found_heap != string::npos));

			if ((found_w != string::npos) && correct_name) {  // only snapshot writable part and [stack] and [heap]
				// cout << "* get: " << addr_range << " " << name << endl;
				// 1. get the address range
				snapshot_t curr_snapshot;
				string delimeter = "-";
				size_t pos = addr_range.find(delimeter);
				if(pos != string::npos) {
					curr_snapshot.start_addr = strtol(addr_range.substr(0, pos).c_str(), NULL, 16);
					addr_range.erase(0, pos + delimeter.length());
				}
				curr_snapshot.end_addr = strtol(addr_range.c_str(), NULL, 16);
				// cout << "* start_addr: " << hex << curr_snapshot.start_addr << ", end_addr: " << curr_snapshot.end_addr << dec << endl;

				// 2. get the content with peektext
				curr_snapshot.content.clear();
				for(unsigned long curr_addr = curr_snapshot.start_addr; curr_addr < curr_snapshot.end_addr; curr_addr += 8) {
					unsigned long curr_content = ptrace(PTRACE_PEEKTEXT, child, curr_addr, 0);
					curr_snapshot.content.push_back(curr_content);
				}
				memory_snapshot.push_back(curr_snapshot);
				// cout << "\n*** memory snapshot ***\naddr start: " << hex << curr_snapshot.start_addr << endl;
				// cout << "content:\n" << curr_snapshot.content << "\n***\n";
			}
		}
    	proc_file.close();
	}

	// store anchor information
	fprintf(stderr, "** dropped an anchor\n");
	has_anchor = true;
	anchor_addr = regs_snapshot.rip;
	// cout << "* end of anchor\n";
}

void cmd_timetravel(pid_t child, struct user_regs_struct& regs_snapshot, vector<snapshot_t>& memory_snapshot) {
	fprintf(stderr, "** go back to the anchor point\n");
	// recover registers
	if(ptrace(PTRACE_SETREGS, child, 0, &regs_snapshot) != 0) errquit("ptrace_setregs");
	
	// recover memory which has writable permission
	for(int i = 0; i < (int)memory_snapshot.size(); i++) {
		unsigned long curr_addr = memory_snapshot[i].start_addr;
		for(int j = 0; j < (int)memory_snapshot[i].content.size(); j++, curr_addr += 8) {
			if(ptrace(PTRACE_POKETEXT, child, curr_addr, memory_snapshot[i].content[j]) != 0) errquit("ptrace_poketext");
		}
		// cout << "\n*** memory snapshot ***\naddr start: " << hex << memory_snapshot[i].start_addr << endl;
		// cout << "content:\n" << memory_snapshot[i].content << "\n***\n";
	}
}

void recover_breakpoint(pid_t child, vector<bp_t>& breakpoints, unsigned long& anchor_addr, bool& has_anchor) {
	for(int i = 0; i < (int)breakpoints.size(); i++) {
		if(breakpoints[i].is_active) continue;

		unsigned long ret;
		ret = ptrace(PTRACE_PEEKTEXT, child, breakpoints[i].addr, 0);

		// do not restore the breakpoint on the anchor (see sample.3)
		if(has_anchor && anchor_addr == breakpoints[i].addr) {
			unsigned long curr_code = ptrace(PTRACE_PEEKTEXT, child, breakpoints[i].addr, 0);
			unsigned long new_code = (breakpoints[i].old_code & 0x00000000000000ff) | (curr_code & ~(0xff));
			if(ptrace(PTRACE_POKETEXT, child, breakpoints[i].addr, new_code) != 0) errquit("ptrace_poketext");
			breakpoints[i].is_active = false;
			continue;
		}
		// restore other breakpoints
		if(ptrace(PTRACE_POKETEXT, child, breakpoints[i].addr, ((ret & (~0xff)) | 0xcc)) != 0) errquit("ptrace_poketext");
		breakpoints[i].is_active = true;
	}
}

int main(int argc, char *argv[]) {
	pid_t child;
	if(argc < 2) {
		fprintf(stderr, "usage: %s program [args ...]\n", argv[0]);
		return -1;
	}
	if((child = fork()) < 0) errquit("fork");
	if(child == 0) {
		if(ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) errquit("ptrace@child");
		execvp(argv[1], argv+1);
		errquit("execvp");

	} else {
		int wait_status;
		if(waitpid(child, &wait_status, 0) < 0) errquit("waitpid");
		ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL);

		// read and parse the elf file
		proc_info_t proc_info;
		get_elf_info(child, argv[1], proc_info);

		// get the machine code -> so 0xcc won't exist in the code
		int code_size = get_code(argv[1]);

		// dissemble the instructions
		struct user_regs_struct regs;
		if(ptrace(PTRACE_GETREGS, child, 0, &regs) != 0) errquit("ptrace_getregs");
		fprintf(stderr, "** program '%s' loaded. entry point 0x%llx\n", argv[1], regs.rip);
		disassemble(child, regs, proc_info, code_size);

		// command list
		vector<string> command_list{"si", "cont", "break", "anchor", "timetravel"};

		// breakpoint list
		vector<bp_t> breakpoints;

		// snapshot information
		struct user_regs_struct regs_snapshot;
		vector<snapshot_t> memory_snapshot;  // record memory which has write permission
		unsigned long anchor_addr;
		bool has_anchor = false;

		string input_hint("(sdb) "), cmd;
		while(true) {
			cout << input_hint;
			getline(cin, cmd);
			vector<string> curr_cmd = get_command(cmd);

			// ignore invalid command
			if(cmd.length() == 0) continue;
			vector<string>::iterator it = find(command_list.begin(), command_list.end(), curr_cmd[0]);
    		if (it == command_list.end()) continue;

			// check which command it is
			if(curr_cmd[0] == "si") {
				check_breakpoint(child, breakpoints);
				cmd_si(child);
				check_status(child, wait_status, breakpoints, curr_cmd[0]);
				disassemble(child, regs, proc_info, code_size);

			} else if(curr_cmd[0] == "cont") {
				check_breakpoint(child, breakpoints);
				cmd_cont(child);
				check_status(child, wait_status, breakpoints, curr_cmd[0]);
				disassemble(child, regs, proc_info, code_size);

			} else if(curr_cmd[0] == "break") {
				unsigned long target = strtol(curr_cmd[1].c_str(), NULL, 16);
				cmd_break(child, target, breakpoints);

			} else if(curr_cmd[0] == "anchor") {
				cmd_anchor(child, regs_snapshot, memory_snapshot, anchor_addr, has_anchor, argv[1]);

			} else if(curr_cmd[0] == "timetravel") {
				cmd_timetravel(child, regs_snapshot, memory_snapshot);
				recover_breakpoint(child, breakpoints, anchor_addr, has_anchor);
				disassemble(child, regs, proc_info, code_size);
			}
		}
	}
	return 0;
}

