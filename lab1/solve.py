#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import hashlib
import time
from pwn import *
import pow as pw
import base64

def getInitialLines(r):
    for i in range(7):
        tmp =  r.recvline()
        if i == 3:
            # print(tmp)
            splitTmp = tmp.split()
            questionNum = int(splitTmp[3])
    return questionNum

def calculateQuestion(str):
    splitStr = str.split()
    question = splitStr[2] + " " + splitStr[3] + " " + splitStr[4]
    ans = eval(question)
    return ans


if __name__ == '__main__':
    # solve pow
    r = remote('up23.zoolab.org', 10363)
    pw.solve_pow(r)

    # get question lines
    questionNum = getInitialLines(r)

    for cnt in range(questionNum):
        q = r.recvuntil(b'?').decode()
        ans = calculateQuestion(q)

        binary = ans.to_bytes(ans.bit_length(), 'big')
        binary = binary.lstrip(b'\x00')
        little_endian = binary[::-1]
        base64_encoded = base64.b64encode(little_endian)

        print(base64_encoded)

        # encode base64
        r.sendline(base64_encoded)

        print("------")

    msg =  r.recvline()
    print(msg)
    # r.interactive()

r.close()