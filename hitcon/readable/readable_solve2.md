&#8195;此处漏洞点就不再详细论述，这里采用的是ret2lib的技术，不过这里不同于一般的构造。一般在寻址时都是base_addr+index，一般在伪造时都是通过伪造index，从而使其执行用户控制的缓冲区。<br>
&#8195;而这里由于动态表所在的区域是可写的，因此这里直接更改动态表的内容，也就是这里直接改base_addr，从而实现指向用户可控的缓冲区。<br>
&#8195;如下所示，首先获取动态表的基址，然后重新构造，第8项和第9项的内容，具体修改需要看程序的动态表分布。
```
dynamic_addr = 0x6006f8

    buf2_base = dynamic_addr + 8 * 0x10a
    buf2 = p64(5)  # DT_STRTAB
    buf2 += p64(buf_base + 0x20)  # fake strtab address
    buf2 += p64(6)  # DT_SYMTAB
    buf2 += p64(0x600f00)
```
