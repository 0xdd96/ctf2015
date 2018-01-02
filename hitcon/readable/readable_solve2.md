&#8195;此处漏洞点就不再详细论述，这里采用的是Return-to-dl-resolve的技术，不过这里不同于一般的构造。一般在寻址时都是base_addr+index，一般在伪造时都是通过伪造index，从而使其执行用户控制的缓冲区。<br>
&#8195;而这里由于**动态表所在的区域是可写的**，因此这里直接更改动态表的内容，也就是这里直接改base_addr，从而实现指向用户可控的缓冲区。<br>
&#8195;如下所示，首先获取动态表的基址，然后重新构造，第8项和第9项的内容，具体修改需要看程序的动态表分布。这里将字符串表的基址改为了buf_base + 0x20，将&#8195;symtab的基址改为了0x600f00，其中buf_base + 0x20地址刚好执行system字符串，0x600f00这里是随意给的，该机制会从symtab项中获取字符串的偏移，只要获取的是0就可以。<br>
```
dynamic_addr = 0x6006f8

    buf2_base = dynamic_addr + 8 * 0x10a
    buf2 = p64(5)  # DT_STRTAB
    buf2 += p64(buf_base + 0x20)  # fake strtab address
    buf2 += p64(6)  # DT_SYMTAB
    buf2 += p64(0x600f00)
```
