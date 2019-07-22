### QShell
> Description: QShell is running on nc spbctf.ppctf.net 37338

服务端返回一个二维码 解码为`sh-5.0$`  
![](https://raw.githubusercontent.com/jiancanxuepiao/Pic/master/2019-7-22/1.png)

这道题的意思是服务器返回一个二维码shell,我们通过对服务器器的二维码解码,然后对命令进行二维码加密发送,获得一个shell
```python
from PIL import Image
from pyzbar.pyzbar import decode
import qrcode
from time import sleep
from ptrlib import *

def receive():
    qr = [[]]
    data = sock.recvuntil("\n\n.").rstrip(b'.').rstrip()
    sock.recvline()
    data += b'#'
    offset = 0
    while offset < len(data):
        if data[offset] == 0xe2:
            qr[-1].append(255)
            offset += 3
        elif data[offset] == 0x20:
            qr[-1].append(0)
            offset += 1
        elif data[offset] == 0x0a:
            qr.append([])
            offset += 1
        else:
            break

    image = Image.new('RGB', (len(qr), len(qr[0])), (255, 255, 255))
    size = len(qr)
    for y, line in enumerate(qr):
        for x, c in enumerate(line):
            c = qr[y][x]
            image.putpixel((x, y), (c, c, c))
    image = image.resize((size * 3, size * 3))
    image.save("last.png")

    result = decode(image)
    return result[0][0]

def send(cmd):
    qr = qrcode.QRCode(box_size=1, border=4, version=20)
    qr.add_data(cmd)
    qr.make()
    img = qr.make_image(fill_color="white", back_color="black")

    data = b''
    for y in range(img.size[1]):
        for x in range(img.size[0]):
            r = img.getpixel((x, y))
            if r == (0, 0, 0):
                data += b'\xe2\x96\x88'
            else:
                data += b' '
        data += b'\n'
    data += b'\n.'

    sock.sendline(data)
    return

if __name__ == '__main__':
    sock = Socket("spbctf.ppctf.net", 37338)

    while True:
        print(bytes2str(receive()), end="")
        cmd = input()
        send(cmd)
        
    sock.interactive()
```

get Flag
```python
$ python solve.py 
[+] __init__: Successfully connected to spbctf.ppctf.net:37338
sh-5.0$ ls
1.py
2.py
docker-compose.yml
Dockerfile
flag.txt
log.txt
qweqwe.png
rex.txt
runserver.sh
run.sh

$ python solve.py 
[+] __init__: Successfully connected to spbctf.ppctf.net:37338
sh-5.0$ cat flag.txt
cybrics{QR_IS_MY_LOVE}
```
### Sender

给了一个邮件内容

```shell
220 ugm.cybrics.net ESMTP Postfix (Ubuntu)
EHLO localhost
250-ugm.cybrics.net
250-PIPELINING
250-SIZE 10240000
250-VRFY
250-ETRN
250-AUTH PLAIN LOGIN
250-ENHANCEDSTATUSCODES
250-8BITMIME
250 DSN
AUTH LOGIN
334 VXNlcm5hbWU6
ZmF3a2Vz
334 UGFzc3dvcmQ6
Q29tYmluNHQxb25YWFk=
235 2.7.0 Authentication successful
MAIL FROM: <fawkes@ugm.cybrics.net>
250 2.1.0 Ok
RCPT TO: <area51@af.mil>
250 2.1.5 Ok
DATA
354 End data with <CR><LF>.<CR><LF>
From: fawkes <fawkes@ugm.cybrics.net>
To: Area51 <area51@af.mil>
Subject: add - archive pw
Content-Type: text/plain; charset="iso-8859-1"
Content-Transfer-Encoding: quoted-printable
MIME-Version: 1.0

=62=74=77=2E=0A=0A=70=61=73=73=77=6F=72=64 =66=6F=72 =74=68=65 =61=72=63=
=68=69=76=65 =77=69=74=68 =66=6C=61=67=3A =63=72=61=63=6B=30=57=65=73=74=
=6F=6E=38=38=76=65=72=74=65=62=72=61=0A=0A=63=68=65=65=72=73=21=0A
.
250 2.0.0 Ok: queued as C4D593E8B6
QUIT
221 2.0.0 Bye
```
base64解出账号密码
fawkes / Combin4t1onXXY

Quoted-printable编码使用cyberchife解密
```
btw.

password for the archive with flag: crack0Weston88vertebra

cheers!

```

写脚本接收文件
```python
from ptrlib import *
import base64

sock = Socket("ugm.cybrics.net", 110)

sock.recvline()
sock.sendline("USER fawkes")
sock.recvline()
sock.sendline("PASS Combin4t1onXXY")
sock.recvline()
sock.sendline("RETR 1")
sock.recvuntil("base64\r\n\r\n")
data = b''
while True:
    data += sock.recv()
    if b'\r\n\r\n' in data:
        data = data[:data.index(b'\r\n\r\n')]
        break

binary = base64.b64decode(data)
with open("secret_flag.zip", "wb") as f:
    f.write(binary)
```

### Matreshka
题目
```
Matreshka hides flag. Open it
matreshka.zip
```

使用jad反编译class文件

```
D:\Tools\Android\AndCrack_Tool\Tools\ApkIDE>jad.exe Code2.class
Parsing Code2.class... Generating Code2.jad

D:\Tools\Android\AndCrack_Tool\Tools\ApkIDE>

```
反编译结果
```java
// Decompiled by Jad v1.5.8g. Copyright 2001 Pavel Kouznetsov.
// Jad home page: http://www.kpdus.com/jad.html
// Decompiler options: packimports(3) 
// Source File Name:   2.java

import java.io.*;
import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;

class Code2
{

    Code2()
    {
    }

    public static byte[] decode(byte abyte0[], String s)
        throws Exception
    {
        SecretKeyFactory secretkeyfactory = SecretKeyFactory.getInstance("DES");
        byte abyte1[] = s.getBytes();
        DESKeySpec deskeyspec = new DESKeySpec(abyte1);
        javax.crypto.SecretKey secretkey = secretkeyfactory.generateSecret(deskeyspec);
        Cipher cipher = Cipher.getInstance("DES");
        cipher.init(2, secretkey);
        byte abyte2[] = cipher.doFinal(abyte0);
        return abyte2;
    }

    public static byte[] encode(byte abyte0[], String s)
        throws Exception
    {
        SecretKeyFactory secretkeyfactory = SecretKeyFactory.getInstance("DES");
        byte abyte1[] = s.getBytes();
        DESKeySpec deskeyspec = new DESKeySpec(abyte1);
        javax.crypto.SecretKey secretkey = secretkeyfactory.generateSecret(deskeyspec);
        Cipher cipher = Cipher.getInstance("DES");
        cipher.init(1, secretkey);
        byte abyte2[] = cipher.doFinal(abyte0);
        return abyte2;
    }

    public static void main(String args[])
        throws Exception
    {
        String s = "matreha!";
        byte abyte0[] = encode(System.getProperty("user.name").getBytes(), s);
        byte abyte1[] = {
            76, -99, 37, 75, -68, 10, -52, 10, -5, 9, 
            92, 1, 99, -94, 105, -18
        };
        for(int i = 0; i < abyte1.length; i++)
            if(abyte1[i] != abyte0[i])
            {
                System.out.println("No");
                return;
            }

        File file = new File("data.bin");
        FileInputStream fileinputstream = new FileInputStream(file);
        byte abyte2[] = new byte[(int)file.length()];
        fileinputstream.read(abyte2);
        fileinputstream.close();
        byte abyte3[] = decode(abyte2, System.getProperty("user.name"));
        FileOutputStream fileoutputstream = new FileOutputStream("stage2.bin");
        fileoutputstream.write(abyte3, 0, abyte3.length);
        fileoutputstream.flush();
        fileoutputstream.close();
    }
}

```



解密abyte1
```
D:\ctf\赛题\2019-07>javac Matreshka.java

D:\ctf\赛题\2019-07>java Matreshka
lettreha

D:\ctf\赛题\2019-07>
```

然后修改Code2
```java
import java.io.*;
import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;

class Code2
{

    Code2()
    {
    }

    public static byte[] decode(byte abyte0[], String s)
        throws Exception
    {
        SecretKeyFactory secretkeyfactory = SecretKeyFactory.getInstance("DES");
        byte abyte1[] = s.getBytes();
        DESKeySpec deskeyspec = new DESKeySpec(abyte1);
        javax.crypto.SecretKey secretkey = secretkeyfactory.generateSecret(deskeyspec);
        Cipher cipher = Cipher.getInstance("DES");
        cipher.init(2, secretkey);
        byte abyte2[] = cipher.doFinal(abyte0);
        return abyte2;
    }

    public static byte[] encode(byte abyte0[], String s)
        throws Exception
    {
        SecretKeyFactory secretkeyfactory = SecretKeyFactory.getInstance("DES");
        byte abyte1[] = s.getBytes();
        DESKeySpec deskeyspec = new DESKeySpec(abyte1);
        javax.crypto.SecretKey secretkey = secretkeyfactory.generateSecret(deskeyspec);
        Cipher cipher = Cipher.getInstance("DES");
        cipher.init(1, secretkey);
        byte abyte2[] = cipher.doFinal(abyte0);
        return abyte2;
    }

    public static void main(String args[])
        throws Exception
    {
        String s = "matreha!";
        String username="lettreha";
        byte abyte0[] = encode(username.getBytes(), s);
        byte abyte1[] = {
            76, -99, 37, 75, -68, 10, -52, 10, -5, 9, 
            92, 1, 99, -94, 105, -18
        };
        for(int i = 0; i < abyte1.length; i++)
            if(abyte1[i] != abyte0[i])
            {
                System.out.println("No");
                return;
            }

        File file = new File("data.bin");
        FileInputStream fileinputstream = new FileInputStream(file);
        byte abyte2[] = new byte[(int)file.length()];
        fileinputstream.read(abyte2);
        fileinputstream.close();
        byte abyte3[] = decode(abyte2, username);
        FileOutputStream fileoutputstream = new FileOutputStream("stage2.bin");
        fileoutputstream.write(abyte3, 0, abyte3.length);
        fileoutputstream.flush();
        fileoutputstream.close();
    }
}

```

得到stage2.bin

直接运行stage2.bin显示Fail
```
jcxp@ubuntu:~/ctf/events/CyBRICS$ ./stage2.bin 
Fail
```

使用gdb调试


这里有一个比较
```c
.text:0000000000476122                 cmp     rax, 11h
.text:0000000000476126                 jnz     loc_4762EA
.text:000000000047612C                 mov     rax, [rsp+0C0h+var_28]
.text:0000000000476134                 xor     ecx, ecx
.text:0000000000476136                 jmp     short loc_47613B
.text:0000000000476138 ; ---------------------------------------------------------------------------
.text:0000000000476138
.text:0000000000476138 loc_476138:                             ; CODE XREF: main_main+19C↓j
.text:0000000000476138                 inc     rcx
.text:000000000047613B
.text:000000000047613B loc_47613B:                             ; CODE XREF: main_main+186↑j
.text:000000000047613B                 cmp     rcx, 11h
.text:000000000047613F                 jge     short loc_476181
.text:0000000000476141                 movzx   edx, byte ptr [rsp+rcx+0C0h+var_49]
.text:0000000000476146                 movzx   ebx, byte ptr [rax+rcx]
.text:000000000047614A                 cmp     dl, bl
.text:000000000047614C                 jz      short loc_476138
.text:000000000047614E                 call    runtime_printlock
.text:0000000000476153                 lea     rax, unk_4A3F9C
.text:000000000047615A                 mov     [rsp+0C0h+var_C0], rax
.text:000000000047615E                 mov     qword ptr [rsp+0C0h+var_B8], 5
.text:0000000000476167                 call    runtime_printstring
.text:000000000047616C                 call    runtime_printunlock
.text:0000000000476171                 mov     rbp, [rsp+0C0h+var_8]
.text:0000000000476179                 add     rsp, 0C0h
.text:0000000000476180                 retn
.text:0000000000476181 ; ---------------------------------------------------------------------------
.text:0000000000476181
.text:0000000000476181 loc_476181:                             ; CODE XREF: main_main+18F↑j
.text:0000000000476181                 call    runtime_printlock
```

通过调试使程序跳转到`runtime_printlock`执行
生成result.pyc

解码
```shell
root@ubuntu:/home/jcxp/ctf/events/CyBRICS# uncompyle6 result.pyc 
# uncompyle6 version 3.3.5
# Python bytecode 3.7 (3394)
# Decompiled from: Python 2.7.12 (default, Nov 12 2018, 14:36:49) 
# [GCC 5.4.0 20160609]
# Embedded file name: ./1.py
# Size of source mod 2**32: 439 bytes


def decode(data, key):
    idx = 0
    res = []
    for c in data:
        res.append(chr(c ^ ord(key[idx])))
        idx = (idx + 1) % len(key)

    return res


flag = [
 40, 11, 82, 58, 93, 82, 64, 76, 6, 70, 100, 26, 7, 4, 123, 124, 127, 45, 1, 125, 107, 115, 0, 2, 31, 15]
print('Enter key to get flag:')
key = input()
if len(key) != 8:
    print('Invalid len')
    quit()
res = decode(flag, key)
print(''.join(res))
# okay decompiling result.pyc

```

由于flag的开头为`cybrics{`  
我们可以算出key为`Kr0H4137`  
flag为`cybrics{M4TR35HK4_15_B35T}`


### Paranoid

> Description: My neighbors are always very careful about their security. For example they've just bought a new home Wi-Fi router, and instead of just leaving it open, they instantly are setting passwords! Don't they trust me? I feel offended. Can you give me their current router admin pw?
File: paranoid.pcap

这个数据包是http和IEEE802.11的混合数据流，在其中的一个post包中有WEP的KEY

```
POST /req/wlanApSecurity HTTP/1.1
Host: 192.168.1.1
Connection: keep-alive
Content-Length: 745
Cache-Control: max-age=0
Authorization: Digest username="admin", realm="KEENETIC", nonce="4304e17cc9ba8af651a012d825b5ef2c", uri="/req/wlanApSecurity", algorithm=MD5, response="1465cdf644d3fbe13622e4bfc5f6a27d", opaque="5ccc069c403ebaf9f0171e9517f40e41", qop=auth, nc=00000001, cnonce="f02e829a935d0bd9"
Origin: http://192.168.1.1
Upgrade-Insecure-Requests: 1
DNT: 1
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.142 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3
Referer: http://192.168.1.1/homenet/wireless/security.asp
Accept-Encoding: gzip, deflate
Accept-Language: ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7
Cookie: interval=50

WLAN_AP_ENCRYPT_TYPE=2&WLAN_AP_WEP_KEY_INDEX=1&WLAN_AP_WEP_KEY1_FORMAT=1&WLAN_AP_WEP_KEY1=Xi1nvy5KGSgI2&WLAN_AP_WEP_KEY2_FORMAT=1&WLAN_AP_WEP_KEY2=Xi1nvy5KGSgI2&WLAN_AP_WEP_KEY3_FORMAT=1&WLAN_AP_WEP_KEY3=Xi1nvy5KGSgI2&WLAN_AP_WEP_KEY4_FORMAT=1&WLAN_AP_WEP_KEY4=Xi1nvy5KGSgI2&WLAN_AP_AUTH_TYPE=1&WLAN_AP_WEP_ENCRYPT_TYPE=2&WLAN_AP_WEP128_KEY_INDEX=1&WLAN_AP_WEP128_KEY1_FORMAT=1&WLAN_AP_WEP128_KEY1=Xi1nvy5KGSgI2&WLAN_AP_WEP128_KEY2_FORMAT=1&WLAN_AP_WEP128_KEY2=Xi1nvy5KGSgI2&WLAN_AP_WEP128_KEY3_FORMAT=1&WLAN_AP_WEP128_KEY3=Xi1nvy5KGSgI2&WLAN_AP_WEP128_KEY4_FORMAT=1&WLAN_AP_WEP128_KEY4=Xi1nvy5KGSgI2&WEP128_passphrase=&WEP64_passphrase=&save=%D0%9F%D1%80%D0%B8%D0%BC%D0%B5%D0%BD%D0%B8%D1%82%D1%8C&submit_url=%2Fhomenet%2Fwireless%2Fsecurity.asp
```
所以WEP的KEY为：`58:69:31:6e:76:79:35:4b:47:53:67:49:32`
![](https://raw.githubusercontent.com/jiancanxuepiao/Pic/master/2019-7-22/0.png)

SSID`为NSA_WIFI_DONT_HACK`

```
root@kali:~/ctf# aircrack-ng paranoid.pcap 
Opening paranoid.pcap
Read 52725 packets.

   #  BSSID              ESSID                     Encryption

   1  00:0C:43:30:52:88  NSA_WIFI_DONT_HACK        WPA (1 handshake)

Choosing first network as target.

Opening paranoid.pcap
Please specify a dictionary (option -w).


Quitting aircrack-ng...
```
解密WEP数据包
```
root@kali:~/ctf# airdecap-ng -e NSA_WIFI_DONT_HACK -w 58:69:31:6e:76:79:35:4b:47:53:67:49:32 paranoid.pcap 
Total number of packets read         52725
Total number of WEP data packets      7434
Total number of WPA data packets      2899
Number of plaintext data packets      2367
Number of decrypted WEP  packets      7434
Number of corrupted WEP  packets         0
Number of decrypted WPA  packets         0
```
成功解密之后,发现WPA/PSK密码`2_RGR_xO-uiJFiAxdA33-PsdanuK`
```
POST /req/wlanApSecurity HTTP/1.1
Host: 192.168.1.1
Connection: keep-alive
Content-Length: 340
Cache-Control: max-age=0
Authorization: Digest username="admin", realm="KEENETIC admin:1234", nonce="1c35e4e680411cb7a44efedcf35f8964", uri="/req/wlanApSecurity", algorithm=MD5, response="9d2a315160f4b83bf526334ef549233a", opaque="5ccc069c403ebaf9f0171e9517f40e41", qop=auth, nc=00000179, cnonce="927accb323642eef"
Origin: http://192.168.1.1
Upgrade-Insecure-Requests: 1
DNT: 1
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.142 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3
Referer: http://192.168.1.1/homenet/wireless/security.asp
Accept-Encoding: gzip, deflate
Accept-Language: ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7
Cookie: interval=50

WLAN_AP_ENCRYPT_TYPE=4&WLAN_AP_WPA_PSK=2_RGR_xO-uiJFiAxdA33-PsdanuK&WLAN_AP_AUTH_TYPE=4&WEP128_passphrase=&WEP64_passphrase=&WLAN_AP_WPA_ENCRYPT_TYPE=4&WLAN_AP_WPA_PSK_FORMAT=1&WLAN_AP_WPA_PSK_passphrase=2_RGR_xO-uiJFiAxdA33-PsdanuK&save=%D0%9F%D1%80%D0%B8%D0%BC%D0%B5%D0%BD%D0%B8%D1%82%D1%8C&submit_url=%2Fhomenet%2Fwireless%2Fsecurity.asp
```

解密这个数据包
```
root@kali:~/ctfairdecap-ng -e NSA_WIFI_DONT_HACK -p 2_RGR_xO-uiJFiAxdA33-PsdanuK paranoid.pcap 
Total number of packets read         52725
Total number of WEP data packets      7434
Total number of WPA data packets      2899
Number of plaintext data packets      2367
Number of decrypted WEP  packets         0
Number of corrupted WEP  packets         0
Number of decrypted WPA  packets      2899
```

成功getflag
```
POST /req/admin HTTP/1.1
Host: 192.168.1.1
Connection: keep-alive
Content-Length: 223
Pragma: no-cache
Cache-Control: no-cache
Authorization: Digest username="admin", realm="KEENETIC admin:1234", nonce="1c35e4e680411cb7a44efedcf35f8964", uri="/req/admin", algorithm=MD5, response="207085dda1202f06cc7af303971b9333", opaque="5ccc069c403ebaf9f0171e9517f40e41", qop=auth, nc=000001dc, cnonce="77e8278bb27dd917"
Origin: http://192.168.1.1
Upgrade-Insecure-Requests: 1
DNT: 1
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.142 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3
Referer: http://192.168.1.1/system/admin.asp
Accept-Encoding: gzip, deflate
Accept-Language: ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7
Cookie: interval=50

ADMIN_NAME=admin&ADMIN_PASSWORD=cybrics%7Bn0_w4Y_7o_h1d3_fR0m_Y0_n316hb0R%7D&PASSWORD_CONFIRM=cybrics%7Bn0_w4Y_7o_h1d3_fR0m_Y0_n316hb0R%7D&save=%D0%9F%D1%80%D0%B8%D0%BC%D0%B5%D0%BD%D0%B8%D1%82%D1%8C&submit_url=%2Fstatus.asp
```