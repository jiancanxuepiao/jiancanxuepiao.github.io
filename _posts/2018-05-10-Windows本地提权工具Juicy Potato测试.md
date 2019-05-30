---
layout: post
title: Windows本地提权工具Juicy Potato测试分析
tags:  内网 渗透 提权 
author: jcxp
---

## 0x00 前言
---
Juicy Potato是一款Windows系统的本地提权工具，是在工具RottenPotatoNG的基础上做了扩展，适用条件更广。  
利用的前提是获得了SeImpersonate或者SeAssignPrimaryToken权限，通常在webshell下使用
那么，Juicy Potato的使用方法有哪些，有哪些限制条件呢？本文将对其进行测试。

Juicy Potato的下载地址：

https://github.com/ohpe/juicy-potato
## 0x01 简介
---

本文将要介绍以下内容：

- 实现原理
- 对RottenPotatoNG的扩展
- 枚举可用COM对象的方法
- 使用方法
- 限制条件
- 防御思路

## 0x02 实现原理
---
参考资料：

https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/

需要理解的几个知识：

1. 使用DCOM时，如果以服务的方式远程连接，那么权限为System，例如BITS服务
2. 使用DCOM可以通过TCP连接到本机的一个端口，发起NTLM认证，该认证可以被重放
3. LocalService用户默认具有SeImpersonate和SeAssignPrimaryToken权限
4. 开启SeImpersonate权限后，能够在调用CreateProcessWithToken时，传入新的Token创建新的进程
5. 开启SeAssignPrimaryToken权限后，能够在调用CreateProcessAsUser时，传入新的Token创建新的进程

Juicy Potato的实现流程如下：
#### 1、加载COM，发出请求，权限为System


在指定ip和端口的位置尝试加载一个COM对象

RottenPotatoNG使用的COM对象为BITS，CLSID为`{4991d34b-80a1-4291-83b6-3328366b9097}`

可供选择的COM对象不唯一，Juicy Potato提供了多个，详细列表可参考如下地址：

https://github.com/ohpe/juicy-potato/blob/master/CLSID/README.md
#### 2、回应步骤1的请求，发起NTLM认证

正常情况下，由于权限不足，当前权限不是System，无法认证成功
#### 3、针对本地端口，同样发起NTLM认证，权限为当前用户

由于权限为当前用户，所以NTLM认证能够成功完成

RottenPotatoNG使用的135端口

Juicy Potato支持指定任意本地端口，但是RPC一般默认为135端口，很少被修改

#### 4、分别拦截两个NTLM认证的数据包，替换数据，通过NTLM重放使得步骤1(权限为System)的NTLM认证通过，获得System权限的Token

重放时需要注意NTLM认证的NTLM Server Challenge不同，需要修正
#### 5、利用System权限的Token创建新进程

如果开启SeImpersonate权限，调用CreateProcessWithToken，传入System权限的Token，创建的进程为System权限   
或者  
如果开启SeAssignPrimaryToken权限，调用CreateProcessAsUser，传入System权限的Token，创建的进程为System权限

**利用的关键：**
当前用户支持SeImpersonate或者SeAssignPrimaryToken权限

以下用户具有该权限：

- 本地管理员组成员和本地服务帐户
- 由服务控制管理器启动的服务
- 由组件对象模型 (COM) 基础结构启动的并配置为在特定帐户下运行的COM服务器

针对提权的话，主要是第三类用户，常见的为LocalService用户，例如IIS和者sqlserver的用户
## 0x03 枚举可用COM对象的方法
---

Juicy Potato提供了枚举可用COM对象的方法，步骤如下：

#### 1、获得可用CLSID的列表

使用GetCLSID.ps1，地址如下：

https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1  
**注：**

使用时同级目录下需要包含支持文件`.\utils\Join-Object.ps1`

执行成功后生成文件`CLSID.list`和`CLSID.csv`
#### 2、使用批处理调用juicypotato.exe逐个测试CLSID

批处理地址如下：

https://github.com/ohpe/juicy-potato/blob/master/Test/test_clsid.bat

juicypotato.exe的参数如下：

```
juicypotato.exe -z -l !port! -c %%i >> result.log
```
Juicy Potato已经测试了如下Windows系统：

- Windows 7 Enterprise
- Windows 8.1 Enterprise
- Windows 10 Enterprise
- Windows 10 Professional
- Windows Server 2008 R2 Enterprise
- Windows Server 2012 Datacenter
- Windows Server 2016 Standard


