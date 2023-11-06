---
weight: 10
title: "Ryuk Malware"
date: 2021-03-06T21:29:01+08:00
description: "We will write something interesting here!!"
tags: ["Malware"]
type: post
showTableOfContents: true
---

# Technical Analysis of Ryuk Malware

---
Below details are for stage 1


| Name | Ryuk Malware |
| --- | --- |
| 1. MD5	 | 5ac0f050f93f86e69026faea1fbb4450 |
| 2. SHA-1 | 9709774fde9ec740ad6fed8ed79903296ca9d571 |
| 3. SHA-256 | 23f8aa94ffb3c08a62735fe7fee5799880a8f322ce1d55ec49a13a3f85312db2 |
| 4. File type	 | Win32 EX |

## Overview

It is a 2 stage malware, where the first stage when initiated suddenly vanishes from the system and drops the second stage to carry out the task of privilege escalation, persistence, and process injection. The details about how it carries out each stage are mentioned further in the report.

## Preliminary Analysis

### Snapshot from VirusTotal

![Untitled.png](https://hackmd.io/_uploads/SJCxMoLmp.png)


### Snapshot from HybridAnalysis

![Untitled 1.png](https://hackmd.io/_uploads/H1VqQjL7a.png)

### MITRE ATT&CK Analysis

- Persistence
- Privilege Escalation
- Defense Evasion
- Credential Access
- Discovery
- Exfiltration

**For better Visuals and info refer to the given links**

[https://www.hybrid-analysis.com/sample/23f8aa94ffb3c08a62735fe7fee5799880a8f322ce1d55ec49a13a3f85312db2/5b78ac487ca3e1394667d414](https://www.hybrid-analysis.com/sample/23f8aa94ffb3c08a62735fe7fee5799880a8f322ce1d55ec49a13a3f85312db2/5b78ac487ca3e1394667d414)

[https://www.virustotal.com/gui/file/23f8aa94ffb3c08a62735fe7fee5799880a8f322ce1d55ec49a13a3f85312db2/](https://www.virustotal.com/gui/file/23f8aa94ffb3c08a62735fe7fee5799880a8f322ce1d55ec49a13a3f85312db2/)

## Basic Analysis of Stage I

At the very start, we see that the ransomware tries to retrieve the Major version of the system and based on it drops the second stage either in of the specified paths.

![Untitled]![Untitled 2.png](https://hackmd.io/_uploads/rJ_j7i87p.png)

## Dynamic Analysis of Stage I

Later we see that an executable is made on the fly whose name is random 5 characters. later is appended with .exe extension.

![Untitled 3.png](https://hackmd.io/_uploads/Sy9f4j8Xp.png)

Later when it tries to create the file in the directory incase it fails the name of the file is kept as ryuV.exe, Hence a ‘V’ being replaced in place of ‘k’.

![Untitled 4.png](https://hackmd.io/_uploads/HkLuEi8Xp.png)

After creation of the file, its time to load the malicious code inside of it. For this stage 1 checks whether the current process is running in 64 bit or 32 bit operating system using IsWowProcess(). Based on the result stage 1 loads code into the newly created file.

For getting the relevant imports of dlls Ryuk uses LoadlibraryA(”Kernel32.dll”) and GetProcAddress().

![Untitled 5.png](https://hackmd.io/_uploads/B1qYVoLXT.png)

Finally once the file is ready Ryuk uses ShellExecuteW() to commit the file to the specified directory.

## Stage II

| SHA256 | 8b0a5fb13309623c3518473551cb1f55d38d8450129d4a3c16b476f7b2867d7d |
| --- | --- |

### Analysis

Well, this part is still a little mystery to me, however referring to the old analysis I came to this point once stage I has completed its job of making the second one it passes to it as a command line argument and deletes itself.

![Untitled 6.png](https://hackmd.io/_uploads/SJwsEj8Xp.png)

To gain Persistence the ransomware uses the trick to add a run key to the registry.

![Untitled 7.png](https://hackmd.io/_uploads/SJDN8s8X6.png)

the full command goes like 

```powershell
C:\Windows\System32\cmd.exe /C REG ADD "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"/v "svchos" /t REG_SZ /d "C:\users\Public\BPWPc.exe" /f
```
Further we check that whether the current user has a “SeDebugPrivilege” using its LUID. Incase it is not there it adjust the privilege using AdjustTokenPrivileges(). Hence Privilege of the current process is escalated because we need special permissions to perform the next attack.

![Untitled 8.png](https://hackmd.io/_uploads/BkmULj8mp.png)

Next the ryuk looks whether the Domain name is NTA or not. Based on that it set the values of the array in which different process’s details are collected.

![Untitled 9.png](https://hackmd.io/_uploads/rJm88oU7a.png)

In the following screenshots we see that ryuk uses process injection technique. It does this by virtually allocating room for the code and then writing to it.

![Untitled 10.png](https://hackmd.io/_uploads/B1XULi8X6.png)

![Untitled 11.png](https://hackmd.io/_uploads/r1MIUoIQp.png)

### Encryption Process

For encryption purposes the malware uses 

- CryptEncrypt
- CryptGenKey
- CryptDecrypt
- CryptAquireContextW
- CryptDestroyKey
- CryptDeriveKey
- CryptImportKey

They are all a part of ADVapi32.dll 

Each encryption thread starts by generating a random 256 AES encryption. 

![Untitled 12.png](https://hackmd.io/_uploads/rkXI8sUQp.png)

![Untitled 13.png](https://hackmd.io/_uploads/ByQIIjImT.png)

After every file is encrypted we see that “HERMES” is being padded to each and every file

![Untitled 14.png](https://hackmd.io/_uploads/ByQU8oUm6.png)

it checks if a file is going to get encrypted twice.

![Untitled 15.png](https://hackmd.io/_uploads/rylm8UoIQa.png)

The important apis used in malware are as follows :

- CryptEncrypt
- CryptGenKey
- CryptDecrypt
- CryptAquireContextW
- CryptDestroyKey
- CryptDeriveKey
- CryptImportKey
- VirtualFree
- WriteProcessMemory
- VirtualAllocEx
- LookupPrivilegeValue
- GetProcAddress
- AdjustTokenPrivilege
- ShellExecuteW
- FreeLibrary
- CreateRemoteThread

