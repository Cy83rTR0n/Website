---
title: "WhisperGate Malware"
date: 2022-11-01T17:55:28+08:00
description: "Something will put here"
tags: ["Malware"]
type: post
weight: 25
showTableOfContents: true
---

# Understanding the working of a Wiper Malware

---

## **About**

Microsoft published a report describing a malware campaign given the name “**WhisperGate**” that is targeting Ukrainian systems including government agencies and technology organizations. This malware takes destructive actions on the host in order to render the victim inoperable under the guise of a ransomware infection.

---

## What is a Data Wiper Malware?

The term "Wiper" derives its name from its fundamental purpose, which is to wipe out data and files with malicious intent. Its primary objective is not just to erase data but to inflict significant damage, often leading to the corruption of files and systems. The main aim of wiper malware is straightforward: destruction. Infamous examples of wiper malware include Shamoon, Maya, DarkSeul, and Whispergate, all of which have wreaked havoc by effectively wiping out data and causing widespread disruption.

---

## **How did Whispergate get deployed?**

An Advanced Persistent Threat (APT) group, known for its stealthy and persistent tactics, has recently come to light due to its involvement in a cybersecurity incident. This APT group had already gained unauthorized access to a targeted network before their activities were detected. Their methods included the theft of credentials, which allowed them to move laterally within the network and escalate their privileges. Notably, they exploited the CVE-2021-32648 vulnerability, highlighting their technical sophistication. This breach exhibited characteristics of a "Defus" type of attack, demonstrating the group's ability to remain undetected while carrying out their malicious operations.

---

## General Features

- Overwrite the Master Boot Record (MBR) and exhibit a fake ransom note after the system reboot.
- Download stage 3 from a Discord server.
- Stop and disable Windows Defender.
- Encrypt and damage files and finally ping an address and remove the malware itself from the machine

---

## Initial Analysis

- Whispergate Malware comprises of 4 stages
    - Stage 1:
        - SHA256: a196c6b8ffcb97ffb276d04f354696e2391311db3841ae16c8c9f56f36a38e92
        - Creation Time: 2022–01–10 10:37:18
        - First Submission: 2022–01–16 20:30:19
        - File Type: Win32 EXE
    - Stage 2:
        - SHA256: dcbbae5a1c61dbbbb7dcd6dc5dd1eb1169f5329958d38b58c3fd9384081c9b78
        - Creation Time: 2022–01–10 14:39:54
        - First Submission: 2022–01–16 20:31:26
        - File Type: Win32 EXE
    - Stage 3:
        - SHA256 : 923eb77b3c9e11d6c56052318c119c1a22d11ab71675e6b95d05eeb73d1accd6
        - Tbopbh.jpg (Reversed)
        - SHA256 : 9ef7dbd3da51332a78eff19146d21c82957821e464e8133e9594a07d716d892d
        - Creation Time: 2022–01–10 14:39:31
        - First Submission: 2022–01–16 21:29:58
        - File Type: Win32 DLL
    - Stage 4
        - 32 bit PE file created using gcc

---

## Master Boot Record

The Master Boot Record (MBR) is a critical component of a computer's startup process, responsible for initializing and managing the booting of the operating system. It consists of a tiny 512-byte data structure that holds essential information. When a computer is powered on or restarted, the BIOS (or UEFI) reads the MBR from the storage device's first sector. The MBR contains information about the disk's partitions, detailing their location, size, and file systems, as well as information about the operating system to be loaded. The MBR's working principle lies in its ability to locate and pass control to the active partition's boot loader, which then loads the operating system. Any corruption or tampering with the MBR can render a computer unable to boot, emphasizing its critical role in the system's startup process.

---

## Stage - 1

- Corrupt MBR
- Main APIs -> CreateFileW and WriteFile
- Memory Overwriting


![Untitled.png](https://hackmd.io/_uploads/BJ3MtPUQ6.png)

![Untitled 1.png](https://hackmd.io/_uploads/r1SHcPI7T.png)

![Untitled 2.png](https://hackmd.io/_uploads/Sy9EjvLmT.png)


---

## Stage - 2

- Written in C#
- Download jpg for stage 3
- Description written in russian

![Untitled 3.png](https://hackmd.io/_uploads/ByFjivLmT.png)

![Untitled 4.png](https://hackmd.io/_uploads/HyapoP876.png)

![Untitled 5.png](https://hackmd.io/_uploads/BkIy3DLXp.png)

![Untitled 6.png](https://hackmd.io/_uploads/ry1-nPUmp.png)

---

## Stage - 3

- PE file
- Reversed
- Calls the same fucntion
- Windows defender Exclusion list
- AdvancedRun.exe

![Untitled 7.png](https://hackmd.io/_uploads/rk9r2PI7p.png)

![Untitled 8.png](https://hackmd.io/_uploads/Hy5PhDLmp.png)

![Untitled 9.png](https://hackmd.io/_uploads/Hyw53wI76.png)


---

## Stage - 4

- Similar to 1st stage in terms of loader and linker
- Two important fucntion to look
- Searches for 120 file extensions
- runs command to delete itself

![Untitled 10.png](https://hackmd.io/_uploads/HJHgpD876.png)

![Untitled 11.png](https://hackmd.io/_uploads/Sy5b6vLm6.png)

![Untitled 12.png](https://hackmd.io/_uploads/BJCzTDIQT.png)

![Untitled 13.png](https://hackmd.io/_uploads/B1H46vLXa.png)

![Deletes itself](https://hackmd.io/_uploads/H1cHav87a.png)


---

## References

- [https://www.netskope.com/blog/netskope-threat-coverage-whispergate](https://www.netskope.com/blog/netskope-threat-coverage-whispergate)
- [https://www.techtarget.com/whatis/definition/Master-Boot-Record-MBR](https://www.techtarget.com/whatis/definition/Master-Boot-Record-MBR)
- [https://docs.microsoft.com/en-in/](https://docs.microsoft.com/en-in/)
- [https://www.microsoft.com/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations/](https://www.microsoft.com/security/blog/2022/01/15/destructive-malware-targeting-ukrainian-organizations/)
- [https://www.ntfs.com/guid-part-table.htm](https://www.ntfs.com/guid-part-table.htm)

