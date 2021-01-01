---
title: VulnconCTF 2020 writeups
subtitle: Reverse engineering

# Summary for listings and search engines
summary: Corruptbattle & HashMe
# Link this post with a project
projects: []

# Date published
date: "2021-01-01T00:00:00Z"

# Date updated
lastmod: "2021-01-01T00:00:00Z"

# Is this an unpublished draft?
draft: false

# Show this page in the Featured widget?
featured: false

# Featured image
# Place an image named `featured.jpg/png` in this page's folder and customize its options here.
image:
  caption: 'Image credit: [**Unsplash**](https://noobarmy.org/vulncon/img/VULNCON.png)'
  focal_point: ""
  placement: 2
  preview_only: false

authors:
- admin

tags:
- Writeup

categories:
- Reverse Engineering
---

# vulnconCTF2020
  
Team: Fword

## Overview

```
Title                      Category             Points  Flag
-------------------------- -------------------  ------- -----------------------------
Corruptbattle              Reverse Engineering  100     vulncon{0xE209470e1289D4CE5F23aa7e486228c46C4D99a4}
HashMe                     Reverse Engineering  100     vulncon{r3ver5eM4s7er}
```


## Reverse Engineering 100: Corruptbattle

**Challenge**  
Can you find my unique blockchain address inside a corrupted and scrambled program , remember the blockchain address is of 42 chars.

![alt text](https://github.com/H4MA-A/Writeups/blob/main/vulnconCTF2020/1.png?raw=true)

**Solution**  
For this challenge, we are provided with a binary, and based on the description we have to find a blockchain address that is 42 chars long

So we start analyzing the binary


![alt text](https://github.com/H4MA-A/Writeups/blob/main/vulnconCTF2020/2.png?raw=true)

it‘s a 64 bit ELF binary so we open IDA and we start checking the disassembly


![alt text](https://github.com/H4MA-A/Writeups/blob/main/vulnconCTF2020/3.png?raw=true)

We notice that there is more than one function called main so after having a look we notice that in the function main_one the binary is loading a hex

![alt text](https://github.com/H4MA-A/Writeups/blob/main/vulnconCTF2020/4.png?raw=true)

We take that string and with python, we check the length:

![alt text](https://github.com/H4MA-A/Writeups/blob/main/vulnconCTF2020/5.png?raw=true)

So its length is 42 so we submit and its the flag 

**Flag**  
```
vulncon{0xE209470e1289D4CE5F23aa7e486228c46C4D99a4}
```

## Reverse Engineering 100: HashMe

**Challenge**  
I hash I xor what else can I do?

![alt text](https://github.com/H4MA-A/Writeups/blob/main/vulnconCTF2020/7.png?raw=true)

**Solution**  
For this challenge, we are provided with a binary, and after analyzing we fin that it’s a 32bit ELF

![alt text](https://github.com/H4MA-A/Writeups/blob/main/vulnconCTF2020/8.png?raw=true)

And once we open IDA we find a lot of conditions so I understood that I have to generate a correct flag

So at first, I tried to understand the condition and use a z3 script to generate a correct flag but I found out that IDA didn’t get the conditions right so I used the disassembly to be more accurate

But the script didn’t seem to work so all that hard work was for nothing so it came up for us to use angr 

```python
import angr
import claripy
import sys


b = "HashMe.bin"
project = angr.Project(b)
length = 13
characters = [claripy.BVS('flag{-%d' %i, 8) for i in range(length)]
input_ = claripy.Concat(*characters + [claripy.BVV(b'\n')])

state = project.factory.full_init_state(args=["b"], stdin=input_)    
simulate = project.factory.simulation_manager(state) 
good_addr = 0x15fc
bad_addr = 0x1610
simulate.explore(find=good_addr, avoid=bad_addr)  
s = []
for j in simulate.deadended:
    if b"Here you go awaaaaay" in j.posix.dumps(1):
        s.append(j)
valid = s[0].posix.dumps(0)
print(valid)
```
I calculated the addresses of the instructions using IDA hex view

![alt text](https://github.com/H4MA-A/Writeups/blob/main/vulnconCTF2020/9.png?raw=true)

Note: the script didn’t work on WSL so I tried it in a Ubuntu VM and it worked fine

![alt text](https://github.com/H4MA-A/Writeups/blob/main/vulnconCTF2020/10.png?raw=true)

**Flag**  
```
vulncon{r3ver5eM4s7er}
```
