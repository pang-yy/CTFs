##  Poly Playground

Category: misc

### Description

Magicians love to create things out of thin air. This time our secret wizards have created a playground. Test out your wizardry here!

Author: jloh02

How to Play:

1. You'll be given a set of `n` roots for each level.

2. Utilize your mathematical knowledge to construct a polynomial equation that has the provided roots. You can assume that repeated roots will be given as repeats.

3. Channel your creativity and problem-solving skills to craft elegant and efficient equations.

4. Submit your polynomial creations as a comma-separted list of `n+1` coefficients starting with the highest order (which should always be 1).

### Solution

Scripts:

```py
from pwn import *
from numpy import poly

p = remote('challs.nusgreyhats.org', 31113)

# 100 levels
count = 0;

for i in range(100):
    print(p.recvuntil((b'Roots: ')))
    recv = p.recvuntil(b'\n')
    num_array = str(recv).split(',')
    payload = ''
    # format
    if (len(num_array) > 1):
        num_array[0] = int((num_array[0].split("'"))[-1])
        num_array[-1] = int((num_array[-1].split('\\'))[0])
        for i in range(1,len(num_array)-1):
            num_array[i] = int(num_array[i])
    else:
        num_array = [int(recv)]

    # answer
    ans = poly(num_array)
    for num in ans:
        payload += str(int(num))
        payload += ','
    payload = payload[:len(payload) - 1]
    payload = payload.encode()
    print(p.recvuntil(b'equation: '))
    p.sendline(payload)

p.interactive()
```
