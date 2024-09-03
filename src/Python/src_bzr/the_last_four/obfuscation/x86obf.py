import os, sys
import argparse
import distorm3
import struct
import random

# constants

R_EAX = 0
R_ECX = 1
R_EDX = 2
R_EBX = 3
R_ESP = 4
R_EBP = 5
R_ESI = 6
R_EDI = 7

# globals

conf_min_steps = 1
conf_max_steps = 5

# classes

class _instr:
    def __init__(self, bytes_data, size, is_data):
        self.bytes = bytes_data
        self.size = size
        self.label = -1
        self.jmp_label = -1
        self.is_data = is_data

# functions

def is_rel_jmp(bytes_data):
    if len(bytes_data) >= 2:
        b = bytes_data[0]
        bb = bytes_data[1]
        if (b & 0xf0) == 0x70 or (b >= 0xe0 and b <= 0xe3) or b == 0xe8 or b == 0xe9 or b == 0xeb or (b == 0x0f and (bb & 0x80) == 0x80):
            return True
    return False

def get_jmp_bytes(bytes_data):
    b = bytes_data[0]
    bb = bytes_data[1]
    if (b & 0xf0) == 0x70 or (b >= 0xe0 and b <= 0xe3) or b == 0xeb:
        return 1
    elif b == 0xe8 or b == 0xe9 or (b == 0x0f and (bb & 0x80) == 0x80):
        return 4
    return 0

def get_jmp_delta(bytes_data):
    dl = get_jmp_bytes(bytes_data)
    if dl == 1:
        d = bytes_data[1]
        if d >= 0x80:
            return (0x100 - d) * (-1)
        else:
            return d
    elif dl == 4:
        fb = 1
        if bytes_data[0] == 0x0f:
            fb = 2
        d = int.from_bytes(bytes_data[fb:fb+4], byteorder='little')
        if d > 0x80000000:
            return (0x100000000 - d) * (-1)
        else:
            return d
    return 0

def get_signed_int(imm, nbytes):
    if nbytes == 1:
        if imm >= 0x80:
            return (0x100 - imm) * (-1)
        else:
            return imm
    elif nbytes == 2:
        if imm >= 0x8000:
            return (0x10000 - imm) * (-1)
        else:
            return imm        
    elif nbytes == 4:
        if imm >= 0x80000000:
            return (0x100000000 - imm) * (-1)
        else:
            return imm
    raise ValueError("Invalid number of bytes")

def get_rand_reg(exclude_regs):
    regs = list(range(R_EAX, R_EDI + 1))
    for r in exclude_regs:
        if r in regs:
            regs.remove(r)
    if len(regs) > 0:
        return random.choice(regs)
    else:
        return -1

def mod_jmp_delta(bytes_data, delta):
    ret_bytes = bytearray()
    js = get_jmp_bytes(bytes_data)
    dm = 0

    if -128 <= delta <= 127:
        if js == 1:
            ret_bytes.append(bytes_data[0])
            ret_bytes += struct.pack('<b', delta)
        elif js == 4:
            if bytes_data[0] == 0x0f:  # jmp cond r32
                if delta < 0:
                    dm = 6 - 2  # opcode len difference
                ret_bytes.append((bytes_data[1] & 0x0f) | 0x70)
                ret_bytes += struct.pack('<b', delta + dm)
            elif bytes_data[0] == 0xe8:  # call
                ret_bytes.append(bytes_data[0])
                ret_bytes += struct.pack('<i', delta)
            elif bytes_data[0] == 0xe9:  # jmp
                if delta < 0:
                    dm = 5 - 2  # opcode len difference
                ret_bytes.append(0xeb)
                ret_bytes += struct.pack('<b', delta + dm)
            else:
                raise ValueError("Unsupported jump instruction")
    else:
        if js == 1:
            if (bytes_data[0] & 0xf0) == 0x70:  # jmp cond short
                if delta < 0:
                    dm = 2 - 6  # opcode len difference
                ret_bytes += bytearray([0x0f, (bytes_data[0] & 0x0f) | 0x80])
                ret_bytes += struct.pack('<i', delta + dm)
            elif bytes_data[0] == 0xeb:  # jmp short
                if delta < 0:
                    dm = 2 - 5
                ret_bytes.append(0xe9)
                ret_bytes += struct.pack('<i', delta + dm)
            else:
                raise ValueError("Unsupported short jump instruction")
        elif js == 4:
            if bytes_data[0] == 0x0f:
                ret_bytes += bytes_data[0:2]
                ret_bytes += struct.pack('<i', delta)
            else:
                ret_bytes.append(bytes_data[0])
                ret_bytes += struct.pack('<i', delta)

    return ret_bytes

# 更新所有其他函数中的 print 语句和字节处理部分
def print_string_hex(bytes_data):
    print(" ".join(f"{b:02x}" for b in bytes_data))

def print_disasm(sl):
    ni = 0
    ioff = 0
    for i in sl:
        if i.is_data == 0:
            l = distorm3.Decode(ioff, i.bytes, distorm3.Decode32Bits)
            for (offset, size, instr, hexdump) in l:
                print(f"{ni:<4} {offset:08x}: {hexdump:<32} {instr}")
                ni += 1
                ioff += size
        else:
            print(f"{ni:<4} {ioff:08x}:", end=" ")
            print_string_hex(i.bytes)
            print("")
            ioff += i.size

# Main function stays the same, but make sure all other functions follow the updated print syntax and byte handling.

if __name__ == '__main__':
    main()
