# elf_inspect

## elfの中身を眺める
### 普通のBPF elf
```shell
$  readelf -a kprobe.o
ELF Header:
  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00 
  Class:                             ELF64
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              REL (Relocatable file)
  Machine:                           Linux BPF
  Version:                           0x1
  Entry point address:               0x0
  Start of program headers:          0 (bytes into file)
  Start of section headers:          696 (bytes into file)
  Flags:                             0x0
  Size of this header:               64 (bytes)
  Size of program headers:           0 (bytes)
  Number of program headers:         0
  Size of section headers:           64 (bytes)
  Number of section headers:         10
  Section header string table index: 1

Section Headers:
  [Nr] Name              Type             Address           Offset
       Size              EntSize          Flags  Link  Info  Align
  [ 0]                   NULL             0000000000000000  00000000
       0000000000000000  0000000000000000           0     0     0
  [ 1] .strtab           STRTAB           0000000000000000  00000238
       000000000000007a  0000000000000000           0     0     1
  [ 2] .text             PROGBITS         0000000000000000  00000040
       0000000000000000  0000000000000000  AX       0     0     4
  [ 3] kprobe/sys_execve PROGBITS         0000000000000000  00000040
       00000000000000b0  0000000000000000  AX       0     0     8
  [ 4] .relkprobe/s[...] REL              0000000000000000  00000208
       0000000000000020  0000000000000010   I       9     3     8
  [ 5] license           PROGBITS         0000000000000000  000000f0
       000000000000000d  0000000000000000  WA       0     0     1
  [ 6] maps              PROGBITS         0000000000000000  00000100
       0000000000000014  0000000000000000  WA       0     0     4
  [ 7] .eh_frame         PROGBITS         0000000000000000  00000118
       0000000000000030  0000000000000000   A       0     0     8
  [ 8] .rel.eh_frame     REL              0000000000000000  00000228
       0000000000000010  0000000000000010   I       9     7     8
  [ 9] .symtab           SYMTAB           0000000000000000  00000148
       00000000000000c0  0000000000000018           1     5     8
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
  L (link order), O (extra OS processing required), G (group), T (TLS),
  C (compressed), x (unknown), o (OS specific), E (exclude),
  D (mbind), p (processor specific)

There are no section groups in this file.

There are no program headers in this file.

There is no dynamic section in this file.

Relocation section '.relkprobe/sys_execve' at offset 0x208 contains 2 entries:
  Offset          Info           Type           Sym. Value    Sym. Name
000000000030  000600000001 R_BPF_INSN_64     0000000000000000 kprobe_map
000000000070  000600000001 R_BPF_INSN_64     0000000000000000 kprobe_map

Relocation section '.rel.eh_frame' at offset 0x228 contains 1 entry:
  Offset          Info           Type           Sym. Value    Sym. Name
00000000001c  000200000002 R_BPF_INSN_32     0000000000000000 kprobe/sys_execve

The decoding of unwind sections for machine type Linux BPF is not currently supported.

Symbol table '.symtab' contains 8 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND 
     1: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS kprobe.c
     2: 0000000000000000     0 SECTION LOCAL  DEFAULT    3 kprobe/sys_execve
     3: 0000000000000098     0 NOTYPE  LOCAL  DEFAULT    3 LBB0_2
     4: 00000000000000a0     0 NOTYPE  LOCAL  DEFAULT    3 LBB0_3
     5: 0000000000000000   176 FUNC    GLOBAL DEFAULT    3 kprobe_execve
     6: 0000000000000000    20 OBJECT  GLOBAL DEFAULT    6 kprobe_map
     7: 0000000000000000    13 OBJECT  GLOBAL DEFAULT    5 __license

No version information found in this file.
```

```shell
$ llvm-objdump -D kprobe.o

kprobe.o:       file format elf64-bpf

Disassembly of section .strtab:

0000000000000000 <.strtab>:
       0:       00 2e 74 65 78 74 00 6d <unknown>
       1:       61 70 73 00 6b 70 72 6f r0 = *(u32 *)(r7 + 115)
       2:       62 65 5f 6d 61 70 00 2e <unknown>
       3:       72 65 6c 6b 70 72 6f 62 <unknown>
       4:       65 2f 73 79 73 5f 65 78 <unknown>
       5:       65 63 76 65 00 6b 70 72 if r3 s> 1919970048 goto +25974 <.strtab+0x32be0>
       6:       6f 62 65 5f 65 78 65 63 r2 <<= r6
       7:       76 65 00 5f 5f 6c 69 63 if w5 s>= 1667853407 goto +24320 <.strtab+0x2f840>
       8:       65 6e 73 65 00 2e 72 65 <unknown>
       9:       6c 2e 65 68 5f 66 72 61 <unknown>
      10:       6d 65 00 6b 70 72 6f 62 if r5 s> r6 goto +27392 <.strtab+0x35858>
      11:       65 2e 63 00 2e 73 74 72 <unknown>
      12:       74 61 62 00 2e 73 79 6d w1 >>= 1836675886
      13:       74 61 62 00 2e 72 6f 64 w1 >>= 1685025326
      14:       61 74 61 2e 73 74 72 31 r4 = *(u32 *)(r7 + 11873)
      15:       2e 31 36 00 4c 42 42 30 if w1 > w3 goto +54 <.strtab+0x230>
      16:       5f 33 00 4c 42 42 30 5f r3 &= r3
      17:       32      <unknown>
      17:       00      <unknown>

Disassembly of section kprobe/sys_execve:

0000000000000000 <kprobe_execve>:
       0:       b7 01 00 00 21 0a 00 00 r1 = 2593
       1:       6b 1a f0 ff 00 00 00 00 *(u16 *)(r10 - 16) = r1
       2:       18 01 00 00 50 46 20 57 00 00 00 00 6f 72 6c 64 r1 = 7236284523806213712 ll
       4:       7b 1a e8 ff 00 00 00 00 *(u64 *)(r10 - 24) = r1
       5:       18 01 00 00 48 65 6c 6c 00 00 00 00 6f 2c 20 42 r1 = 4764857262830019912 ll
       7:       7b 1a e0 ff 00 00 00 00 *(u64 *)(r10 - 32) = r1
       8:       b7 06 00 00 00 00 00 00 r6 = 0
       9:       73 6a f2 ff 00 00 00 00 *(u8 *)(r10 - 14) = r6
      10:       bf a1 00 00 00 00 00 00 r1 = r10
      11:       07 01 00 00 e0 ff ff ff r1 += -32
      12:       b7 02 00 00 13 00 00 00 r2 = 19
      13:       85 00 00 00 06 00 00 00 call 6
      14:       63 6a dc ff 00 00 00 00 *(u32 *)(r10 - 36) = r6
      15:       b7 06 00 00 01 00 00 00 r6 = 1
      16:       7b 6a e0 ff 00 00 00 00 *(u64 *)(r10 - 32) = r6
      17:       bf a2 00 00 00 00 00 00 r2 = r10
      18:       07 02 00 00 dc ff ff ff r2 += -36
      19:       18 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 r1 = 0 ll
      21:       85 00 00 00 01 00 00 00 call 1
      22:       55 00 09 00 00 00 00 00 if r0 != 0 goto +9 <LBB0_2>
      23:       bf a2 00 00 00 00 00 00 r2 = r10
      24:       07 02 00 00 dc ff ff ff r2 += -36
      25:       bf a3 00 00 00 00 00 00 r3 = r10
      26:       07 03 00 00 e0 ff ff ff r3 += -32
      27:       18 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 r1 = 0 ll
      29:       b7 04 00 00 00 00 00 00 r4 = 0
      30:       85 00 00 00 02 00 00 00 call 2
      31:       05 00 01 00 00 00 00 00 goto +1 <LBB0_3>

0000000000000100 <LBB0_2>:
      32:       db 60 00 00 00 00 00 00 lock *(u64 *)(r0 + 0) += r6

0000000000000108 <LBB0_3>:
      33:       b7 00 00 00 00 00 00 00 r0 = 0
      34:       95 00 00 00 00 00 00 00 exit

Disassembly of section .relkprobe/sys_execve:

0000000000000000 <.relkprobe/sys_execve>:
       0:       98 00 00 00 00 00 00 00 <unknown>
       1:       01 00 00 00 06 00 00 00 <unknown>
       2:       d8 00 00 00 00 00 00 00 <unknown>
       3:       01 00 00 00 06 00 00 00 <unknown>

Disassembly of section license:

0000000000000000 <__license>:
       0:       44 75 61 6c 20 4d 49 54 w5 |= 1414090016
       1:       2f      <unknown>
       1:       47      <unknown>
       1:       50      <unknown>
       1:       4c      <unknown>
       1:       00      <unknown>

Disassembly of section maps:

0000000000000000 <kprobe_map>:
       0:       02 00 00 00 04 00 00 00 <unknown>
       1:       08 00 00 00 01 00 00 00 <unknown>
       2:       00      <unknown>
       2:       00      <unknown>
       2:       00      <unknown>
       2:       00      <unknown>

Disassembly of section .rodata.str1.16:

0000000000000000 <.rodata.str1.16>:
       0:       48 65 6c 6c 6f 2c 20 42 r0 = *(u16 *)skb[r6]
       1:       50 46 20 57 6f 72 6c 64 r0 = *(u8 *)skb[r4]
       2:       21      <unknown>
       2:       0a      <unknown>
       2:       00      <unknown>

Disassembly of section .eh_frame:

0000000000000000 <.eh_frame>:
       0:       10 00 00 00 00 00 00 00 <unknown>
       1:       01 7a 52 00 08 7c 0b 01 <unknown>
       2:       0c 00 00 00 18 00 00 00 w0 += w0
       3:       18 00 00 00 00 00 00 00 00 00 00 00 18 01 00 00 r0 = 1202590842880 ll
                ...

Disassembly of section .rel.eh_frame:

0000000000000000 <.rel.eh_frame>:
       0:       1c 00 00 00 00 00 00 00 w0 -= w0
       1:       02 00 00 00 02 00 00 00 <unknown>

Disassembly of section .symtab:

0000000000000000 <.symtab>:
                ...
       3:       53 00 00 00 04 00 f1 ff <unknown>
                ...
       6:       03 00 03 00 00 00 00 00 <unknown>
                ...
       9:       83 00 00 00 00 00 03 00 <unknown>
      10:       00 01 00 00 00 00 00 00 <unknown>
                ...
      12:       7c 00 00 00 00 00 03 00 w0 >>= w0
      13:       08 01 00 00 00 00 00 00 <unknown>
                ...
      15:       2d 00 00 00 12 00 03 00 if r0 > r0 goto +0 <.symtab+0x80>
                ...
      17:       18 01 00 00 00 00 00 00 0c 00 00 00 11 00 06 00 r1 = 1688922874707968 ll
                ...
      20:       14 00 00 00 00 00 00 00 w0 -= 0
      21:       3b 00 00 00 11 00 05 00 <unknown>
                ...
      23:       0d 00 00 00 00 00 00 00 <unknown>
```

### BTF形式のも眺めておく
```shell
$ readelf -a kprobe.o
ELF Header:
  Magic:   7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00 
  Class:                             ELF64
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              REL (Relocatable file)
  Machine:                           Linux BPF
  Version:                           0x1
  Entry point address:               0x0
  Start of program headers:          0 (bytes into file)
  Start of section headers:          4976 (bytes into file)
  Flags:                             0x0
  Size of this header:               64 (bytes)
  Size of program headers:           0 (bytes)
  Number of program headers:         0
  Size of section headers:           64 (bytes)
  Number of section headers:         28
  Section header string table index: 1

Section Headers:
  [Nr] Name              Type             Address           Offset
       Size              EntSize          Flags  Link  Info  Align
  [ 0]                   NULL             0000000000000000  00000000
       0000000000000000  0000000000000000           0     0     0
  [ 1] .strtab           STRTAB           0000000000000000  00001238
       0000000000000131  0000000000000000           0     0     1
  [ 2] .text             PROGBITS         0000000000000000  00000040
       0000000000000000  0000000000000000  AX       0     0     4
  [ 3] kprobe/sys_execve PROGBITS         0000000000000000  00000040
       0000000000000118  0000000000000000  AX       0     0     8
  [ 4] .relkprobe/s[...] REL              0000000000000000  00000e48
       0000000000000020  0000000000000010   I      27     3     8
  [ 5] license           PROGBITS         0000000000000000  00000158
       000000000000000d  0000000000000000  WA       0     0     1
  [ 6] .rodata.str1.16   PROGBITS         0000000000000000  00000170
       0000000000000013  0000000000000001 AMS       0     0     16
  [ 7] .maps             PROGBITS         0000000000000000  00000188
       0000000000000020  0000000000000000  WA       0     0     8
  [ 8] .debug_loclists   PROGBITS         0000000000000000  000001a8
       0000000000000058  0000000000000000           0     0     1
  [ 9] .debug_abbrev     PROGBITS         0000000000000000  00000200
       0000000000000107  0000000000000000           0     0     1
  [10] .debug_info       PROGBITS         0000000000000000  00000307
       0000000000000199  0000000000000000           0     0     1
  [11] .rel.debug_info   REL              0000000000000000  00000e68
       0000000000000060  0000000000000010   I      27    10     8
  [12] .debug_rnglists   PROGBITS         0000000000000000  000004a0
       0000000000000019  0000000000000000           0     0     1
  [13] .debug_str_o[...] PROGBITS         0000000000000000  000004b9
       0000000000000078  0000000000000000           0     0     1
  [14] .rel.debug_s[...] REL              0000000000000000  00000ec8
       00000000000001c0  0000000000000010   I      27    13     8
  [15] .debug_str        PROGBITS         0000000000000000  00000531
       0000000000000164  0000000000000001  MS       0     0     1
  [16] .debug_addr       PROGBITS         0000000000000000  00000695
       0000000000000020  0000000000000000           0     0     1
  [17] .rel.debug_addr   REL              0000000000000000  00001088
       0000000000000030  0000000000000010   I      27    16     8
  [18] .BTF              PROGBITS         0000000000000000  000006b8
       0000000000000380  0000000000000000           0     0     4
  [19] .rel.BTF          REL              0000000000000000  000010b8
       0000000000000020  0000000000000010   I      27    18     8
  [20] .BTF.ext          PROGBITS         0000000000000000  00000a38
       00000000000000f0  0000000000000000           0     0     4
  [21] .rel.BTF.ext      REL              0000000000000000  000010d8
       00000000000000c0  0000000000000010   I      27    20     8
  [22] .eh_frame         PROGBITS         0000000000000000  00000b28
       0000000000000030  0000000000000000   A       0     0     8
  [23] .rel.eh_frame     REL              0000000000000000  00001198
       0000000000000010  0000000000000010   I      27    22     8
  [24] .debug_line       PROGBITS         0000000000000000  00000b58
       00000000000000d2  0000000000000000           0     0     1
  [25] .rel.debug_line   REL              0000000000000000  000011a8
       0000000000000090  0000000000000010   I      27    24     8
  [26] .debug_line_str   PROGBITS         0000000000000000  00000c2a
       000000000000009a  0000000000000001  MS       0     0     1
  [27] .symtab           SYMTAB           0000000000000000  00000cc8
       0000000000000180  0000000000000018           1    13     8
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
  L (link order), O (extra OS processing required), G (group), T (TLS),
  C (compressed), x (unknown), o (OS specific), E (exclude),
  D (mbind), p (processor specific)

There are no section groups in this file.

There are no program headers in this file.

There is no dynamic section in this file.

Relocation section '.relkprobe/sys_execve' at offset 0xe48 contains 2 entries:
  Offset          Info           Type           Sym. Value    Sym. Name
000000000098  000e00000001 R_BPF_INSN_64     0000000000000000 kprobe_map
0000000000d8  000e00000001 R_BPF_INSN_64     0000000000000000 kprobe_map

Relocation section '.rel.debug_info' at offset 0xe68 contains 6 entries:
  Offset          Info           Type           Sym. Value    Sym. Name
000000000008  000600000003 R_BPF_INSN_16     0000000000000000 .debug_abbrev
000000000011  000800000003 R_BPF_INSN_16     0000000000000000 .debug_str_offsets
000000000015  000b00000003 R_BPF_INSN_16     0000000000000000 .debug_line
00000000001f  000a00000003 R_BPF_INSN_16     0000000000000000 .debug_addr
000000000023  000700000003 R_BPF_INSN_16     0000000000000000 .debug_rnglists
000000000027  000500000003 R_BPF_INSN_16     0000000000000000 .debug_loclists

Relocation section '.rel.debug_str_offsets' at offset 0xec8 contains 28 entries:
  Offset          Info           Type           Sym. Value    Sym. Name
000000000008  000900000003 R_BPF_INSN_16     0000000000000000 .debug_str
00000000000c  000900000003 R_BPF_INSN_16     0000000000000000 .debug_str
000000000010  000900000003 R_BPF_INSN_16     0000000000000000 .debug_str
000000000014  000900000003 R_BPF_INSN_16     0000000000000000 .debug_str
000000000018  000900000003 R_BPF_INSN_16     0000000000000000 .debug_str
00000000001c  000900000003 R_BPF_INSN_16     0000000000000000 .debug_str
000000000020  000900000003 R_BPF_INSN_16     0000000000000000 .debug_str
000000000024  000900000003 R_BPF_INSN_16     0000000000000000 .debug_str
000000000028  000900000003 R_BPF_INSN_16     0000000000000000 .debug_str
00000000002c  000900000003 R_BPF_INSN_16     0000000000000000 .debug_str
000000000030  000900000003 R_BPF_INSN_16     0000000000000000 .debug_str
000000000034  000900000003 R_BPF_INSN_16     0000000000000000 .debug_str
000000000038  000900000003 R_BPF_INSN_16     0000000000000000 .debug_str
00000000003c  000900000003 R_BPF_INSN_16     0000000000000000 .debug_str
000000000040  000900000003 R_BPF_INSN_16     0000000000000000 .debug_str
000000000044  000900000003 R_BPF_INSN_16     0000000000000000 .debug_str
000000000048  000900000003 R_BPF_INSN_16     0000000000000000 .debug_str
00000000004c  000900000003 R_BPF_INSN_16     0000000000000000 .debug_str
000000000050  000900000003 R_BPF_INSN_16     0000000000000000 .debug_str
000000000054  000900000003 R_BPF_INSN_16     0000000000000000 .debug_str
000000000058  000900000003 R_BPF_INSN_16     0000000000000000 .debug_str
00000000005c  000900000003 R_BPF_INSN_16     0000000000000000 .debug_str
000000000060  000900000003 R_BPF_INSN_16     0000000000000000 .debug_str
000000000064  000900000003 R_BPF_INSN_16     0000000000000000 .debug_str
000000000068  000900000003 R_BPF_INSN_16     0000000000000000 .debug_str
00000000006c  000900000003 R_BPF_INSN_16     0000000000000000 .debug_str
000000000070  000900000003 R_BPF_INSN_16     0000000000000000 .debug_str
000000000074  000900000003 R_BPF_INSN_16     0000000000000000 .debug_str

Relocation section '.rel.debug_addr' at offset 0x1088 contains 3 entries:
  Offset          Info           Type           Sym. Value    Sym. Name
000000000008  000f00000002 R_BPF_INSN_32     0000000000000000 __license
000000000010  000e00000002 R_BPF_INSN_32     0000000000000000 kprobe_map
000000000018  000200000002 R_BPF_INSN_32     0000000000000000 kprobe/sys_execve

Relocation section '.rel.BTF' at offset 0x10b8 contains 2 entries:
  Offset          Info           Type           Sym. Value    Sym. Name
00000000017c  000e00000004 R_BPF_INSN_DISP16 0000000000000000 kprobe_map
000000000194  000f00000004 R_BPF_INSN_DISP16 0000000000000000 __license

Relocation section '.rel.BTF.ext' at offset 0x10d8 contains 12 entries:
  Offset          Info           Type           Sym. Value    Sym. Name
00000000002c  000200000004 R_BPF_INSN_DISP16 0000000000000000 kprobe/sys_execve
000000000040  000200000004 R_BPF_INSN_DISP16 0000000000000000 kprobe/sys_execve
000000000050  000200000004 R_BPF_INSN_DISP16 0000000000000000 kprobe/sys_execve
000000000060  000200000004 R_BPF_INSN_DISP16 0000000000000000 kprobe/sys_execve
000000000070  000200000004 R_BPF_INSN_DISP16 0000000000000000 kprobe/sys_execve
000000000080  000200000004 R_BPF_INSN_DISP16 0000000000000000 kprobe/sys_execve
000000000090  000200000004 R_BPF_INSN_DISP16 0000000000000000 kprobe/sys_execve
0000000000a0  000200000004 R_BPF_INSN_DISP16 0000000000000000 kprobe/sys_execve
0000000000b0  000200000004 R_BPF_INSN_DISP16 0000000000000000 kprobe/sys_execve
0000000000c0  000200000004 R_BPF_INSN_DISP16 0000000000000000 kprobe/sys_execve
0000000000d0  000200000004 R_BPF_INSN_DISP16 0000000000000000 kprobe/sys_execve
0000000000e0  000200000004 R_BPF_INSN_DISP16 0000000000000000 kprobe/sys_execve

Relocation section '.rel.eh_frame' at offset 0x1198 contains 1 entry:
  Offset          Info           Type           Sym. Value    Sym. Name
00000000001c  000200000002 R_BPF_INSN_32     0000000000000000 kprobe/sys_execve

Relocation section '.rel.debug_line' at offset 0x11a8 contains 9 entries:
  Offset          Info           Type           Sym. Value    Sym. Name
000000000022  000c00000003 R_BPF_INSN_16     0000000000000000 .debug_line_str
000000000026  000c00000003 R_BPF_INSN_16     0000000000000000 .debug_line_str
00000000002a  000c00000003 R_BPF_INSN_16     0000000000000000 .debug_line_str
00000000002e  000c00000003 R_BPF_INSN_16     0000000000000000 .debug_line_str
00000000003a  000c00000003 R_BPF_INSN_16     0000000000000000 .debug_line_str
00000000004f  000c00000003 R_BPF_INSN_16     0000000000000000 .debug_line_str
000000000064  000c00000003 R_BPF_INSN_16     0000000000000000 .debug_line_str
000000000079  000c00000003 R_BPF_INSN_16     0000000000000000 .debug_line_str
000000000093  000200000002 R_BPF_INSN_32     0000000000000000 kprobe/sys_execve

The decoding of unwind sections for machine type Linux BPF is not currently supported.

Symbol table '.symtab' contains 16 entries:
   Num:    Value          Size Type    Bind   Vis      Ndx Name
     0: 0000000000000000     0 NOTYPE  LOCAL  DEFAULT  UND 
     1: 0000000000000000     0 FILE    LOCAL  DEFAULT  ABS kprobe.c
     2: 0000000000000000     0 SECTION LOCAL  DEFAULT    3 kprobe/sys_execve
     3: 0000000000000100     0 NOTYPE  LOCAL  DEFAULT    3 LBB0_2
     4: 0000000000000108     0 NOTYPE  LOCAL  DEFAULT    3 LBB0_3
     5: 0000000000000000     0 SECTION LOCAL  DEFAULT    8 .debug_loclists
     6: 0000000000000000     0 SECTION LOCAL  DEFAULT    9 .debug_abbrev
     7: 0000000000000000     0 SECTION LOCAL  DEFAULT   12 .debug_rnglists
     8: 0000000000000000     0 SECTION LOCAL  DEFAULT   13 .debug_str_offsets
     9: 0000000000000000     0 SECTION LOCAL  DEFAULT   15 .debug_str
    10: 0000000000000000     0 SECTION LOCAL  DEFAULT   16 .debug_addr
    11: 0000000000000000     0 SECTION LOCAL  DEFAULT   24 .debug_line
    12: 0000000000000000     0 SECTION LOCAL  DEFAULT   26 .debug_line_str
    13: 0000000000000000   280 FUNC    GLOBAL DEFAULT    3 kprobe_execve
    14: 0000000000000000    32 OBJECT  GLOBAL DEFAULT    7 kprobe_map
    15: 0000000000000000    13 OBJECT  GLOBAL DEFAULT    5 __license

No version information found in this file.
readelf: Warning: unable to apply unsupported reloc type 3 to section .debug_info
readelf: Warning: Unrecognized form: 0x22
readelf: Warning: Unrecognized form: 0x22
readelf: Warning: Unrecognized form: 0x22
readelf: Warning: Unrecognized form: 0x23
```

```shell
$ llvm-objdump -D kprobe.o

kprobe.o:       file format elf64-bpf

Disassembly of section .strtab:

0000000000000000 <.strtab>:
       0:       00 2e 64 65 62 75 67 5f <unknown>
       1:       61 62 62 72 65 76 00 2e r2 = *(u32 *)(r6 + 29282)
       2:       74 65 78 74 00 2e 72 65 w5 >>= 1701981696
       3:       6c 2e 42 54 46 2e 65 78 <unknown>
       4:       74 00 2e 64 65 62 75 67 w0 >>= 1735746149
       5:       5f 72 6e 67 6c 69 73 74 r2 &= r7
       6:       73 00 2e 64 65 62 75 67 *(u8 *)(r0 + 25646) = r0
       7:       5f 6c 6f 63 6c 69 73 74 <unknown>
       8:       73 00 2e 72 65 6c 2e 64 *(u8 *)(r0 + 29230) = r0
       9:       65 62 75 67 5f 73 74 72 if r2 s> 1920234335 goto +26485 <.strtab+0x33bf8>
      10:       5f 6f 66 66 73 65 74 73 <unknown>
      11:       00 2e 6d 61 70 73 00 2e <unknown>
      12:       64 65 62 75 67 5f 73 74 w5 <<= 1953718119
      13:       72 00 2e 64 65 62 75 67 <unknown>
      14:       5f 6c 69 6e 65 5f 73 74 <unknown>
      15:       72 00 2e 72 65 6c 2e 64 <unknown>
      16:       65 62 75 67 5f 61 64 64 if r2 s> 1684300127 goto +26485 <.strtab+0x33c30>
      17:       72 00 6b 70 72 6f 62 65 <unknown>
      18:       5f 6d 61 70 00 2e 72 65 <unknown>
      19:       6c 2e 64 65 62 75 67 5f <unknown>
      20:       69 6e 66 6f 00 2e 72 65 <unknown>
      21:       6c 6b 70 72 6f 62 65 2f w11 <<= w6
      22:       73 79 73 5f 65 78 65 63 *(u8 *)(r9 + 24435) = r7
      23:       76 65 00 6b 70 72 6f 62 if w5 s>= 1651470960 goto +27392 <.strtab+0x358c0>
      24:       65 5f 65 78 65 63 76 65 <unknown>
      25:       00 5f 5f 6c 69 63 65 6e <unknown>
      26:       73 65 00 2e 72 65 6c 2e *(u8 *)(r5 + 11776) = r6
      27:       64 65 62 75 67 5f 6c 69 w5 <<= 1768709991
      28:       6e 65 00 2e 72 65 6c 2e if w5 s> w6 goto +11776 <.strtab+0x170e8>
      29:       65 68 5f 66 72 61 6d 65 if r8 s> 1701667186 goto +26207 <.strtab+0x333e8>
      30:       00 6b 70 72 6f 62 65 2e <unknown>
      31:       63 00 2e 73 74 72 74 61 *(u32 *)(r0 + 29486) = r0
      32:       62 00 2e 73 79 6d 74 61 <unknown>
      33:       62 00 2e 72 65 6c 2e 42 <unknown>
      34:       54 46 00 2e 72 6f 64 61 w6 &= 1633972082
      35:       74 61 2e 73 74 72 31 2e w1 >>= 774992500
      36:       31 36 00 4c 42 42 30 5f <unknown>
      37:       33 00 4c 42 42 30 5f 32 <unknown>
      38:       00      <unknown>

Disassembly of section kprobe/sys_execve:

0000000000000000 <kprobe_execve>:
       0:       b7 01 00 00 21 0a 00 00 r1 = 2593
       1:       6b 1a f0 ff 00 00 00 00 *(u16 *)(r10 - 16) = r1
       2:       18 01 00 00 50 46 20 57 00 00 00 00 6f 72 6c 64 r1 = 7236284523806213712 ll
       4:       7b 1a e8 ff 00 00 00 00 *(u64 *)(r10 - 24) = r1
       5:       18 01 00 00 48 65 6c 6c 00 00 00 00 6f 2c 20 42 r1 = 4764857262830019912 ll
       7:       7b 1a e0 ff 00 00 00 00 *(u64 *)(r10 - 32) = r1
       8:       b7 06 00 00 00 00 00 00 r6 = 0
       9:       73 6a f2 ff 00 00 00 00 *(u8 *)(r10 - 14) = r6
      10:       bf a1 00 00 00 00 00 00 r1 = r10
      11:       07 01 00 00 e0 ff ff ff r1 += -32
      12:       b7 02 00 00 13 00 00 00 r2 = 19
      13:       85 00 00 00 06 00 00 00 call 6
      14:       63 6a dc ff 00 00 00 00 *(u32 *)(r10 - 36) = r6
      15:       b7 06 00 00 01 00 00 00 r6 = 1
      16:       7b 6a e0 ff 00 00 00 00 *(u64 *)(r10 - 32) = r6
      17:       bf a2 00 00 00 00 00 00 r2 = r10
      18:       07 02 00 00 dc ff ff ff r2 += -36
      19:       18 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 r1 = 0 ll
      21:       85 00 00 00 01 00 00 00 call 1
      22:       55 00 09 00 00 00 00 00 if r0 != 0 goto +9 <LBB0_2>
      23:       bf a2 00 00 00 00 00 00 r2 = r10
      24:       07 02 00 00 dc ff ff ff r2 += -36
      25:       bf a3 00 00 00 00 00 00 r3 = r10
      26:       07 03 00 00 e0 ff ff ff r3 += -32
      27:       18 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 r1 = 0 ll
      29:       b7 04 00 00 00 00 00 00 r4 = 0
      30:       85 00 00 00 02 00 00 00 call 2
      31:       05 00 01 00 00 00 00 00 goto +1 <LBB0_3>

0000000000000100 <LBB0_2>:
      32:       db 60 00 00 00 00 00 00 lock *(u64 *)(r0 + 0) += r6

0000000000000108 <LBB0_3>:
      33:       b7 00 00 00 00 00 00 00 r0 = 0
      34:       95 00 00 00 00 00 00 00 exit

Disassembly of section .relkprobe/sys_execve:

0000000000000000 <.relkprobe/sys_execve>:
       0:       98 00 00 00 00 00 00 00 <unknown>
       1:       01 00 00 00 0e 00 00 00 <unknown>
       2:       d8 00 00 00 00 00 00 00 <unknown>
       3:       01 00 00 00 0e 00 00 00 <unknown>

Disassembly of section license:

0000000000000000 <__license>:
       0:       44 75 61 6c 20 4d 49 54 w5 |= 1414090016
       1:       2f      <unknown>
       1:       47      <unknown>
       1:       50      <unknown>
       1:       4c      <unknown>
       1:       00      <unknown>

Disassembly of section .rodata.str1.16:

0000000000000000 <.rodata.str1.16>:
       0:       48 65 6c 6c 6f 2c 20 42 r0 = *(u16 *)skb[r6]
       1:       50 46 20 57 6f 72 6c 64 r0 = *(u8 *)skb[r4]
       2:       21      <unknown>
       2:       0a      <unknown>
       2:       00      <unknown>

Disassembly of section .maps:

0000000000000000 <kprobe_map>:
                ...

Disassembly of section .debug_loclists:

0000000000000000 <.debug_loclists>:
       0:       54 00 00 00 05 00 08 00 w0 &= 524293
       1:       03 00 00 00 0c 00 00 00 <unknown>
       2:       1c 00 00 00 35 00 00 00 w0 -= w0
       3:       04 70 88 01 02 30 9f 04 w0 += 77541378
       4:       88 01 98 02 02 7a 0c 00 <unknown>
       5:       04 80 01 b8 01 02 31 9f w0 += -1624178175
       6:       04 b8 01 80 02 02 7a 10 w8 += 276431362
       7:       04 80 02 88 02 02 31 9f w0 += -1624178174
       8:       00 04 88 01 b0 01 02 30 <unknown>
       9:       9f 04 b0 01 f8 01 01 50 <unknown>
      10:       04 80 02 88 02 01 50 00 w0 += 5243138

Disassembly of section .debug_abbrev:

0000000000000000 <.debug_abbrev>:
       0:       01 11 01 25 25 13 05 03 <unknown>
       1:       25 72 17 10 17 1b 25 11 if r2 > 287644439 goto +4119 <.debug_abbrev+0x80c8>
       2:       1b 12 06 73 17 74 17 8c <unknown>
       3:       01 17 00 00 02 34 00 03 <unknown>
       4:       25 49 13 3f 19 3a 0b 3b if r9 > 990591513 goto +16147 <.debug_abbrev+0x1f8c0>
       5:       0b 02 18 00 00 03 01 01 <unknown>
       6:       49 13 00 00 04 21 00 49 <unknown>
       7:       13 37 0b 00 00 05 24 00 <unknown>
       8:       03 25 3e 0b 0b 0b 00 00 <unknown>
       9:       06 24 00 03 25 0b 0b 3e <unknown>
      10:       0b 00 00 07 13 01 0b 0b <unknown>
      11:       3a 0b 3b 0b 00 00 08 0d <unknown>
      12:       00 03 25 49 13 3a 0b 3b <unknown>
      13:       0b 38 0b 00 00 09 0f 00 <unknown>
      14:       49 13 00 00 0a 16 00 49 <unknown>
      15:       13 03 25 3a 0b 3b 0b 00 <unknown>
      16:       00 0b 34 00 03 25 49 13 <unknown>
      17:       3a 0b 3b 0b 00 00 0c 15 <unknown>
      18:       01 49 13 27 19 00 00 0d <unknown>
      19:       05 00 49 13 00 00 0e 18 goto +4937 <.debug_abbrev+0x9ae8>
      20:       00 00 00 0f 26 00 49 13 <unknown>
      21:       00 00 10 0f 00 00 00 11 <unknown>
      22:       26 00 00 00 12 04 01 49 if w0 > 1224803346 goto +0 <.debug_abbrev+0xb8>
      23:       13 0b 0b 3a 0b 3b 05 00 <unknown>
      24:       00 13 28 00 03 25 1c 0f <unknown>
      25:       00 00 14 2e 01 11 1b 12 <unknown>
      26:       06 40 18 7a 19 03 25 3a <unknown>
      27:       0b 3b 0b 49 13 3f 19 00 <unknown>
      28:       00 15 34 00 02 22 03 25 <unknown>
      29:       3a 0b 3b 0b 49 13 00 00 <unknown>
      30:       16 0b 01 55 23 00 00 17 if w11 == 385876003 goto +21761 <.debug_abbrev+0x2a900>
      31:       34 00 02 18 03 25 3a 0b w0 /= 188359939
      32:       3b      <unknown>
      32:       0b      <unknown>
      32:       49      <unknown>
      32:       13      <unknown>
      32:       00      <unknown>
      32:       00      <unknown>
      32:       00      <unknown>

Disassembly of section .debug_info:

0000000000000000 <.debug_info>:
       0:       95 01 00 00 05 00 01 08 <unknown>
       1:       00 00 00 00 01 00 0c 00 <unknown>
       2:       01 08 00 00 00 00 00 00 <unknown>
       3:       00 02 02 18 01 00 00 08 <unknown>
       4:       00 00 00 0c 00 00 00 0c <unknown>
       5:       00 00 00 02 03 36 00 00 <unknown>
       6:       00 00 04 02 a1 00 03 42 <unknown>
       7:       00 00 00 04 46 00 00 00 <unknown>
       8:       0d 00 05 04 06 01 06 05 <unknown>
       9:       08 07 02 06 55 00 00 00 <unknown>
      10:       00 12 02 a1 01 07 20 00 <unknown>
      11:       0c 08 07 7e 00 00 00 00 w8 += w0
      12:       0e 00 08 09 93 00 00 00 <unknown>
      13:       00 0f 08 08 0c a4 00 00 <unknown>
      14:       00 00 10 10 08 0f b5 00 <unknown>
      15:       00 00 00 11 18 00 09 83 <unknown>
      16:       00 00 00 03 8f 00 00 00 <unknown>
      17:       04 46 00 00 00 02 00 05 w6 += 83886592
      18:       08 05 04 09 98 00 00 00 <unknown>
      19:       0a a0 00 00 00 0b 01 1b <unknown>
      20:       05 0a 07 04 09 a9 00 00 goto +1031 <.debug_info+0x20e0>
      21:       00 0a b1 00 00 00 0e 01 <unknown>
      22:       1f 05 0d 07 08 09 ba 00 r5 -= r0
      23:       00 00 03 8f 00 00 00 04 <unknown>
      24:       46 00 00 00 01 00 0b 10 <unknown>
      25:       ce 00 00 00 02 ab 09 d3 if w0 s< w0 goto +0 <.debug_info+0xd0>
      26:       00 00 00 0c e4 00 00 00 <unknown>
      27:       0d e8 00 00 00 0d 98 00 <unknown>
      28:       00 00 0e 00 05 11 05 08 <unknown>
      29:       09 ed 00 00 00 0f 42 00 <unknown>
      30:       00 00 0b 12 fa 00 00 00 <unknown>
      31:       02 32 09 ff 00 00 00 0c <unknown>
      32:       0f 01 00 00 0d 0f 01 00 r1 += r0
      33:       00 0d 10 01 00 00 00 10 <unknown>
      34:       09 15 01 00 00 11 0b 13 <unknown>
      35:       1e 01 00 00 02 48 09 23 if w1 == w0 goto +0 <.debug_info+0x120>
      36:       01 00 00 0c e4 00 00 00 <unknown>
      37:       0d 0f 01 00 00 0d 10 01 <unknown>
      38:       00 00 0d 10 01 00 00 0d <unknown>
      39:       a9 00 00 00 00 12 a0 00 <unknown>
      40:       00 00 04 03 90 04 13 14 <unknown>
      41:       00 13 15 01 13 16 02 13 <unknown>
      42:       17 04 00 14 02 18 01 00 r4 -= 71682
      43:       00 01 5a 18 00 15 8f 00 <unknown>
      44:       00 00 15 00 09 00 18 98 <unknown>
      45:       00 00 00 15 01 1a 00 19 <unknown>
      46:       a9 00 00 00 15 02 1b 00 <unknown>
      47:       19 a4 00 00 00 16 00 17 <unknown>
      48:       02 91 10 19 00 17 8c 01 <unknown>
      49:       00 00 00 00 03 42 00 00 <unknown>
      50:       00 04 46 00 00 00 13 00 <unknown>
      51:       00      <unknown>

Disassembly of section .rel.debug_info:

0000000000000000 <.rel.debug_info>:
       0:       08 00 00 00 00 00 00 00 <unknown>
       1:       03 00 00 00 06 00 00 00 <unknown>
       2:       11 00 00 00 00 00 00 00 <unknown>
       3:       03 00 00 00 08 00 00 00 <unknown>
       4:       15 00 00 00 00 00 00 00 if r0 == 0 goto +0 <.rel.debug_info+0x28>
       5:       03 00 00 00 0b 00 00 00 <unknown>
       6:       1f 00 00 00 00 00 00 00 r0 -= r0
       7:       03 00 00 00 0a 00 00 00 <unknown>
       8:       23 00 00 00 00 00 00 00 <unknown>
       9:       03 00 00 00 07 00 00 00 <unknown>
      10:       27 00 00 00 00 00 00 00 r0 *= 0
      11:       03 00 00 00 05 00 00 00 <unknown>

Disassembly of section .debug_rnglists:

0000000000000000 <.debug_rnglists>:
       0:       15 00 00 00 05 00 08 00 if r0 == 524293 goto +0 <.debug_rnglists+0x8>
       1:       01 00 00 00 04 00 00 00 <unknown>
       2:       04 08 70 04 90 01 98 01 w8 += 26739088
       3:       00      <unknown>

Disassembly of section .debug_str_offsets:

0000000000000000 <.debug_str_offsets>:
       0:       74 00 00 00 05 00 00 00 w0 >>= 5
       1:       00 00 00 00 27 00 00 00 <unknown>
       2:       30 00 00 00 61 00 00 00 r0 = *(u8 *)skb[97]
       3:       6b 00 00 00 70 00 00 00 *(u16 *)(r0 + 0) = r0
       4:       84 00 00 00 8f 00 00 00 w0 = -w0
       5:       94 00 00 00 98 00 00 00 <unknown>
       6:       9c 00 00 00 a9 00 00 00 <unknown>
       7:       af 00 00 00 b5 00 00 00 r0 ^= r0
       8:       c8 00 00 00 ce 00 00 00 <unknown>
       9:       da 00 00 00 eb 00 00 00 <unknown>
      10:       f0 00 00 00 04 01 00 00 <unknown>
      11:       18 01 00 00 20 01 00 00 2c 01 00 00 36 01 00 00 r1 = 1331439862048 ll
      13:       41 01 00 00 4f 01 00 00 <unknown>
      14:       57 01 00 00 5f 01 00 00 r1 &= 351

Disassembly of section .rel.debug_str_offsets:

0000000000000000 <.rel.debug_str_offsets>:
       0:       08 00 00 00 00 00 00 00 <unknown>
       1:       03 00 00 00 09 00 00 00 <unknown>
       2:       0c 00 00 00 00 00 00 00 w0 += w0
       3:       03 00 00 00 09 00 00 00 <unknown>
       4:       10 00 00 00 00 00 00 00 <unknown>
       5:       03 00 00 00 09 00 00 00 <unknown>
       6:       14 00 00 00 00 00 00 00 w0 -= 0
       7:       03 00 00 00 09 00 00 00 <unknown>
       8:       18 00 00 00 00 00 00 00 03 00 00 00 09 00 00 00 r0 = 38654705664 ll
      10:       1c 00 00 00 00 00 00 00 w0 -= w0
      11:       03 00 00 00 09 00 00 00 <unknown>
      12:       20 00 00 00 00 00 00 00 r0 = *(u32 *)skb[0]
      13:       03 00 00 00 09 00 00 00 <unknown>
      14:       24 00 00 00 00 00 00 00 w0 *= 0
      15:       03 00 00 00 09 00 00 00 <unknown>
      16:       28 00 00 00 00 00 00 00 r0 = *(u16 *)skb[0]
      17:       03 00 00 00 09 00 00 00 <unknown>
      18:       2c 00 00 00 00 00 00 00 w0 *= w0
      19:       03 00 00 00 09 00 00 00 <unknown>
      20:       30 00 00 00 00 00 00 00 r0 = *(u8 *)skb[0]
      21:       03 00 00 00 09 00 00 00 <unknown>
      22:       34 00 00 00 00 00 00 00 w0 /= 0
      23:       03 00 00 00 09 00 00 00 <unknown>
      24:       38 00 00 00 00 00 00 00 <unknown>
      25:       03 00 00 00 09 00 00 00 <unknown>
      26:       3c 00 00 00 00 00 00 00 w0 /= w0
      27:       03 00 00 00 09 00 00 00 <unknown>
      28:       40 00 00 00 00 00 00 00 r0 = *(u32 *)skb[r0]
      29:       03 00 00 00 09 00 00 00 <unknown>
      30:       44 00 00 00 00 00 00 00 w0 |= 0
      31:       03 00 00 00 09 00 00 00 <unknown>
      32:       48 00 00 00 00 00 00 00 r0 = *(u16 *)skb[r0]
      33:       03 00 00 00 09 00 00 00 <unknown>
      34:       4c 00 00 00 00 00 00 00 w0 |= w0
      35:       03 00 00 00 09 00 00 00 <unknown>
      36:       50 00 00 00 00 00 00 00 r0 = *(u8 *)skb[r0]
      37:       03 00 00 00 09 00 00 00 <unknown>
      38:       54 00 00 00 00 00 00 00 w0 &= 0
      39:       03 00 00 00 09 00 00 00 <unknown>
      40:       58 00 00 00 00 00 00 00 <unknown>
      41:       03 00 00 00 09 00 00 00 <unknown>
      42:       5c 00 00 00 00 00 00 00 w0 &= w0
      43:       03 00 00 00 09 00 00 00 <unknown>
      44:       60 00 00 00 00 00 00 00 <unknown>
      45:       03 00 00 00 09 00 00 00 <unknown>
      46:       64 00 00 00 00 00 00 00 w0 <<= 0
      47:       03 00 00 00 09 00 00 00 <unknown>
      48:       68 00 00 00 00 00 00 00 <unknown>
      49:       03 00 00 00 09 00 00 00 <unknown>
      50:       6c 00 00 00 00 00 00 00 w0 <<= w0
      51:       03 00 00 00 09 00 00 00 <unknown>
      52:       70 00 00 00 00 00 00 00 <unknown>
      53:       03 00 00 00 09 00 00 00 <unknown>
      54:       74 00 00 00 00 00 00 00 w0 >>= 0
      55:       03 00 00 00 09 00 00 00 <unknown>

Disassembly of section .debug_str:

0000000000000000 <.debug_str>:
       0:       55 62 75 6e 74 75 20 63 if r2 != 1663071604 goto +28277 <.debug_str+0x373b0>
       1:       6c 61 6e 67 20 76 65 72 w1 <<= w6
       2:       73 69 6f 6e 20 31 34 2e *(u8 *)(r9 + 28271) = r6
       3:       30 2e 30 2d 31 75 62 75 r0 = *(u8 *)skb[1969386801]
       4:       6e 74 75 31 2e 31 00 6b if w4 s> w7 goto +12661 <.debug_str+0x18bd0>
       5:       70 72 6f 62 65 2e 63 00 <unknown>
       6:       2f 68 6f 6d 65 2f 75 62 r8 *= r6
       7:       75 6e 74 75 2f 70 72 69 <unknown>
       8:       76 61 74 65 2f 70 65 72 if w1 s>= 1919250479 goto +25972 <.debug_str+0x32be8>
       9:       6c 2d 65 62 70 66 2f 73 <unknown>
      10:       61 6d 70 6c 65 2f 6b 70 <unknown>
      11:       72 6f 62 65 5f 62 74 66 <unknown>
      12:       00 5f 5f 6c 69 63 65 6e <unknown>
      13:       73 65 00 63 68 61 72 00 *(u8 *)(r5 + 25344) = r6
      14:       5f 5f 41 52 52 41 59 5f <unknown>
      15:       53 49 5a 45 5f 54 59 50 <unknown>
      16:       45 5f 5f 00 6b 70 72 6f <unknown>
      17:       62 65 5f 6d 61 70 00 74 <unknown>
      18:       79 70 65 00 69 6e 74 00 r0 = *(u64 *)(r7 + 101)
      19:       6b 65 79 00 75 6e 73 69 *(u16 *)(r5 + 121) = r6
      20:       67 6e 65 64 20 69 6e 74 <unknown>
      21:       00 5f 5f 75 33 32 00 76 <unknown>
      22:       61 6c 75 65 00 75 6e 73 <unknown>
      23:       69 67 6e 65 64 20 6c 6f r7 = *(u16 *)(r6 + 25966)
      24:       6e 67 20 6c 6f 6e 67 00 if w7 s> w6 goto +27680 <.debug_str+0x361c8>
      25:       5f 5f 75 36 34 00 6d 61 <unknown>
      26:       78 5f 65 6e 74 72 69 65 <unknown>
      27:       73 00 62 70 66 5f 74 72 *(u8 *)(r0 + 28770) = r0
      28:       61 63 65 5f 70 72 69 6e r3 = *(u32 *)(r6 + 24421)
      29:       74 6b 00 6c 6f 6e 67 00 w11 >>= 6778479
      30:       62 70 66 5f 6d 61 70 5f <unknown>
      31:       6c 6f 6f 6b 75 70 5f 65 <unknown>
      32:       6c 65 6d 00 62 70 66 5f w5 <<= w6
      33:       6d 61 70 5f 75 70 64 61 if r1 s> r6 goto +24432 <.debug_str+0x2fc90>
      34:       74 65 5f 65 6c 65 6d 00 w5 >>= 7169388
      35:       42 50 46 5f 41 4e 59 00 <unknown>
      36:       42 50 46 5f 4e 4f 45 58 <unknown>
      37:       49 53 54 00 42 50 46 5f <unknown>
      38:       45 58 49 53 54 00 42 50 <unknown>
      39:       46 5f 46 5f 4c 4f 43 4b <unknown>
      40:       00 6b 70 72 6f 62 65 5f <unknown>
      41:       65 78 65 63 76 65 00 5f if r8 s> 1593861494 goto +25445 <.debug_str+0x31c78>
      42:       5f 5f 5f 66 6d 74 00 69 <unknown>
      43:       6e 69 74 76 61 6c 00 76 if w9 s> w6 goto +30324 <.debug_str+0x3b500>
      44:       61      <unknown>
      44:       6c      <unknown>
      44:       70      <unknown>
      44:       00      <unknown>

Disassembly of section .debug_addr:

0000000000000000 <.debug_addr>:
       0:       1c 00 00 00 05 00 08 00 w0 -= w0
                ...

Disassembly of section .rel.debug_addr:

0000000000000000 <.rel.debug_addr>:
       0:       08 00 00 00 00 00 00 00 <unknown>
       1:       02 00 00 00 0f 00 00 00 <unknown>
       2:       10 00 00 00 00 00 00 00 <unknown>
       3:       02 00 00 00 0e 00 00 00 <unknown>
       4:       18 00 00 00 00 00 00 00 02 00 00 00 02 00 00 00 r0 = 8589934592 ll

Disassembly of section .BTF:

0000000000000000 <.BTF>:
       0:       9f eb 01 00 18 00 00 00 <unknown>
       1:       00 00 00 00 84 01 00 00 <unknown>
       2:       84 01 00 00 e4 01 00 00 w1 = -w1
       3:       00 00 00 00 00 00 00 02 <unknown>
       4:       03 00 00 00 01 00 00 00 <unknown>
       5:       00 00 00 01 04 00 00 00 <unknown>
       6:       20 00 00 01 00 00 00 00 r0 = *(u32 *)skb[0]
       7:       00 00 00 03 00 00 00 00 <unknown>
       8:       02 00 00 00 04 00 00 00 <unknown>
       9:       02 00 00 00 05 00 00 00 <unknown>
      10:       00 00 00 01 04 00 00 00 <unknown>
      11:       20 00 00 00 00 00 00 00 r0 = *(u32 *)skb[0]
      12:       00 00 00 02 06 00 00 00 <unknown>
      13:       19 00 00 00 00 00 00 08 <unknown>
      14:       07 00 00 00 1f 00 00 00 r0 += 31
      15:       00 00 00 01 04 00 00 00 <unknown>
      16:       20 00 00 00 00 00 00 00 r0 = *(u32 *)skb[0]
      17:       00 00 00 02 09 00 00 00 <unknown>
      18:       2c 00 00 00 00 00 00 08 w0 *= w0
      19:       0a 00 00 00 32 00 00 00 <unknown>
      20:       00 00 00 01 08 00 00 00 <unknown>
      21:       40 00 00 00 00 00 00 00 r0 = *(u32 *)skb[r0]
      22:       00 00 00 02 0c 00 00 00 <unknown>
      23:       00 00 00 00 00 00 00 03 <unknown>
      24:       00 00 00 00 02 00 00 00 <unknown>
      25:       04 00 00 00 01 00 00 00 w0 += 1
      26:       00 00 00 00 04 00 00 04 <unknown>
      27:       20 00 00 00 45 00 00 00 r0 = *(u32 *)skb[69]
      28:       01 00 00 00 00 00 00 00 <unknown>
      29:       4a 00 00 00 05 00 00 00 <unknown>
      30:       40 00 00 00 4e 00 00 00 r0 = *(u32 *)skb[r0]
      31:       08 00 00 00 80 00 00 00 <unknown>
      32:       54 00 00 00 0b 00 00 00 w0 &= 11
      33:       c0 00 00 00 60 00 00 00 <unknown>
      34:       00 00 00 0e 0d 00 00 00 <unknown>
      35:       01 00 00 00 00 00 00 00 <unknown>
      36:       00 00 00 0d 02 00 00 00 <unknown>
      37:       6b 00 00 00 01 00 00 0c *(u16 *)(r0 + 0) = r0
      38:       0f 00 00 00 c7 01 00 00 r0 += r0
      39:       00 00 00 01 01 00 00 00 <unknown>
      40:       08 00 00 01 00 00 00 00 <unknown>
      41:       00 00 00 03 00 00 00 00 <unknown>
      42:       11 00 00 00 04 00 00 00 <unknown>
      43:       0d 00 00 00 cc 01 00 00 <unknown>
      44:       00 00 00 0e 12 00 00 00 <unknown>
      45:       01 00 00 00 d6 01 00 00 <unknown>
      46:       01 00 00 0f 00 00 00 00 <unknown>
      47:       0e 00 00 00 00 00 00 00 <unknown>
      48:       20 00 00 00 dc 01 00 00 r0 = *(u32 *)skb[476]
      49:       01 00 00 0f 00 00 00 00 <unknown>
      50:       13 00 00 00 00 00 00 00 <unknown>
      51:       0d 00 00 00 00 69 6e 74 <unknown>
      52:       00 5f 5f 41 52 52 41 59 <unknown>
      53:       5f 53 49 5a 45 5f 54 59 r3 &= r5
      54:       50 45 5f 5f 00 5f 5f 75 r0 = *(u8 *)skb[r4]
      55:       33 32 00 75 6e 73 69 67 <unknown>
      56:       6e 65 64 20 69 6e 74 00 if w5 s> w6 goto +8292 <.BTF+0x104e8>
      57:       5f 5f 75 36 34 00 75 6e <unknown>
      58:       73 69 67 6e 65 64 20 6c *(u8 *)(r9 + 28263) = r6
      59:       6f 6e 67 20 6c 6f 6e 67 <unknown>
      60:       00 74 79 70 65 00 6b 65 <unknown>
      61:       79 00 76 61 6c 75 65 00 r0 = *(u64 *)(r0 + 24950)
      62:       6d 61 78 5f 65 6e 74 72 if r1 s> r6 goto +24440 <.BTF+0x2fdb8>
      63:       69 65 73 00 6b 70 72 6f r5 = *(u16 *)(r6 + 115)
      64:       62 65 5f 6d 61 70 00 6b <unknown>
      65:       70 72 6f 62 65 5f 65 78 <unknown>
      66:       65 63 76 65 00 6b 70 72 if r3 s> 1919970048 goto +25974 <.BTF+0x32dc8>
      67:       6f 62 65 2f 73 79 73 5f r2 <<= r6
      68:       65 78 65 63 76 65 00 2f if r8 s> 788555126 goto +25445 <.BTF+0x31d50>
      69:       68 6f 6d 65 2f 75 62 75 <unknown>
      70:       6e 74 75 2f 70 72 69 76 if w4 s> w7 goto +12149 <.BTF+0x17de0>
      71:       61 74 65 2f 70 65 72 6c r4 = *(u32 *)(r7 + 12133)
      72:       2d 65 62 70 66 2f 73 61 if r5 > r6 goto +28770 <.BTF+0x38558>
      73:       6d 70 6c 65 2f 6b 70 72 if r0 s> r7 goto +25964 <.BTF+0x32db0>
      74:       6f 62 65 5f 62 74 66 2f r2 <<= r6
      75:       6b 70 72 6f 62 65 2e 63 *(u16 *)(r0 + 28530) = r7
      76:       00 69 6e 74 20 6b 70 72 <unknown>
      77:       6f 62 65 5f 65 78 65 63 r2 <<= r6
      78:       76 65 28 29 00 09 62 70 if w5 s>= 1885473024 goto +10536 <.BTF+0x14bb8>
      79:       66 5f 70 72 69 6e 74 6b <unknown>
      80:       28 22 48 65 6c 6c 6f 2c r0 = *(u16 *)skb[745499756]
      81:       20 42 50 46 20 57 6f 72 r0 = *(u32 *)skb[1919899424]
      82:       6c 64 21 5c 6e 22 29 3b w4 <<= w6
      83:       00 09 5f 5f 75 33 32 20 <unknown>
      84:       6b 65 79 20 3d 20 30 3b *(u16 *)(r5 + 8313) = r6
      85:       00 09 5f 5f 75 36 34 20 <unknown>
      86:       69 6e 69 74 76 61 6c 20 <unknown>
      87:       3d 20 31 2c 20 2a 76 61 if r0 >= r2 goto +11313 <.BTF+0x16448>
      88:       6c 70 20 3d 20 30 3b 00 w0 <<= w7
      89:       09 76 61 6c 70 20 3d 20 <unknown>
      90:       62 70 66 5f 6d 61 70 5f <unknown>
      91:       6c 6f 6f 6b 75 70 5f 65 <unknown>
      92:       6c 65 6d 28 26 6b 70 72 w5 <<= w6
      93:       6f 62 65 5f 6d 61 70 2c r2 <<= r6
      94:       20 26 6b 65 79 29 3b 00 r0 = *(u32 *)skb[3877241]
      95:       09 69 66 20 28 21 76 61 <unknown>
      96:       6c 70 29 00 09 09 62 70 w0 <<= w7
      97:       66 5f 6d 61 70 5f 75 70 <unknown>
      98:       64 61 74 65 5f 65 6c 65 w1 <<= 1701602655
      99:       6d 28 26 6b 70 72 6f 62 if r8 s> r2 goto +27430 <.BTF+0x35c50>
     100:       65 5f 6d 61 70 2c 20 26 <unknown>
     101:       6b 65 79 2c 20 26 69 6e *(u16 *)(r5 + 11385) = r6
     102:       69 74 76 61 6c 2c 20 42 r4 = *(u16 *)(r7 + 24950)
     103:       50 46 5f 41 4e 59 29 3b r0 = *(u8 *)skb[r4]
     104:       00 09 5f 5f 73 79 6e 63 <unknown>
     105:       5f 66 65 74 63 68 5f 61 r6 &= r6
     106:       6e 64 5f 61 64 64 28 76 if w4 s> w6 goto +24927 <.BTF+0x30e50>
     107:       61 6c 70 2c 20 31 29 3b <unknown>
     108:       00 7d 00 63 68 61 72 00 <unknown>
     109:       5f 5f 6c 69 63 65 6e 73 <unknown>
     110:       65 00 2e 6d 61 70 73 00 if r0 s> 7565409 goto +27950 <.BTF+0x36ce8>
     111:       6c 69 63 65 6e 73 65 00 w9 <<= w6

Disassembly of section .rel.BTF:

0000000000000000 <.rel.BTF>:
       0:       7c 01 00 00 00 00 00 00 w1 >>= w0
       1:       04 00 00 00 0e 00 00 00 w0 += 14
       2:       94 01 00 00 00 00 00 00 <unknown>
       3:       04 00 00 00 0f 00 00 00 w0 += 15

Disassembly of section .BTF.ext:

0000000000000000 <.BTF.ext>:
       0:       9f eb 01 00 20 00 00 00 <unknown>
       1:       00 00 00 00 14 00 00 00 <unknown>
       2:       14 00 00 00 bc 00 00 00 w0 -= 188
       3:       d0 00 00 00 00 00 00 00 <unknown>
       4:       08 00 00 00 79 00 00 00 <unknown>
       5:       01 00 00 00 00 00 00 00 <unknown>
       6:       10 00 00 00 10 00 00 00 <unknown>
       7:       79 00 00 00 0b 00 00 00 r0 = *(u64 *)(r0 + 0)
       8:       00 00 00 00 8b 00 00 00 <unknown>
       9:       c5 00 00 00 00 54 00 00 if r0 s< 21504 goto +0 <.BTF.ext+0x50>
      10:       08 00 00 00 8b 00 00 00 <unknown>
      11:       d9 00 00 00 02 5c 00 00 <unknown>
      12:       70 00 00 00 8b 00 00 00 <unknown>
      13:       fd 00 00 00 08 60 00 00 <unknown>
      14:       80 00 00 00 8b 00 00 00 <unknown>
      15:       0d 01 00 00 08 64 00 00 <unknown>
      16:       90 00 00 00 8b 00 00 00 <unknown>
      17:       d9 00 00 00 02 5c 00 00 <unknown>
      18:       98 00 00 00 8b 00 00 00 <unknown>
      19:       2c 01 00 00 09 6c 00 00 w1 *= w0
      20:       b0 00 00 00 8b 00 00 00 <unknown>
      21:       5c 01 00 00 06 70 00 00 w1 &= w0
      22:       c0 00 00 00 8b 00 00 00 <unknown>
                ...
      24:       d8 00 00 00 8b 00 00 00 <unknown>
      25:       68 01 00 00 03 78 00 00 <unknown>
      26:       00 01 00 00 8b 00 00 00 <unknown>
      27:       a5 01 00 00 02 84 00 00 if r1 < 33794 goto +0 <.BTF.ext+0xe0>
      28:       08 01 00 00 8b 00 00 00 <unknown>
      29:       c5 01 00 00 01 90 00 00 if r1 s< 36865 goto +0 <.BTF.ext+0xf0>

Disassembly of section .rel.BTF.ext:

0000000000000000 <.rel.BTF.ext>:
       0:       2c 00 00 00 00 00 00 00 w0 *= w0
       1:       04 00 00 00 02 00 00 00 w0 += 2
       2:       40 00 00 00 00 00 00 00 r0 = *(u32 *)skb[r0]
       3:       04 00 00 00 02 00 00 00 w0 += 2
       4:       50 00 00 00 00 00 00 00 r0 = *(u8 *)skb[r0]
       5:       04 00 00 00 02 00 00 00 w0 += 2
       6:       60 00 00 00 00 00 00 00 <unknown>
       7:       04 00 00 00 02 00 00 00 w0 += 2
       8:       70 00 00 00 00 00 00 00 <unknown>
       9:       04 00 00 00 02 00 00 00 w0 += 2
      10:       80 00 00 00 00 00 00 00 <unknown>
      11:       04 00 00 00 02 00 00 00 w0 += 2
      12:       90 00 00 00 00 00 00 00 <unknown>
      13:       04 00 00 00 02 00 00 00 w0 += 2
      14:       a0 00 00 00 00 00 00 00 <unknown>
      15:       04 00 00 00 02 00 00 00 w0 += 2
      16:       b0 00 00 00 00 00 00 00 <unknown>
      17:       04 00 00 00 02 00 00 00 w0 += 2
      18:       c0 00 00 00 00 00 00 00 <unknown>
      19:       04 00 00 00 02 00 00 00 w0 += 2
      20:       d0 00 00 00 00 00 00 00 <unknown>
      21:       04 00 00 00 02 00 00 00 w0 += 2
      22:       e0 00 00 00 00 00 00 00 <unknown>
      23:       04 00 00 00 02 00 00 00 w0 += 2

Disassembly of section .eh_frame:

0000000000000000 <.eh_frame>:
       0:       10 00 00 00 00 00 00 00 <unknown>
       1:       01 7a 52 00 08 7c 0b 01 <unknown>
       2:       0c 00 00 00 18 00 00 00 w0 += w0
       3:       18 00 00 00 00 00 00 00 00 00 00 00 18 01 00 00 r0 = 1202590842880 ll
                ...

Disassembly of section .rel.eh_frame:

0000000000000000 <.rel.eh_frame>:
       0:       1c 00 00 00 00 00 00 00 w0 -= w0
       1:       02 00 00 00 02 00 00 00 <unknown>

Disassembly of section .debug_line:

0000000000000000 <.debug_line>:
       0:       ce 00 00 00 05 00 08 00 if w0 s< w0 goto +0 <.debug_line+0x8>
       1:       82 00 00 00 08 01 01 fb <unknown>
       2:       0e 0d 00 01 01 01 01 00 <unknown>
       3:       00 00 01 00 00 01 01 01 <unknown>
       4:       1f 04 00 00 00 00 31 00 r4 -= r0
       5:       00 00 4a 00 00 00 5b 00 <unknown>
       6:       00 00 03 01 1f 02 0f 05 <unknown>
       7:       1e 04 6e 00 00 00 00 9c if w4 == w0 goto +110 <.debug_line+0x3b0>
       8:       0c 16 ec b4 07 74 c7 b5 w6 += w1
       9:       9b fd 91 2e 99 22 04 77 <unknown>
      10:       00 00 00 01 b8 10 f2 70 <unknown>
      11:       73 3e 10 63 19 b6 7e f5 <unknown>
      12:       12 c6 24 6e 82 00 00 00 <unknown>
      13:       02 ea df 4a 8b cf 7a c4 <unknown>
      14:       e7 bd 6d 2c b6 66 45 22 <unknown>
      15:       42 94 00 00 00 03 9a e8 <unknown>
      16:       d3 e7 79 4a ed 0d b7 a0 <unknown>
      17:       a2 34 5a b8 81 ee 04 00 <unknown>
      18:       00 09 02 00 00 00 00 00 <unknown>
      19:       00 00 00 03 15 01 05 02 <unknown>
      20:       0a 21 05 08 c9 2f 06 03 <unknown>
      21:       67 20 05 02 06 03 17 20 r0 <<= 538379014
      22:       05 09 24 05 06 3d 06 03 goto +1316 <.debug_line+0x29d8>
      23:       64 20 05 03 06 03 1e 4a w0 <<= 1243480838
      24:       06 03 62 4a 05 02 06 03 <unknown>
      25:       21 20 05 01 23 02 02 00 <unknown>
      26:       01      <unknown>
      26:       01      <unknown>

Disassembly of section .rel.debug_line:

0000000000000000 <.rel.debug_line>:
       0:       22 00 00 00 00 00 00 00 <unknown>
       1:       03 00 00 00 0c 00 00 00 <unknown>
       2:       26 00 00 00 00 00 00 00 if w0 > 0 goto +0 <.rel.debug_line+0x18>
       3:       03 00 00 00 0c 00 00 00 <unknown>
       4:       2a 00 00 00 00 00 00 00 <unknown>
       5:       03 00 00 00 0c 00 00 00 <unknown>
       6:       2e 00 00 00 00 00 00 00 if w0 > w0 goto +0 <.rel.debug_line+0x38>
       7:       03 00 00 00 0c 00 00 00 <unknown>
       8:       3a 00 00 00 00 00 00 00 <unknown>
       9:       03 00 00 00 0c 00 00 00 <unknown>
      10:       4f 00 00 00 00 00 00 00 r0 |= r0
      11:       03 00 00 00 0c 00 00 00 <unknown>
      12:       64 00 00 00 00 00 00 00 w0 <<= 0
      13:       03 00 00 00 0c 00 00 00 <unknown>
      14:       79 00 00 00 00 00 00 00 r0 = *(u64 *)(r0 + 0)
      15:       03 00 00 00 0c 00 00 00 <unknown>
      16:       93 00 00 00 00 00 00 00 <unknown>
      17:       02 00 00 00 02 00 00 00 <unknown>

Disassembly of section .debug_line_str:

0000000000000000 <.debug_line_str>:
       0:       2f 68 6f 6d 65 2f 75 62 r8 *= r6
       1:       75 6e 74 75 2f 70 72 69 <unknown>
       2:       76 61 74 65 2f 70 65 72 if w1 s>= 1919250479 goto +25972 <.debug_line_str+0x32bb8>
       3:       6c 2d 65 62 70 66 2f 73 <unknown>
       4:       61 6d 70 6c 65 2f 6b 70 <unknown>
       5:       72 6f 62 65 5f 62 74 66 <unknown>
       6:       00 2f 75 73 72 2f 69 6e <unknown>
       7:       63 6c 75 64 65 2f 61 73 <unknown>
       8:       6d 2d 67 65 6e 65 72 69 <unknown>
       9:       63 00 2f 75 73 72 2f 69 *(u32 *)(r0 + 29999) = r0
      10:       6e 63 6c 75 64 65 2f 62 if w3 s> w6 goto +30060 <.debug_line_str+0x3abb8>
      11:       70 66 00 2f 75 73 72 2f <unknown>
      12:       69 6e 63 6c 75 64 65 2f <unknown>
      13:       6c 69 6e 75 78 00 6b 70 w9 <<= w6
      14:       72 6f 62 65 2e 63 00 69 <unknown>
      15:       6e 74 2d 6c 6c 36 34 2e if w4 s> w7 goto +27693 <.debug_line_str+0x361e8>
      16:       68 00 62 70 66 5f 68 65 <unknown>
      17:       6c 70 65 72 5f 64 65 66 w0 <<= w7
      18:       73 2e 68 00 62 70 66 2e <unknown>
      19:       68      <unknown>
      19:       00      <unknown>

Disassembly of section .symtab:

0000000000000000 <.symtab>:
                ...
       3:       f1 00 00 00 04 00 f1 ff <unknown>
                ...
       6:       03 00 03 00 00 00 00 00 <unknown>
                ...
       9:       2a 01 00 00 00 00 03 00 <unknown>
      10:       00 01 00 00 00 00 00 00 <unknown>
                ...
      12:       23 01 00 00 00 00 03 00 <unknown>
      13:       08 01 00 00 00 00 00 00 <unknown>
                ...
      15:       03 00 08 00 00 00 00 00 <unknown>
                ...
      18:       03 00 09 00 00 00 00 00 <unknown>
                ...
      21:       03 00 0c 00 00 00 00 00 <unknown>
                ...
      24:       03 00 0d 00 00 00 00 00 <unknown>
                ...
      27:       03 00 0f 00 00 00 00 00 <unknown>
                ...
      30:       03 00 10 00 00 00 00 00 <unknown>
                ...
      33:       03 00 18 00 00 00 00 00 <unknown>
                ...
      36:       03 00 1a 00 00 00 00 00 <unknown>
                ...
      39:       bb 00 00 00 12 00 03 00 <unknown>
                ...
      41:       18 01 00 00 00 00 00 00 8a 00 00 00 11 00 07 00 r1 = 1970397851418624 ll
                ...
      44:       20 00 00 00 00 00 00 00 r0 = *(u32 *)skb[0]
      45:       c9 00 00 00 11 00 05 00 <unknown>
                ...
      47:       0d 00 00 00 00 00 00 00 <unknown>
```

## elfパーサーの実装方針
[https://gist.github.com/x0nu11byt3/bcb35c3de461e5fb66173071a2379779](ELF Format Cheatsheet)を参考にしておく


