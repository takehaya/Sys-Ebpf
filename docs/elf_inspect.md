# elf_inspect

## elfの中身を眺める
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

## elfパーサーの実装方針
[https://gist.github.com/x0nu11byt3/bcb35c3de461e5fb66173071a2379779](ELF Format Cheatsheet)を参考にしておく


