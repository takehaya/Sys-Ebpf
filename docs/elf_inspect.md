# elf_inspect

## elfの中身を眺める
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