# unEXEPACK

## Information

Unpacker for Microsoft EXEPACK utility compressor.

### EXEPACK layout

```
+--------------------------+
|      EXEPACK HEADER      |
+--------------------------+
|      UNPACKER  STUB      |
+--------------------------+
|       Error string       |
| "Packed file is corrupt" |
+--------------------------+
|     RELOCATION TABLE     |
+--------------------------+
```

### EXEPACK header

Header format:

```
+ 0x00 : REAL_IP                [WORD]  // Original initial IP value
+ 0x02 : REAL_CS                [WORD]  // Original initial (relative) CS value
+ 0x04 : MEM_START              [WORD]  // Start of executable in memory : not used by the unpacker
+ 0x06 : EXEPACK_SIZE           [WORD]  // sizeof (EXEPACK HEADER) + unpacker stub length + strlen(ERROR_STRING) + relocation table length
+ 0x08 : REAL_SP                [WORD]  // Original initial SP value
+ 0x0A : REAL_SS                [WORD]  // Original initial (relative) SS value
+ 0x0C : DEST_LEN               [WORD]  // Unpacked data length (in paragraphs)
+ 0x0E : SKIP_LEN               [WORD]  // field only present in specific version of EXEPACK : not used by the unpacker
+ 0x10 : SIGNATURE              [WORD]  // Magic number "RB"
```

### Algorithm

EXEPACK employs a fairly basic run-length encoding, commands are encoded on bits 1-7 (mask `0xFE`).

* Command `0xB0`, write `LENGTH` bytes with `VALUE`.

```
[LENGTH (WORD)][VALUE (BYTE)]
```

* Command `0xB2`, copy the next `LENGTH` bytes

```
[LENGTH (WORD)][BYTES ((BYTE) * LENGTH)]
```

### Relocation table

Relocation table is optimized too, for each segment (0-15), there is the following layout, where `entry` is relative to the start of the exe in memory.

```
+ 0x00 : NB_ENTRIES      [WORD]
+ 0x02 : ENTRY           [WORD] * NB_ENTRIES
```

## Usage

```
unpack.exe <EXEPACK_file> [OUTPUT_FILE]
    default ouput file is "unpacked"
```

`EXEPACK_file` : Specifies the input file to unpack

`OUTPUT_FILE` : Specifies the output file to which the unpacked executable results will be written to. Defaults to 'unpacked'.

## EXEPACK list

If you are wondering if an game/executable is using EXEPACK, a list of EXEPACK executable is available [here](http://w4kfu.github.io/unEXEPACK/files/exepack_list.html).

This list is based on the awesome [Total DOS Collection Release 14](https://archive.org/details/Total_DOS_Collection_Release_14) archive, thanks to the authors!

## Known bugs

Only works on english version of exepack.

Relocation table location is computed by looking at the pattern "Packed file is corrupt".

E.g: `Sound.exe` (md5 : `F176559889278FFD535D753CEC99EA53`) from `Batman Returns (Es) (1992)(Konami Inc.) [Adventure]`:

```
Offset(h) 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F

00002EE0  00 00 00 00 00 00 7D 01 00 01 3B 28 3C 28 02 00  ......}...;(<(..
00002EF0  52 42 8C C0 05 10 00 0E 1F A3 04 00 03 06 0C 00  RBŒÀ.....£......
00002F00  8E C0 8B 0E 06 00 8B F9 4F 8B F7 FD F3 A4 8B 16  ŽÀ‹...‹ùO‹÷ýó¤‹.
00002F10  0E 00 50 B8 38 00 50 CB 8C C3 8C D8 2B C2 8E D8  ..P¸8.PËŒÃŒØ+ÂŽØ
00002F20  8E C0 BF 0F 00 B9 10 00 B0 FF F3 AE 47 8B F7 8B  ŽÀ¿..¹..°ÿó®G‹÷‹
00002F30  C3 2B C2 8E C0 BF 0F 00 B1 04 8B C6 F7 D0 D3 E8  Ã+ÂŽÀ¿..±.‹Æ÷ÐÓè
00002F40  74 09 8C DA 2B D0 8E DA 83 CE F0 8B C7 F7 D0 D3  t.ŒÚ+ÐŽÚƒÎð‹Ç÷ÐÓ
00002F50  E8 74 09 8C C2 2B D0 8E C2 83 CF F0 AC 8A D0 4E  èt.ŒÂ+ÐŽÂƒÏð¬ŠÐN
00002F60  AD 8B C8 46 8A C2 24 FE 3C B0 75 06 AC F3 AA EB  .‹ÈFŠÂ$þ<°u.¬óªë
00002F70  07 90 3C B2 75 6B F3 A4 8A C2 A8 01 74 BA BE 2D  ..<²ukó¤ŠÂ¨.tº¾-
00002F80  01 0E 1F 8B 1E 04 00 FC 33 D2 AD 8B C8 E3 13 8B  ...‹...ü3Ò.‹Èã.‹
00002F90  C2 03 C3 8E C0 AD 8B F8 83 FF FF 74 11 26 01 1D  Â.ÃŽÀ.‹øƒÿÿt.&..
00002FA0  E2 F3 81 FA 00 F0 74 16 81 C2 00 10 EB DC 8C C0  âó.ú.ðt..Â..ëÜŒÀ
00002FB0  40 8E C0 83 EF 10 26 01 1D 48 8E C0 EB E2 8B C3  @ŽÀƒï.&..HŽÀëâ‹Ã
00002FC0  8B 3E 08 00 8B 36 0A 00 03 F0 01 06 02 00 2D 10  ‹>..‹6...ð....-.
00002FD0  00 8E D8 8E C0 BB 00 00 FA 8E D6 8B E7 FB 2E FF  .ŽØŽÀ»..úŽÖ‹çû.ÿ
00002FE0  2F B4 40 BB 02 00 B9 16 00 8C CA 8E DA BA 17 01  /´@»..¹..ŒÊŽÚº..
00002FF0  CD 21 B8 FF 4C CD 21 46 69 63 68 65 72 6F 20 63  Í!¸ÿLÍ!Fichero c
00003000  6F 72 72 6F 6D 70 69 64 6F 20 20 20 20 18 00 EA  orrompido    ..ê
```

## Ressources

* [File Format](http://www.shikadi.net/moddingwiki/Microsoft_EXEPACK#File_Format)
* [unexepack from openKB](https://sourceforge.net/p/openkb/code/ci/master/tree/src/tools/unexepack.c)