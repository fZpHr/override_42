# Override

Binary exploitation wargame (42). Ten setuid binaries, each owned by the next
user. Reading a level's password file requires exploiting that level's binary,
then escalating to the next one.

Each `levelXX/` directory holds the decompiled source and a writeup of the
technique used.

## Levels

| Level | Technique |
|-------|-----------|
| 00 | Hardcoded password recovered from the decompilation |
| 01 | Stack buffer overflow, shellcode staged in `.bss` |
| 02 | Format string, leaking the password from memory |
| 03 | Reverse engineering a XOR keygen |
| 04 | Stack overflow + ret2libc, bypassing a `ptrace` anti-debug check |
| 05 | Format string overwriting a GOT entry to redirect execution |
| 06 | Reverse engineering the serial check (keygen) |
| 07 | Out-of-bounds array index + ret2libc |
| 08 | Abusing a setuid backup feature to read a protected file |
| 09 | Stack overflow redirecting execution to a hidden backdoor |

## Concepts

Stack and heap overflows, format strings, GOT/PLT overwrite, shellcoding,
ret2libc, keygen-style reversing, and working around `ptrace` anti-debugging.
Targets are x86 32-bit and 64-bit ELF. Tooling: Ghidra, gdb/gef,
objdump/readelf.

> Educational material. The exploited binaries are intentionally vulnerable 42
> coursework.
