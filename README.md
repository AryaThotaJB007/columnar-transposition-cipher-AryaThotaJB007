# Columnar Transposition Cipher — x86 Assembly (NASM)

CS 66 term project: a 32-bit NASM assembly program implementing a full
columnar transposition cipher — encryption and decryption — using raw
Linux `int 0x80` syscalls with no external library or high-level language
dependencies.

## What it does

- Prompts the user to pick one of three plaintext files (`msg1.txt`,
  `msg2.txt`, `msg3.txt`) and loads it into memory.
- Asks for a key length (5–10) and generates a random column-order key
  via a Fisher–Yates shuffle, seeded from the system clock.
- Builds a row-major matrix from the plaintext (padding the last row
  with `_`), encrypts by reading columns out in key order, then decrypts
  by reversing the process — recovering the original text exactly.
- Prints the approximate key entropy (log2(key length!)) alongside the
  plaintext, key, ciphertext, and decrypted text.
- Optionally attempts a brute-force crack without the key, searching
  column-order permutations for a crib substring.

## Implementation notes

- `compute_dimensions` / `build_matrix` / `encrypt` / `decrypt` /
  `print_all` are separate modular procedures, all indexing into one
  flat 1-D buffer via `row * keyLen + column` arithmetic.
- All I/O (reading input, opening/reading files, writing output) goes
  through raw `int 0x80` syscalls (`sys_read`, `sys_write`, `sys_open`,
  `sys_close`, `sys_time`) — no libc, no external assembly library.
- Input is read one line at a time per prompt; this assumes an
  interactive terminal (each `read` call gets one line as it's typed).
  Piping all input in at once will not work correctly.

## Build & run

A fresh Codespace/container likely won't have `nasm` installed. Install it
first:

```bash
sudo apt-get update && sudo apt-get install -y nasm
```

Then assemble, link, and run:

```bash
nasm -f elf32 cipher.asm -o cipher.o
ld -m elf_i386 -o cipher cipher.o
./cipher
```

(`ld` comes from `binutils`, which is preinstalled on standard Ubuntu
Codespace images. This program links no libraries, so `gcc-multilib` is
not needed here.)

## License

See `LICENSE` (MIT, course-provided template).
