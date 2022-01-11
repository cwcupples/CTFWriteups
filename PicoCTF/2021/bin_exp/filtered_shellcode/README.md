# Filtered Shellcode - Pico CTF 2021

This challenge takes a look at writing shellcode but in a very specific manner. We are given a single binary called "fun" and given the hint to look at the calling convention and see how to set up the registers.

So to begin, we download the binary and throw it in Ghidra and find out a little bit about the program. Below is the decompiled main function and we can see that it takes user input and calls a function called execute. Below main is the decompiled version of execute, but it's a little difficult to determine exactly what execute is doing. It roughly looks like it takes the input from the command line and then stores is in the stack, but with some filtering that's a little hard to figure out.

undefined4 main(void)
{
  int i_user_input;
  char buf [1000];
  char c_user_input;
  uint i;
  undefined *local_10;
  
  local_10 = &stack0x00000004;
  setbuf(stdout,(char *)0x0);
  i = 0;
  c_user_input = 0;
  puts("Give me code to run:");
  i_user_input = fgetc(stdin);
  c_user_input = (char)i_user_input;
  while ((c_user_input != '\n' && (i < 1000))) {
    buf[i] = c_user_input;
    i_user_input = fgetc(stdin);
    c_user_input = (char)i_user_input;
    i = i + 1;
  }
                    /* ensure input is even length */
  if ((i & 1) != 0) {
    buf[i] = -0x70;
    i = i + 1;
  }
  execute(buf,i);
  return 0;
}

void execute(int buffer,int length)
{
  int iVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  undefined4 uStack48;
  undefined auStack44 [8];
  undefined *local_24;
  undefined *local_20;
  uint local_1c;
  uint total_length;
  int local_14;
  uint local_10;
  
  uStack48 = 0x8048502;
  if ((buffer != 0) && (length != 0)) {
    total_length = length * 2;
    local_1c = total_length;
    uVar3 = (total_length + 0x10) / 0x10;
    iVar1 = uVar3 * -0x10;
    local_20 = auStack44 + iVar1;
    local_14 = 0;
    local_10 = 0;
    while (iVar2 = local_14, local_10 < total_length) {
      uVar4 = (uint)((int)local_10 >> 0x1f) >> 0x1e;
      if ((int)((local_10 + uVar4 & 3) - uVar4) < 2) {
        local_14 = local_14 + 1;
        auStack44[local_10 + iVar1] = *(undefined *)(buffer + iVar2);
      }
      else {
        auStack44[local_10 + iVar1] = 0x90;
      }
      local_10 = local_10 + 1;
    }
    auStack44[total_length + iVar1] = 0xc3;
    local_24 = auStack44 + iVar1;
    (&uStack48)[uVar3 * -4] = 0x80485cb;
    (*(code *)(auStack44 + iVar1))();
    return;
  }
                    /* WARNING: Subroutine does not return */
  exit(1);
}

To get a better idea of what exactly execute() is doing, let's take a look at this binary in GDB. Unfortunately, I had to open up my Kali VM to actually run the binary in GDB because it wouldn't work correctly on my mac. So off to the VM!

Setting a breakpoint right before we call the (*(code *)(auStack44 + iVar1))(); line in execute() we can inspect the instructions that are about to be executed by this function. We see that the instructions are grouped into 4 bytes, with the first two being the user input, and the latter two being 0x90 (nops). So it appears that this binary will take in some shellcode, but only execute two byte instructions.  This means we need to find some shellcode that only uses 2 byte instructions which is probably going to be really hard to find. Instead let's just use some normal shellcode and modify it for our purposes here.

Going to shell-storm.org and looking for some useful shellcode, I found one with the title: Linux x86 execve("/bin/sh") - 28 bytes (http://shell-storm.org/shellcode/files/shellcode-811.php). This seems like it'll work


On the server, we find the actual code which looks like:
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_LENGTH 1000

void execute(char *shellcode, size_t length) {
	if (!shellcode || !length) {
		exit(1);
	}
	size_t new_length = length * 2;
	char result[new_length + 1];

	int spot = 0;
	for (int i = 0; i < new_length; i++) {
		if ((i % 4) < 2) {
			result[i] = shellcode[spot++];
		} else {
			result[i] = '\x90';
		}
	}
	// result[new_length] = '\xcc';
	result[new_length] = '\xc3';

	// Execute code
	int (*code)() = (int(*)())result;
	code();
}

int main(int argc, char *argv[]) {
	setbuf(stdout, NULL);
	char buf[MAX_LENGTH];
	size_t length = 0;
	char c = '\0';

	printf("Give me code to run:\n");
	c = fgetc(stdin);
	while ((c != '\n') && (length < MAX_LENGTH)) {
		buf[length] = c;
		c = fgetc(stdin);
		length++;
	}
	if (length % 2) {
		buf[length] = '\x90';
		length++;
	}
	execute(buf, length);
	return 0;
}
