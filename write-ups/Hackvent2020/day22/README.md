# HV20.22 Padawanlock

_A new apprentice Elf heard about "Configuration as Code". When he had to solve the problem to protected a secret he came up with this "very sophisticated padlock"._

[Download](padawanlock.zip)

---

```
$ file padawanlock 
padawanlock: ELF 32-bit LSB pie executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=56e8cc633ab14ebd1c6fdd3bfda3ebd100a6a45e, for GNU/Linux 3.2.0, stripped

$ ./padawanlock
PIN (6 digits): 133337  
Unlocked secret is: ,_HES_ONLY_A_WOOKIEE!}
```

The lock prints random quotes from Star Wars. There are 1,000,000 possible PINs. Simple brute-force is not an
option as a single iteration takes too long.

Let's take a look what's inside. I used [Ghidra](https://ghidra-sre.org/).

This is the "main" function:
```
void FUN_000111e0(void)
{
  char *__nptr;
  int iVar1;
  
  printf(s_PIN_(6_digits):_01326008);           // Print "PIN (6 digits):"
  __nptr = gets(&DAT_013261be);                 // Read PIN from console
  __nptr[6] = '\0';                             // Take first 6 chars only
  iVar1 = atoi(__nptr);                         // Convert to integer iVar1
  (*(code *)(&DAT_0001124b + iVar1 * 0x14))();  // Call 20*iVar1 + &DAT_0001124b (memory location pointer)
  FUN_00011241();
  printf(s_Unlocked_secret_is:_01326019);       // Print "Unlocked secret is:"
  printf(&DAT_0132602e);                        // Print THE SECRET
  return;
}
```

I was unable to fully comprehend the last part, but looking into plain assembly helped me:
```
        00011215 05 4b 12        ADD        EAX,LAB_0001124b
                 01 00
        0001121a bb 2e 60        MOV        EBX,DAT_0132602e
                 32 01
        0001121f ff d0           CALL       EAX
```

There is a dynamic call based on the user input (stored in `EAX`). `EBX` is just a memory location for the returned message.
In other words, programs jumps to a place based on our PIN. The file size matches my assumption. It's about
20 MBs, and we have 1,000,000 (1 MB) options * 20 bytes data chunks.

This is one of 1,000,000 jump targets (20 bytes of data/instructions):
```
  iVar1 = 0x1500694;
  do {
    iVar1 = iVar1 + -1;
  } while (iVar1 != 0);
  unaff_EBX[1] = 0x55;
```

In assembly:
```
                             LAB_00e7ad9b                                    XREF[1]:     000210a6(j)  
        00e7ad9b b9 94 06        MOV        ECX,0x1500694
                 50 01
                             LAB_00e7ada0                                    XREF[1]:     00e7ada4(j)  
        00e7ada0 49              DEC        ECX
        00e7ada1 83 f9 00        CMP        ECX,0x0
        00e7ada4 75 fa           JNZ        LAB_00e7ada0
        00e7ada6 c6 03 55        MOV        byte ptr [EBX],0x55
        00e7ada9 43              INC        EBX
        00e7adaa e9 88 02        JMP        LAB_0012b037
                 2b ff

```

There is a long loop at the beginning. The only purpose of this loop is to make brute-forcing not
(easily) possibly. Then, a single byte (character) is saved (`byte ptr [EBX],0x55`) and, finally, a jump
to a new location. Each PIN starts a series of similar jumps (usually 10-50) and thus creates a secret
message.

I recreated the logic in Kotlin to make brute-forcing all 1,000,000 fast:
```kotlin
private const val START_OFFSET = 0x124B

fun main() {
    val data = Resources.asBytes("hv20/padawanlock")

    for (i in 0..999999) {
        val message = StringBuilder()
        var offset = START_OFFSET + i * 0x14

        while (offset != 0x1226) { // Address of the final jump
            val char = data[offset + 13].toChar()
            message.append(char)

            val rip = offset + 20
            val jmp = ByteBuffer.wrap(data.copyOfRange(offset + 16, offset + 20))
                .order(ByteOrder.LITTLE_ENDIAN)
                .getInt(0)

            offset = jmp + rip
        }
        if (message.startsWith("HV20{")) {
            println("PIN: $i")
            println(message.toString())
            exitProcess(0)
        }
    }
}
```

The right pin is `451235` and the flag is `HV20{C0NF1GUR4T10N_AS_C0D3_N0T_D0N3_R1GHT}`
