---
course: NI-REV
lab: 1
topic: OllyDbg, IA-32, stack frames
tags: [reverse-engineering, ollydbg, ia-32, stack, ni-rev]
source: https://courses.fit.cvut.cz/NI-REV/en/labs/lab01.html
---

# NI-REV Lab 01: Introduction to OllyDbg

> [!info] About the numbers
> Addresses like `001AFF1C` come from my own runs and **change on every restart** (stack and heap move). Use your own numbers. The *offsets* (`EBP+8`, `EBP-1DC`, ...) never change.
> Task 1 was done in run A (`argv = 0066DF20`), Tasks 5-7 in run B (`argv = 0073DF20`, `EBP = 001AFF1C`).

---

## 1. Concepts

### IA-32
Intel's 32-bit x86 architecture. Registers are 32 bits wide, addresses are 32 bits (4 GB). That is why `PUSH`/`POP` move `ESP` by 4 and addresses have 8 hex digits. OllyDbg only debugs 32-bit programs.

### Registers that matter for this lab
| Register | Role |
|---|---|
| `ESP` | top of the stack (lowest used address) |
| `EBP` | fixed anchor of the current stack frame |
| `EIP` | address of the next instruction |
| `EAX`, `ECX`, `EDX` | scratch, `EAX` holds return values |
| `ESI`, `EDI`, `EBX` | general use, **saved by the function** if it uses them |

### Flags (`EFL`)
Set automatically by `CMP`, `TEST`, `ADD`, `SUB`, ... and read by conditional jumps.

| Flag | Set to 1 when |
|---|---|
| `Z` | result was 0 (`JE`/`JZ` jumps when Z=1) |
| `S` | result negative |
| `C` | unsigned carry |
| `O` | signed overflow |
| `P` | low byte has even number of 1 bits |
| `A` | carry from bit 3 (obsolete) |
| `T` | trace (single-step), used by debuggers |
| `D` | string instructions go backwards |

`if (a == b)` compiles to `CMP` + `JE`. `EFL = 00000246` means P and Z set.

### Not needed for this lab
- **FPU** (`ST0`-`ST7`, `FST`, `FCW`): 80-bit stack for decimal maths, older.
- **SSE** (`XMM0`-`XMM7`, `MXCSR`): 128-bit registers, several values at once, newer.
- **Segment registers** (`CS DS ES FS GS SS`): constant in flat 32-bit mode.
- **`LastErr`**: not a CPU register. Result of Win32 `GetLastError()`, like `errno`.

### Little-endian
A 4-byte value is stored lowest byte first. `0066DF28` appears in the dump as `28 DF 66 00`.

### The stack
- Grows toward **lower** addresses.
- `PUSH x`: `ESP = ESP-4`, then store `x` at `[ESP]`.
- `POP x`: read `[ESP]`, then `ESP = ESP+4`.

---

## 2. Function calls (cdecl)

1. Caller `PUSH`es the arguments, **last argument first**.
2. `CALL f` pushes the **return address** (next instruction) and jumps to `f`.
3. `f` runs.
4. `RET` pops the return address into `EIP`.
5. Caller removes the arguments with `ADD ESP, n` (`n` = 4 x number of arguments).

Telling which pushes are arguments: count back from the call using the `ADD ESP,n` after it. `ADD ESP,0C` = 3 arguments. Not every `PUSH` before a call is an argument (some just save registers).

### How `main` is called (page 13)
```
004122F0  MOV EAX,[envp]
004122F5  PUSH EAX          ; envp
004122F6  MOV ECX,[argv]
004122FC  PUSH ECX          ; argv
004122FD  MOV EDX,[argc]
00412303  PUSH EDX          ; argc
00412304  CALL main
00412309  ADD ESP,0C        ; remove 3 args
```
`main(int argc, char** argv, char** envp)`.

---

## 3. Stack frame

### Prologue (setup) / epilogue (teardown)
```
PUSH EBP            ; save caller's EBP
MOV  EBP,ESP        ; EBP = fixed anchor
SUB  ESP,1DC        ; room for locals
PUSH EBX / ESI / EDI ; save registers
LEA  EDI,[EBP-1DC]  ; debug build: fill locals with CC
MOV  ECX,77
MOV  EAX,CCCCCCCC
REP  STOS DWORD PTR ES:[EDI]   ; 0x77 * 4 = 0x1DC bytes
```
Epilogue undoes it in reverse: `POP EDI/ESI/EBX`, `ADD ESP,1DC`, `MOV ESP,EBP`, `POP EBP`, `RETN`.

**Where the prologue ends:** after the last instruction that only prepares the frame. The body starts at the first instruction that does the program's real work.

### Offsets from EBP
```
EBP+0C   argv   (2nd argument)
EBP+8    argc   (1st argument)
EBP+4    return address
EBP+0    saved EBP        <- EBP points here
EBP-4 ...EBP-1DC  local variables (the 1DC room)
EBP-1E0  saved EBX
EBP-1E4  saved ESI
EBP-1E8  saved EDI        <- ESP points here after the prologue
```
`EBP+something` = argument, `EBP-something` = local variable.

---

## 4. Debugger keys

| Key | Action |
|---|---|
| F2 | toggle breakpoint on the **selected line** |
| F9 | run until breakpoint (selected line does not matter) |
| F7 | step into (enters calls) |
| F8 | step over (runs a call as one step) |
| Ctrl+F9 | step out (run to `RET`) |
| Ctrl+F2 | restart program |
| Ctrl+G | go to address / expression in the active pane |
| Enter | follow `JMP`/`CALL` target |
| Numpad `-` | go back to previous view |
| Numpad `*` | go to current `EIP` |
| Double-click a flag | flip it (force a jump) |

OllyDbg cannot step backwards. To go back in time, restart (Ctrl+F2).

---

## 5. Walkthrough

### Setup
1. File → Open `bek1.exe`. It stops at `0041112C` (`_start`, not `main`). That is image base `00400000` + entry RVA `1112C`.
2. Select the `CALL` at `00412304`, press **F2**, then **F9**.
3. Stack pane (top = `ESP`) shows `argc`, `argv`, `envp`. Newer OllyDbg builds show no labels, so identify them by position.

### Task 1: `argv[0]`
`argv` is a pointer to an array of pointers.
```
stack value argv = 0066DF20  -> array: 0066DF20: 28 DF 66 00   argv[0] = 0066DF28
                                       0066DF24: 00 00 00 00   argv[1] = NULL
                              string at 0066DF28: E:\Reverse Engineering\...\bek1.exe
```
1. Dump pane, Ctrl+G, enter the `argv` value.
2. First 4 bytes are `argv[0]`, backwards. Reverse them for the address.
3. Go to that address: ASCII shows the exe path.

`argv[1]` is NULL because no argument was given.

### Task 2: prologue of `main` (`00411750`)
```
00411750  PUSH EBP
00411751  MOV  EBP,ESP
00411753  SUB  ESP,1DC
00411759  PUSH EBX
0041175A  PUSH ESI
0041175B  PUSH EDI
0041175C  LEA  EDI,[EBP-1DC]
00411762  MOV  ECX,77
00411767  MOV  EAX,CCCCCCCC
0041176C  REP  STOS DWORD PTR ES:[EDI]
```
Reach it with F7 on the call, then F7 on the `JMP` stub.

### Task 3: epilogue of `main` (ignoring `_RTC_CheckEsp`)
```
00411BAB  POP EDI
00411BAC  POP ESI
00411BAD  POP EBX
00411BAE  ADD ESP,1DC
00411BBB  MOV ESP,EBP
00411BBD  POP EBP
00411BBE  RETN
```
`POP EAX`/`POP EDX` just before are the debug build's stack-variable check, not part of the frame teardown.

### Task 4: settings
Options → Options... → Analysis. Match the screenshot:
- Recognition of procedures: **Fuzzy**
- Automatic module analysis: **All modules**
- Show predicted register values: checked
- Don't predict register contents for system DLLs: unchecked
- Show recognized ARGs and LOCALs **in disassembly**: **unchecked** (the circled one)
- Show recognized ARGs and LOCALs **in comments**: checked
- Use symbolic names for ARGs: unchecked

Then the question under the screenshot, at the first instruction of `main` (`00411750`):
```
ESP -> 001AFF20  00412309  return address (into __tmainCRTStartup+199)
       001AFF24  00000001  argc
       001AFF28  0073DF20  argv
       001AFF2C  0073EBF8  envp
```
- Top of stack: `001AFF20` (= ESP).
- Stored there: the return address `00412309`.
- `argc` at **ESP+4**, `argv` at **ESP+8**.

### Task 5: stack at `LEA EDI,[EBP-1DC]`
Step with F8 six times from `00411750`. `ESP = 001AFD34`, `EBP = 001AFF1C`.
```
ESP -> 001AFD34  0041112C   saved EDI   (last push)
       001AFD38  0041112C   saved ESI
       001AFD3C  003EF000   saved EBX   (first push)
       001AFD40  ┐
         ...     │ 1DC bytes, empty for now
       001AFF1B  ┘
EBP -> 001AFF1C  (caller's EBP)  saved EBP
       001AFF20  00412309   return address
       001AFF24  00000001   argc
       001AFF28  0073DF20   argv
```
Check: `001AFF1C - 1DC = 001AFD40`. The saved registers sit **below** the room because `SUB ESP` ran before the three `PUSH`es. The `PUSH` order is EBX, ESI, EDI, so EDI ends up on top.

### Task 6: where EBP points
At the **saved EBP** slot (`001AFF1C`), directly above the 1DC room and below the return address.

### Task 7: argc and argv relative to EBP
- `argc` at **EBP+8** (`001AFF24`)
- `argv` at **EBP+0C** (`001AFF28`)

### Task 8: the buffer for `scanf`
> [!warning] Verify this one on your own machine
> Not tested end to end yet.

This exe uses **`sscanf`**, not `scanf`. The call is at `0041191E`:
```
0041190B  MOV ESI,ESP
0041190D  LEA EAX,[EBP-10C]   ; destination (a short)
00411911  PUSH EAX            ; Arg3
00411912  PUSH "%hd"          ; Arg2 = format
00411917  LEA ECX,[EBP-100]   ; input text
0041191D  PUSH ECX            ; Arg1
0041191E  CALL sscanf
```
- Where `sscanf` **writes**: `EBP-10C` (2 bytes, `001AFE10` in run B).
- The text it **reads**: `EBP-100`.
- `[EBP-10C]` is set to 0 by `MOV WORD PTR [EBP-10C],AX` at `00411770`, so it shows `00 00`, not `CC`.

Likely answer to give: **`EBP-10C`** (mention `EBP-100` as the input line). Check which one the course expects.

Verify: break on `0041191E`, note the bytes at `EBP-10C`, press F8 over the call, then check them again. A `short` is little-endian, so `7` appears as `07 00`.

---

## 6. What `main` actually does

```
strcmp(argv[1], "/?")  ; if equal -> usage()
strcmp(argv[1], "-?")  ; if equal -> usage()
f = fopen(argv[1], "rt")      ; stored at [EBP-118]
if (f == 0) goto 00411956     ; CMP [EBP-118],0 / JE
printf("Your name is: ")
fgets(buf1, 0x20, f); encrypt(buf1)   ; buf1 at EBP-30
fgets(buf2, 0x20, f); encrypt(buf2)   ; EBP-48
fgets(buf3, 0x20, f); encrypt(buf3)   ; EBP-60
fgets(buf4, 0x20, f); encrypt(buf4)   ; EBP-78
fgets(buf5, 0x20, f); encrypt(buf5)   ; EBP-100
sscanf(buf5, "%hd", &x)               ; x at EBP-10C
```
The `argv[1]` access is `MOV ECX,[EBP+0C]` (= `argv`), then `MOV EDX,[EAX+ECX]` with `EAX = 4`, so `argv[1]`. `encrypt` was not examined.

---

## 7. Open issue: access violation

Running with **no** command-line argument crashes inside `strcmp` (`MOV EAX,[EDX]` with `EDX = 0`), status bar: *Access violation when reading [00000000]*. Cause: `argv[1]` is NULL (matches Task 1).

To get past it:
1. File → Set new arguments... → a file path (the program opens it with `fopen`).
2. **Ctrl+F2** to restart, then run to `00412304`.
3. Check the stack: `argc` should now be `00000002`.
4. If `argc` is still 1, the argument was not applied.

Not yet confirmed: whether the crash is gone with `argc = 2`, and what the course intends here (the lab page only mentions that arguments *can* be set).

---

## 8. Useful links
- Lab page: https://courses.fit.cvut.cz/NI-REV/en/labs/lab01.html
- Intel x86 intro: https://www.cs.virginia.edu/~evans/cs216/guides/x86.html
- 32-bit cheat sheet: https://forum.tuts4you.com/files/file/1841-win32-reverse-engineering-cheat-sheet/
- Intel Software Developer's Manual
