---
title: NIE-REV Lecture 1 - Introduction to Reverse Engineering, Stack Frame Analysis
course: NIE-REV (Reverse Engineering)
lecturers: Tomáš Zahradnický, Josef Kokeš (CTU Prague, FIT)
tags: [reverse-engineering, x86, assembly, stack-frame, SEH, NIE-REV]
status: studied, self-check questions at the end still open
---

# Lecture 1: Introduction to RE, Stack Frame Analysis

> [!abstract] Goal of the lecture
> Take a raw disassembled function and recover something close to its C source.
> Core skill: **partition the stack frame, infer types (signedness + API signatures), identify the calling convention.**

> [!note] Conventions in these notes
> All code is **32-bit x86** unless stated. Hex is written `0Ch`, `0x0C` or `25h`, all meaning the same thing (`0Ch` = 12, `10h` = 16, `218h` = 536, `25Ch` = 604).

---

## 0. Beginner background

- **Machine code** is what the CPU runs. **Assembly** is the same thing as readable text. RE = reading assembly and working out the original C.
- **Registers** (tiny built-in CPU variables):
  - `EAX`: usually the return value
  - `ESP`: stack pointer (top of stack)
  - `EBP`: base pointer (fixed anchor inside the current frame)
  - `ECX`, `EDX`: scratch registers
- **Stack**: grows *downward* (push = ESP decreases).
  - `push x` puts a value on the stack, `pop r` takes the top value into a register
  - `call f` pushes the return address and jumps; `ret` pops it and jumps back
- **Stack frame**: a function's chunk of the stack (parameters, return address, saved EBP, locals).
- `[x]` in assembly means "the memory at address x". `[ecx+4]` = read the value 4 bytes after the address in ECX.
- `and esp, 0xfffffff0`: bitwise AND clears the low 4 bits, so ESP is rounded **down to a multiple of 16** (stack alignment).
- `nop` = do nothing. `xchg ax, ax` = swap a register with itself (also a no-op, 2 bytes). Used as **padding** so the next function starts on a 16-byte boundary. Ignore when reading code.
- `#pragma pack(1)`: C directive that **turns off struct padding** so fields sit back to back. Matters because struct layout in memory depends on it.
- **MSVC** = Microsoft Visual C++ (Windows compiler). **GCC** = standard Linux compiler. Recognizing the compiler is part of RE.

### Signed vs unsigned

Same bits, two interpretations. Example with 8 bits: `11111111` = **255** unsigned, **-1** signed.
So "is it less than 5?" has opposite answers. That is why the CPU has two families of comparison jumps, and why the jump the compiler chose reveals the original C type.

---

## 1. Introduction

- **Software engineering**: source → object code → executable. **Reverse engineering** reverses this: analyze a system to build a *higher-level representation* of it.
- **Uses of RE**: find algorithms/formats/protocols, find vulnerabilities, understand a product (e.g. to design a competing or cooperating one), decide whether something is malicious.

### Ethical aspects (course framing)

| Ethical (with valid license) | Unethical |
|---|---|
| Interconnect with a proprietary product | Bypass copy protection / DRM |
| Discover private interfaces to extend a product | Discover serial scheme, make a keygen |
| Fix vulnerabilities in a proprietary product | Create a competing product |

### Legal aspects (Czech law, as presented)

- EULAs often forbid RE, but **law has priority over a EULA**.
- Czech Author's Act 121/2000 Coll., **§ 66**: a legitimate user may study/test a program to learn its ideas and principles (1d), and may RE for **interoperability** if the info isn't otherwise readily available (1e).
- **§ 66(4)**: info obtained for interoperability must not be passed on, nor used to build a similar competing program.
- The lecture warns to **beware of paragraph 1(b)**.
- This is the course's framing, not legal advice.

---

## 2. RE essentials

### Amount of information

Source code (names, comments, separate files) > object code (some debug info) > executable (almost nothing, everything merged). Going back is hard because information was lost. Recovered source is generally **not recompilable**; source → exe → source → exe round-trips are unrealistic.

### Disassembly vs decompilation

- **Disassembly**: machine code → assembly. Accurate but huge. Can be hampered by obfuscation (opaque predicates, API call obfuscation), encoding, packing.
- **Decompilation**: machine code → higher-level language (usually C). Not 100%, no round trips.

### Dead code (static) analysis

Analysis of a **non-running** executable, typically with a disassembler.
1. Disassemble. 2. Don't read it raw: too many lines. 3. **Reduce LOC**: identify the compiler, statically linked library code and data, drop them. 4. Annotate with everything extractable (segments, class names, strings, RTTI, exception info, stack frames, parameter types from known API calls). 5. A human studies what's left. 6. Even the disassembler can get confused.

### Live code (dynamic) analysis

Analysis of a **running** target, typically in a debugger: breakpoints, watchpoints, inspecting registers and memory at run time. Software can resist (anti-debugging, killer threads, CRC checks for software breakpoints; Lecture 6).

---

## 3. ABI (Application Binary Interface)

Defines: parameter passing, stack/data alignment, register use (volatile vs preserved), name mangling, struct/class layout, virtual function calls, RTTI, exceptions.

### Data alignment

Misaligned access is slower (or impossible on some CPUs, e.g. MC68000 can't read a 4-byte word from an odd address). Compilers pad structs. Alignment differs between compilers, which can break interoperability, so it can be controlled with `.align` (assembly) or `#pragma pack` (C/C++).

```c
#pragma pack(push)       // store current alignment
#pragma pack(1)          // 1-byte boundary from here on
typedef struct _MYSTRUCT {
    char f_Field1;
    char f_Filler1[1];   // manual filler to align f_Int
    int  f_Int;
} MYSTRUCT;
#pragma pack(pop)        // restore
```

> [!warning] Table caveat
> The slide text I had for the alignment tables (static data vs struct member alignment, MSVC vs GCC, i386 vs x86_64) was inconsistent between its two tables. **Check the numbers in the original slides** rather than trusting any summary.

### Stack alignment

- 32-bit systems traditionally align the stack to 4 bytes (but compilers often realign to 16); 64-bit systems align to **16 bytes**.
- `call` pushes the return address (4 bytes in 32-bit, 8 in 64-bit), which knocks the stack off 16-byte alignment.
- `main` in the lecture realigns with `and esp, 0xfffffff0`. Functions are padded with `xchg ax,ax` so the next one starts at a 16-byte boundary.

### Name mangling (Microsoft: "decoration")

C++ allows overloading, so extra info is encoded in the symbol name: name, namespaces/classes, const/volatile, public/protected/private, argument types (sometimes return type), scalar vs vector.

Example: `?_GetOutputTechnologyString@CDisplayData@@AAEXPAGHH@Z`

| Part | Meaning |
|---|---|
| `?_GetOutputTechnologyString` | method name |
| `@CDisplayData@@` | class `CDisplayData` (`@` is a delimiter) |
| `A` | private |
| `A` | neither const nor volatile |
| `E` | `__thiscall` |
| `X` | returns void |
| `PAG` | pointer to unsigned short |
| `H` `H` | int, int |
| `@Z` | end |

Result: `private __thiscall void CDisplayData::_GetOutputTechnologyString(CDisplayData* this, unsigned short*, int, int);`
Real prototype: `void CDisplayData::_GetOutputTechnologyString(LPWSTR, int, int);`

> [!info] The `this` pointer
> A C++ method needs to know which object it works on, so the compiler secretly passes a pointer to the object as an extra first parameter. In 32-bit Windows `__thiscall` it goes in **ECX**. Fields are read as `[ecx+offset]`. `static` methods get no `this`.
> ```cpp
> class Player { int health; /* offset 0 */  int score; /* offset 4 */ };
> // reading score inside a method:  mov eax, [ecx+4]
> ```

### Register use (simplified, from the lecture)

| | Win32 (32-bit) | Linux/BSD/OS X 32-bit | Win64 | Linux/BSD/OS X 64 |
|---|---|---|---|---|
| volatile (callee may trash) | EAX, ECX, EDX, ST(0-7) | same | RAX, RCX, RDX, R8-R11, ST(0-7) | RAX, RCX, RDX, RSI, RDI, R8-R11, ST(0-7) |
| callee-saved (must preserve) | EBX, ESI, EDI, EBP | same | RBX, RSI, RDI, RBP, R12-R15 | RBX, RBP, R12-R15 |
| parameter transfer | special | special | RCX, RDX, R8, R9 | RDI, RSI, RDX, RCX, R8, R9 |

### Calling conventions

Define where parameters go, argument order, where the result is returned, and **who cleans up the stack** (caller or callee). `__cdecl` is the default for C functions, `__thiscall` for methods. The convention is part of the function's type, including pointers to it: `BOOL (__stdcall *pfn)(UINT)`. A wrong convention causes a severe bug (stack corruption).

Example call `f(1, 2, 3)`:

| Convention | Register args | Arg order | Cleanup | Function ends with |
|---|---|---|---|---|
| `__cdecl` | none | right to left | **caller** (`add esp, 0Ch`) | `ret` |
| `__stdcall` | none | right to left | callee | `ret N` |
| `__fastcall` | ECX, EDX | right to left | callee | `ret N` |
| `__thiscall` | ECX (`this`) | right to left | callee | `ret N` |
| `__pascal` | none | **left to right** | callee | `ret N` |
| GNU | (C hybrid per the table; the slide doesn't explain) | | | |

- 64-bit is simpler: Windows = RCX, RDX, R8, R9; Linux/BSD/OS X = RDI, RSI, RDX, RCX, R8, R9; caller cleans up.
- `ret N` means "return and discard N bytes of arguments". `ret 0Ch` = 12 bytes = 3 × 4-byte arguments.
- `__fastcall` example: `mov ecx,1 / mov edx,2 / push 3 / call f`, ending with `ret 4`.

**Recognition recipe**
1. Plain `ret` → `__cdecl`. `ret N` → callee cleans (`__stdcall` / `__fastcall` / `__thiscall` / `__pascal`).
2. Reads **ECX** before setting it → `__thiscall` or `__fastcall`. Also reads **EDX** → `__fastcall`.
3. Neither register read → most likely `__stdcall`.

---

## 4. Reverse engineering a function

A function = **prologue** (optional) + **body** + **epilogue** (optional). In RE, move over the prologue quickly and focus on the body.

### Prologue (MSVC / IA-32)

```asm
push ebp          ; EBP is non-volatile, save it
mov  ebp, esp     ; stack items are referenced relative to EBP
sub  esp, 20h     ; reserve 32 bytes for locals
push ebx          ; only if the function overwrites it
push esi
push edi
```

> [!tip] The one rule that matters
> - `[ebp - offset]` = **local variable**
> - `[ebp + 0 .. +3]` = saved EBP, `[ebp + 4 .. +7]` = return address
> - `[ebp + offset]` with offset ≥ **8** = **parameter** (`ebp+8` = 1st, `ebp+0Ch` = 2nd, ...)

`enter 20h, 0` does the same as push/mov/sub but costs ~12 µops vs ~4 (Haswell), so compilers rarely use it.

### Stack canaries

A random value is placed on the stack in the prologue and checked before return. If it changed (stack smashing), the program is terminated instead of returning to a possibly hijacked address.

**GCC (Linux stack protector, `-fstack-protector`)**
```asm
mov eax, gs:0x14
mov [ebp-0Ch], eax          ; insertion
...
mov ecx, [ebp-0Ch]
xor ecx, gs:0x14
je  canary_ok
call __stack_chk_fail@plt   ; check
```

**MSVC ("Buffer Security Check")**
```asm
mov eax, [___security_cookie]
xor eax, ebp
mov [ebp-4], eax            ; insertion
...
mov ecx, [ebp-4]
xor ecx, ebp
call @__security_check_cookie@4   ; check
```

**Cookie generation** (`__security_init_cookie`): initial constant `0xBB40E64E`. At startup, if the cookie is still the initial value, mix with XOR: system time (high ^ low), process ID, thread ID, tick count, performance counter (low, high). Fixups: if the result equals the initial value use `0xBB40E64F`; if the upper 16 bits are zero, shift a copy into them. Store the cookie and its complement `__security_cookie_complement`. Unpredictable per run, and XOR with EBP makes it differ per frame.

### Structured Exception Handling (SEH, 32-bit Windows)

MSVC C `__try/__except/__finally` and C++ `try/catch` are built on SEH.

```c
struct EXCEPTION_REGISTRATION {
    EXCEPTION_REGISTRATION* prev;   // previous record
    LPVOID handler;                 // handler address
};
```

- Records are a **linked list on the stack**; a pointer to the top one is at **`fs:[0]`** (first field of the Thread Information Block).
- Install a raw record:
  ```asm
  push ebp / mov ebp, esp
  push MyExceptionHandler   ; .handler
  push fs:[0]               ; .prev
  mov  fs:[0], esp          ; new top
  ```
- Remove: `mov eax,[ebp-8]` / `mov fs:[0], eax`.

**What happens on an exception:** OS calls the top handler → it accepts or refuses → if it refuses, follow `prev` and ask the next → repeat; at the end of the list the OS "last resort" handler kills the program (or attaches a debugger).

```c
EXCEPTION_DISPOSITION __cdecl except_handler(
    struct _EXCEPTION_RECORD* ExceptionRecord,  // code, address, flags
    void* EstablisherFrame,                      // -> EXCEPTION_REGISTRATION of the faulting frame
    struct _CONTEXT* ContextRecord,              // thread state
    void* DispatcherContext);
```

**Unwinding:** once a handler accepts, the chain is called **again** with `EH_UNWINDING` set in `ExceptionFlags`, up to the handling frame, to run cleanup (C++ destructors, `__finally` blocks).

#### MSVC extension (SEH3/SEH4)

The MSVC **runtime** (not the OS) provides `_except_handler3` / `_except_handler4`, which need two extra fields:

```c
struct EH3_EXCEPTION_REGISTRATION {
    EH3_EXCEPTION_REGISTRATION* prev;
    LPVOID handler;                  // -> _except_handler3/4
    SCOPETABLE_ENTRY* ScopeTable;    // usually in a read-only section
    DWORD TryLevel;                  // current try block id
};
struct _SCOPETABLE_ENTRY {
    DWORD  EnclosingLevel;           // parent try block
    LPVOID* FilterFunc;              // "do I want this exception?"
    LPVOID* HandlerFunc;             // the __except body
};
```

- **One record per function**, however many `__try` blocks. Entering a try block = writing its id into `TryLevel`.
- On an exception the handler: reads `TryLevel` → indexes the scope table → calls `FilterFunc`. "Mine": call `HandlerFunc` and set `TryLevel = EnclosingLevel`. "Not mine": go to `EnclosingLevel` and ask that parent.
- Top-level index: **-2** for C `__try`, **-1** for C++ `try`. If even that refuses, control returns to the OS's normal SEH chain.
- **SEH4** additionally XORs the scope table pointer with the security cookie.

**Annotated SEH4 prologue** (record at `ebp-10h`: prev `-10h`, handler `-0Ch`, ScopeTable `-8`, TryLevel `-4`):

```asm
push ebp / mov ebp,esp
push 0FFFFFFFEh               ; TryLevel = -2           (ebp-4)
push 418540h                  ; scope table             (ebp-8)
push 411069h                  ; __except_handler4       (ebp-0Ch)
mov  eax, fs:[0]
push eax                      ; prev                    (ebp-10h)
sub  esp, 10h
mov  eax, [__security_cookie]
xor  [ebp-8], eax             ; obfuscate scope table pointer
xor  eax, ebp
mov  [ebp-1Ch], eax           ; canary
push ebx / esi / edi
lea  eax, [ebp-10h]           ; EAX = &record
mov  fs:[0], eax              ; record becomes top of chain
mov  [ebp-18h], esp           ; save stack top
```

Fingerprints to look for: `push 0FFFFFFFEh`, a scope-table push, and `fs:[0]` read and write.

```asm
; __try body
mov  [ebp-4], 0               ; enter try block 0
mov  dword ptr ds:[0], 0      ; NULL write -> exception
mov  [ebp-4], 0FFFFFFFEh      ; leave try (only if no exception)
jmp  after_block

; filter code (called by the SEH handler, not by the function)
mov eax,[ebp-14h]   ; GetExceptionInformation()
mov ecx,[eax]       ; -> ExceptionRecord
mov edx,[ecx]       ; -> ExceptionCode
mov [ebp-5Ch],edx
... push both; call MyExceptionFilter; add esp,8
ret                 ; returns to the SEH handler

; __except body
mov esp,[ebp-18h]   ; restore saved stack top (stack was unwound)
... printf ...
mov [ebp-4],0FFFFFFFEh
mov ecx,[ebp-10h]   ; prev
mov fs:[0],ecx      ; remove our record from the chain
; normal epilogue
```

`mov esp,[ebp-18h]` is needed because the exception may be raised deep inside nested calls, so ESP is unknown when the `__except` body starts.

#### Who installs the fallback handler?

```
ThreadRoutine                   <- your code
kernel32!BaseThreadInitThunk    <- no SEH, just calls your routine
ntdll!__RtlUserThreadStart      <- this one has the SEH
ntdll!_RtlUserThreadStart
```

`__RtlUserThreadStart` calls `__SEH_prolog4` and writes `TryLevel` (0 on entry, -2 on exit), so it contains a `__try`:

```c
__try {
    if (Kernel32ThreadInitThunkFunction)
        result = Kernel32ThreadInitThunkFunction(NULL, pfnThreadProc, pArg);
    else { result = pfnThreadProc(pArg); RtlExitUserThread(result); }
}
__except (RtlpGetExceptionFilter(GetExceptionInformation())) {
    ZwTerminateProcess(GetCurrentProcess(), GetExceptionCode());
}
```

The OS "last resort" is an ordinary `__try/__except` at the base of every thread whose handler kills the process.

#### SEH exploit (pop-pop-ret)

Idea: overflow a buffer into the `EXCEPTION_REGISTRATION` in the same frame, then trigger an exception.

1. Overwrite `handler` with the address of a **`pop reg; pop reg; ret`** sequence found in the program.
2. Put the attacker's code bytes in `prev` (the first 4 bytes of the exploit code).
3. Trigger any exception → the OS calls the "handler" (= the gadget).

Stack at handler entry (`__cdecl`):

| Position | Contents |
|---|---|
| `[esp]` | return address (into `ExecuteHandler2`) |
| `[esp+4]` | `ExceptionRecord*` |
| `[esp+8]` | **`EstablisherFrame*`** (address of the registration record) |
| `[esp+12]` | `ContextRecord*` |
| `[esp+16]` | `DispatcherContext*` |

The two `pop`s discard `[esp]` and `[esp+4]`; `ret` then pops **`EstablisherFrame*`** and jumps to it, which is the **start of the record on the stack, i.e. the `prev` field**, now holding attacker bytes. The OS itself passes in the address, so the attacker needn't know the stack address in advance; he relies on the fixed handler argument layout.

- Opcodes `5x 5y C3` with x, y in {8..F} except `C` (`5C` = `pop esp`, unsuitable).
- Requires an **executable stack**.
- `prev` is only 4 bytes, so in practice it holds a tiny jump over the `handler` field to a larger payload (general exploit knowledge, **not on the slides**).

### Epilogue

Destroys the frame, restores non-volatile registers, returns (optionally cleaning arguments), and checks the canary if one is used.

| Variant | Code |
|---|---|
| MSVC IA-32 `__cdecl` | `mov esp,ebp / pop ebp / ret` |
| MSVC IA-32 `__stdcall` | `mov esp,ebp / pop ebp / ret 8` |
| GNU IA-32 | `leave / ret` |
| GNU x86_64 | `leaveq / retq` |

### Summary checklist (what to read off a function quickly)

- **Prologue:** where it starts; bytes of locals; stack aligned?; frame pointer used?; canary?; SEH?; parameter expected in ECX → `__thiscall` or `__fastcall` (and EDX too → `__fastcall`).
- **Epilogue:** where it ends; canary checked?; `EXCEPTION_REGISTRATION` restored?; `ret XXX` → `__stdcall`/`__thiscall`, plain `ret` → `__cdecl`.

---

## 5. Stack frame analysis (the core skill)

For every instruction that touches the frame (`mov`, `push`, `lea`, ...), record:

1. **Offset**: `ebp-8` is a local, `ebp+8` a parameter.
2. **Size**: `dword ptr` = 4, `word ptr` = 2, `byte ptr` = 1 (`qword` = 8).
3. **Address taken** (`lea eax,[ebp-218h]`): marks a **buffer** starting at that offset.

At this stage use only unknown-signedness types (`UINT64`, `DWORD`, `WORD`, `BYTE`) and generic names: `local_offset` / `arg_offset` (short: `l_off`, `a_off`). `MSVC` provides `__LOCAL_SIZE` (bytes of locals), useful with `__declspec(naked)`.

### Worked example

```asm
00412ad0 push ebp
00412ad1 mov  ebp,esp
00412ad3 sub  esp,25Ch                      ; 25Ch = 604 bytes for locals
00412ad9 mov  eax,[__security_cookie]
00412ade xor  eax,ebp
00412ae0 mov  [ebp-4],eax                   ; canary (not a real variable)
00412ae3 push ebx / esi / edi               ; end of prologue
```

```asm
mov dword ptr [ebp-8],   0                  ; dword
mov dword ptr [ebp-0Ch], 0                  ; dword
mov dword ptr [ebp-10h], 0                  ; dword
mov dword ptr [ebp-21Ch],0                  ; dword
lea eax,[ebp-218h]                          ; address taken -> buffer at ebp-218h
```

Frame layout, lowest address to highest:

| Offset | Size | What |
|---|---|---|
| `ebp-21Ch` | 4 | dword (becomes `HRESULT hr`) |
| `ebp-218h` | **520** | buffer (`WCHAR[MAX_PATH]`) |
| `ebp-10h` | 4 | dword (return value) |
| `ebp-0Ch` | 4 | dword (function pointer) |
| `ebp-8` | 4 | dword (`HMODULE`) |
| `ebp-4` | 4 | canary |
| `ebp` | 4 | saved EBP |
| `ebp+4` | 4 | return address |
| `ebp+8` | 4 | `a_008`, first parameter |

> [!check] Buffer size, two independent confirmations
> - From the frame: gap between `ebp-218h` and `ebp-10h` = 536 - 16 = **520 bytes**
> - From the API: `MAX_PATH` (260, from the Windows headers) × 2 bytes per `WCHAR` = **520 bytes** (the `W` suffix means wide / UTF-16, 2 bytes per character; `A` = 1-byte ANSI)
>
> When both agree you can be confident. If they don't, suspect a misread frame.

```asm
push eax / push 0 / push 0 / push 25h / push 0        ; args pushed right to left
call SHGetFolderPathW                                  ; last param pszPath (the buffer) is the FIRST push
mov  [ebp-21Ch],eax
cmp  [ebp-21Ch],0
jge  loc_ok                                            ; jge -> signed -> HRESULT
jmp  loc_end                                           ; negative = failure, skip to return
```

```asm
push offset string / lea eax,[ebp-218h] / push eax
call PathAppendW                      ; append string to the path in the buffer
lea  eax,[ebp-218h] / push eax
call LoadLibraryW
mov  [ebp-8],eax                      ; HMODULE
cmp  [ebp-8],0 / jne continue         ; non-zero = loaded OK
mov  [ebp-10h],0 / jmp end            ; else result = 0

push offset string2 / mov eax,[ebp-8] / push eax
call GetProcAddress                   ; (module, name)
mov  [ebp-0Ch],eax
cmp  [ebp-0Ch],0 / je skip
mov  eax,[ebp+8] / push eax           ; 1st parameter
call [ebp-0Ch]                        ; call THROUGH the function pointer
mov  [ebp-10h],eax
skip:
mov  eax,[ebp-8] / push eax
call FreeLibrary
mov  [ebp-8],0
end:
mov  eax,[ebp-10h]                    ; return value
; epilogue: pop edi/esi/ebx, check canary, mov esp,ebp, pop ebp, ret (plain ret -> __cdecl)
```

### Signedness analysis

Look at the conditional jump after a `cmp` / `test` / arithmetic instruction.

| Family | Jumps | Flags | Meaning |
|---|---|---|---|
| above / below | `ja/jnbe`, `jae/jnc`, `jb/jc/jnae`, `jbe/jna` | CF (and ZF) | **unsigned** |
| greater / less | `jg/jnle`, `jge/jnl`, `jl/jnge`, `jle/jng` | SF, OF (and ZF) | **signed** |
| overflow / sign | `jo`, `jno`, `js`, `jns` | OF / SF | signed |
| equal | `je/jz`, `jne/jnz` | ZF | **no information** |

Why it works: the compiler picks the jump from the C type (`int` → `jge`, `unsigned` → `jae`), because the two give different answers for the same bits. So the jump is a fingerprint of the original type. It is evidence, not proof.

In the example, `cmp [ebp-21Ch],0` + `jge` ⇒ `l_21c` is signed ⇒ `int`.

### API call analysis

Documented Windows API signatures reveal exact types, sizes and even content.

1. **Buffer:** last param of `SHGetFolderPathW` (`pszPath`) is `MAX_PATH` WCHARs ⇒ 520 bytes ⇒ fills the buffer ⇒ `WCHAR buf_218[MAX_PATH]`.
2. **`SHGetFolderPathW`** returns `HRESULT` (signed, 4 bytes) ⇒ `l_21c` becomes `HRESULT`.
3. **`PathAppendW`** appends a string to a path (result ≤ `MAX_PATH` chars); nothing new.
4. **`LoadLibraryW`** returns `HMODULE`, stored in `ebp-8` ⇒ `HMODULE`. Later passed as the first argument to `GetProcAddress` and `FreeLibrary`, which confirms it. `jne` alone says nothing about type; the API signature does.
5. **`GetProcAddress`**(HMODULE, char*) returns a function pointer, stored in `ebp-0Ch`; `call [ebp-0Ch]` calls through it. The string argument names the function (`SetProcessDEPPolicy`), so the pointer is `BOOL (__stdcall *)(DWORD)` (one pushed arg, callee cleans up).
6. The pointer is called with `a_008`; the result (4-byte `BOOL`, kept as `DWORD`) goes to `ebp-10h`.

Two sources of type information: **jumps give signedness, API signatures give exact types.**

### Final reconstruction

```c
DWORD __cdecl UnknownFunction(DWORD a_008)
{
    HRESULT hr = S_OK;                                       // ebp-21Ch
    WCHAR   wszLibraryPath[MAX_PATH];                        // ebp-218h (520 B)
    DWORD   dwResult = 0;                                    // ebp-10h
    BOOL (__stdcall *pfnSetProcessDEPPolicy)(DWORD) = NULL;  // ebp-0Ch
    HMODULE hLibrary = NULL;                                 // ebp-8

    hr = SHGetFolderPathW(0, 0x25, 0, 0, wszLibraryPath);
    if (hr >= 0) {
        PathAppendW(wszLibraryPath, L"...");                 // string not shown in the lecture
        hLibrary = LoadLibraryW(wszLibraryPath);
        if (hLibrary != NULL) {
            pfnSetProcessDEPPolicy = GetProcAddress(hLibrary, "SetProcessDEPPolicy");
            if (pfnSetProcessDEPPolicy != NULL)
                dwResult = pfnSetProcessDEPPolicy(a_008);
            FreeLibrary(hLibrary);
            hLibrary = NULL;
        }
    }
    return dwResult;
}
```

In words: finds a system folder, loads a DLL from it, dynamically resolves `SetProcessDEPPolicy` (likely because it doesn't exist on older Windows), calls it with the parameter, returns the result (0 on any failure).

> [!warning] Not from the slides
> - `0x25` = `CSIDL_SYSTEM` is from my recollection of the Windows headers.
> - The appended string and "the DLL is kernel32" are inferences, not shown in the lecture.

---

## 6. Practice questions and answers

| # | Question | Answer |
|---|---|---|
| 1 | Function ends with `ret 0Ch`, reads `[ecx+4]` with ECX never initialized. Convention? How many stack params? | Likely **`__thiscall`** (possibly `__fastcall`), **3 stack parameters** (12 ÷ 4); `this` is in ECX, not counted. Assumes **32-bit**; `ret N` and ECX only make sense there. |
| 2 | `cmp [ebp-14h], 5` then `jb`: signed or unsigned? | **Unsigned** (`jb` is in the above/below family). |
| 3 | Why does `pop; pop; ret` work as an SEH exploit gadget? Where does `ret` jump? | `ret` jumps to **`EstablisherFrame`**, the address of the `EXCEPTION_REGISTRATION` on the stack, i.e. the `prev` field now containing attacker code. The OS supplies the address. Needs an executable stack. |

### Mistakes made along the way (so I don't repeat them)

- Said the OS "holds the handlers" at `EstablisherFrame`. Wrong: the record lives on the **stack in the vulnerable frame**; the CPU executes the **attacker's bytes** there.
- Wrote "the start of the current exception"; correct is "the start of the `EXCEPTION_REGISTRATION`".
- Assumed `je/jne` could type `ebp-8`. It can't; the **API return type** (`HMODULE`) does.
- Layout slip: `ebp-21Ch` is **below** the buffer, not between it and `ebp-10h`.
- The conventions `ret N`, `__stdcall`, `__thiscall` and ECX only apply to **32-bit**.

---

## 7. Self-check (still open, answers not yet given)

1. In the SEH assembly, which instruction tells you the function uses **SEH4** rather than a plain handler?
2. A function has two nested `__try` blocks but only one `EXCEPTION_REGISTRATION`. How does the handler know which block you were in?
3. Why does the `__except` body start with `mov esp,[ebp-18h]`?

> [!hint] Pointers
> 1. Look at what happens to the scope table pointer right after the pushes (the cookie), and the handler address pushed.
> 2. `TryLevel` + scope table.
> 3. Think about where ESP could be when an exception is raised.

---

## 8. Priority guide for revision

- **Know well:** frame partitioning (3 rules), signedness table, API call analysis, calling convention recognition, prologue/epilogue, SEH record and `TryLevel`/scope table, pop-pop-ret.
- **Look up when needed:** alignment tables, register usage table, cookie generation details.
- **Skim once:** legal and ethical slides (exams may ask).
- Check the syllabus or past assignments for what is actually assessed.

## References (from the lecture)

1. Wikipedia: Software Engineering
2. Chikofsky and Cross: *Reverse engineering and design recovery: A taxonomy*, IEEE Software, 1990
3. Fog A.: *Calling conventions for different C++ compilers and operating systems*, 2014
4. Pietrek M.: *A Crash Course on the Depths of Win32 Structured Exception Handling*, 1997
5. Russinovich, Solomon, Ionescu: *Windows Internals Part 1*, 6th ed., 2012
6. Skochinsky I.: *Compiler Internals: Exceptions and RTTI*, Recon 2012
