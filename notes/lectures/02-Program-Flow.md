---
title: NIE-REV Lecture 2 - Analysis of a Program's Flow
course: NIE-REV (Reverse Engineering)
lecturers: Tomáš Zahradnický, Josef Kokeš (CTU FIT Prague)
tags: [reverse-engineering, assembly, pe-format, windows, cfg, iat]
---

# Lecture 2: Analysis of a Program's Flow

**Contents:** [[#1. Control flow analysis]] · [[#2. Entry point, initialization, termination]] · [[#3. Miscellaneous]] · [[#4. Import Address Table]] · [[#5. Cheat sheet and self-test]]

> [!info] Legend
> Everything in this note is from the slides unless marked **(extra)**. **(extra)** = explained in our tutoring session, not on the slides.
> Also marked: **(slide bug)** where a slide is wrong.

---

## 1. Control flow analysis

### 1.1 Basic block (BB) (slide 3)

> **Basic Block [NIE-GEN]:** the maximal sequence of consecutive instructions where the flow of control can only enter and can only leave the block through the first instruction and the last instruction of the block, respectively.

Goal: with the stack frame analyzed and locals identified, reconstruct a **Control Flow Graph (CFG)**, and later higher-level constructs (`if-then-else`, `do-while` / `for` / `while`).

**Finding blocks (extra):** mark the *leaders* (first instruction of a block):
1. the first instruction of the function
2. any instruction that is the **target** of a jump
3. any instruction **right after** a jump or `ret`

A block runs from one leader up to the next. Blocks never overlap.

**Worked example (slide 8 function, extra):** 4 blocks.

| Block | Range | Ends with |
|---|---|---|
| BB1 | `77e2a8cd`-`77e2a8da` | `ja loc_77e5547c` (conditional, 2 edges) |
| BB2 | `77e2a8e0`-`77e2a8e5` | falls through (next is a jump target, so it must end here) |
| BB3 | `77e2a8e7`-`77e2a8e8` | `retn 8` (2 incoming edges: from BB2 and BB4) |
| BB4 | `77e5547c`-`77e55487` | `jmp loc_77e2a8e7` |

### 1.2 Constructing a CFG (slide 4)

- each BB is a **vertex**
- control flow is an **oriented edge** between BBs
- CFG gives initial higher-level insight; it is one input to a **decompiler**, which recognizes known patterns and reconstructs high-level code
- Not always straightforward, especially with **obfuscation** (e.g. **Opaque Predicates**)

In IDA graphs: the red edge = condition false (fall-through), green = jump taken, blue = unconditional.

### 1.3 If-then (slides 5-7)

```c
if( condition )
  expression;
```

Assembly pseudo-code:

```
comparison op testing the condition
jxx skip_away
expression
skip_away:
```

**Key idea (extra):** the jump is the **inverse** of the C condition, because it *skips* the body. C `if (x > 10)` becomes `jle skip`.

**With CMP/TEST** (slide 5, `kernel32!StringCbPrintfW`):

```
77e3c7a0 shr ecx, 1
77e3c7a2 push 0
77e3c7a4 pop eax
77e3c7a5 jz  short loc_77e3c7e5
// The cmp instruction sets flags, based on the comparison result
77e3c7a7 cmp ecx, 7fffffffh
77e3c7ad ja  short loc_77e3c7e5
...
77e3c7e5 mov eax, 80070057h   // HRESULT_FROM_WIN32( ERROR_INVALID_PARAMETER )
77e3c7ea jmp short loc_77e3c7af
```

**Without CMP/TEST** (slide 6): flags can be set by a non-comparison (arithmetic) instruction:

```
77e3c798 mov edi, edi         // A 2-byte NOP for hot patching
77e3c79a push ebp
77e3c79b mov ebp, esp
77e3c79d mov ecx, [ebp+c]     // Load 2nd parameter into ECX
77e3c7a0 shr ecx, 1           // Unsigned divide by 2, set ZF and CF
77e3c7a2 push 0
77e3c7a4 pop eax
// shr sets/clears ZF in EFL if the result is/isn't zero
// push and pop do not manipulate flags in EFL
77e3c7a5 jz  short loc_77e3c7e5
```

**CFG (slide 7):** `__if_then` has 3 blocks: header (`printf("Zacatek")`, `cmp [ebp+arg_0], 0Ah`, `jle loc_37`), then-block (`printf("%d je vetsi nez 10")`), and `loc_37` (`printf("Konec")`, `xor eax,eax`, `pop ebp`, `retn`). The `jle` skips the then-block.

### 1.4 If-then-else (slides 8-9)

```c
if( condition ) expression1;
else            expression2;
```

Slide 8 (`kernel32!UIntPtrToInt`):

```
77e2a8cd mov edi, edi
77e2a8cf push ebp
77e2a8d0 mov ebp, esp
77e2a8d2 mov eax, [ebp+8]
77e2a8d5 cmp eax, 7fffffffh
77e2a8da ja  loc_77e5547c
77e2a8e0 mov ecx, [ebp+c]
77e2a8e3 mov [ecx], eax
77e2a8e5 xor eax, eax // Fall thru
77e2a8e7 loc_77e2a8e7:
77e2a8e7 pop ebp
77e2a8e8 retn 8
77e5547c loc_77e5547c:
77e5547c mov eax, [ebp+c]
77e5547f or  dword ptr [eax], 0ffffffffh
77e55482 mov eax, 80070216h // HRESULT_FROM_WIN32( ERROR_ARITHMETIC_OVERFLOW )
77e55487 jmp loc_77e2a8e7   // Jump back
```

Pattern: one path falls through, the other is placed elsewhere and **jumps back** to a common join point.

**CFG (slide 9):** header block with `jle loc_79` splits into two blocks (`"%d je vetsi nez 10"` ending with `jmp short loc_8A`, and `loc_79: "%d neni vetsi nez 10"`), which both join at `loc_8A` (`"Konec"`).

### 1.5 Loops (slides 10-15)

**while** (slide 10):

```c
while( condition ) body;
```

```
00401561 push ebp
00401562 mov  ebp,esp
00401564 loc_0401564:
00401564 mov   eax,dword ptr [ebp+c]
00401567 movsx ecx,byte ptr [eax]
0040156a test  ecx,ecx          // Test the condition
0040156c je    loc_040158c      // Jump after the loop if failed
0040156e mov   edx,dword ptr [ebp+8]
00401571 mov   eax,dword ptr [ebp+c]
00401574 mov   cl,byte ptr [eax]
00401576 mov   byte ptr [edx],cl
00401578 mov   edx,dword ptr [ebp+8]
0040157b add   edx,1
0040157e mov   dword ptr [ebp+8],edx
00401581 mov   eax,dword ptr [ebp+c]
00401584 add   eax,1
00401587 mov   dword ptr [ebp+c],eax
0040158a jmp   loc_0401564     // Perform next iteration
0040158c loc_040158c:
0040158c pop ebp
0040158d ret
```

Shape: **test at the top** (`je` out of loop) + **unconditional `jmp` back** at the bottom. CFG (slide 11): header, a loop-condition block `loc_B8` (`cmp eax,[ebp+arg_0]` / `jge loc_DC`), a body block with `jmp loc_B8` back, and the exit block `loc_DC`.

**do-while** (slide 12):

```c
do { body; } while(condition);
```

```
00401340 mov   edx,dword ptr [esp+4]
00401344 mov   eax,dword ptr [esp+8]
00401348 loc_0401348:
00401348 movzx ecx,byte ptr [eax]
0040134b lea   eax,[eax+1]
0040134e mov   byte ptr [edx],cl
00401350 movzx ecx,byte ptr [eax-1]
00401354 test  cl,cl             // Test the condition
00401356 jne   loc_0401348h      // Perform next iteration
00401358 ret
```

Shape: **no top test**, a single **conditional jump at the bottom** goes back to the start. That is why it needs fewer jumps than `while`. CFG on slide 13: loop block ends with `jl loc_108`.

> [!note] No stack frame here
> This function creates **no stack frame**: parameters are accessed via **ESP** directly. Code is smaller and faster, **but each `push` changes the offset** of parameters and locals. Compile-time switches: `-fomit-frame-pointer` (GCC), `/Oy` (MSVC).

**for** (slide 14):

```c
for( initialization; condition; increment ) { body; }
```

```
00401280 mov  ecx,dword ptr [esp+4]
00401284 xor  eax,eax
00401286 test ecx,ecx          // Enter the loop?
00401288 jle  loc_040129c      // No - jump after it
0040128a lea  ebx,[ebx]
00401290 loc_0401290:
00401290 mov  dword ptr [eax*4+403020h],eax
00401297 inc  eax              // Perform the increment
00401298 cmp  eax,ecx          // Test the condition
0040129a jl   loc_0401290      // Perform next iteration
0040129c loc_040129c:
         ret
```

- `for` can have any part empty, so it can express a `while` (omit/move init and increment). The generated code is the same as for `while`, so **you cannot tell whether the original was `for` or `while`**. The decompiler sticks to one of them.
- **(extra)** Notice this one is shaped like a do-while with a guard in front (`test`/`jle` before the loop, test at the bottom). Compilers often do this to save one jump per iteration.
- CFG (slide 15): `loc_163` tests `jge loc_17E`, the body jumps to `loc_15A` (the increment block), which jumps back to `loc_163`.

### 1.6 Switch (slides 16-19)

All three variants implement:

```c
switch( arg ) {
  case 1: statement_1; break;
  case 2: statement_2; break;
  case 3: statement_3; break;   // (absent in the sub/dec variant)
  case 4: statement_4; break;
  default: statement_n; break;
}
```

**Variant 1: cmp chain** (slide 16): comparisons binary-search the cases.

```
8048389 mov 0x8(%ebp),%eax   // Load arg. into EAX
804838c cmp $0x2,%eax
804838f je  0x80483df        // arg == 2
8048391 jle 0x80483c0        // arg < 2 -> check 1
8048393 cmp $0x3,%eax
8048396 je  0x80483b2        // arg == 3
8048398 cmp $0x4,%eax
...
80483a0 jne 0x80483d1        // not 4 -> default
80483a2 movl $0x8048595,(%esp) ; call puts   // case 4
80483c0 dec %eax             // Dec/sub instruction commonly used!
80483c1 jne 0x80483d1        // not 1 -> default
80483c3 movl $0x8048570,(%esp)               // case 1
```

(Note: `nop` and `lea 0x0(%esi,%eiz,1),%esi` at `804839b`/`804839c` are alignment padding.)

**Variant 2: sub/dec chain** (slide 17, cases 1, 2, 4 only):

```
00401000 mov eax, [esp+4]
00401004 dec eax
00401005 jz  short loc_401042   ; arg was 1 -> noParameter
00401007 dec eax
00401008 jz  short loc_401031   ; arg was 2 -> oneParameter
0040100A sub eax, 2
0040100D jz  short loc_401020   ; arg was 4 -> threeParameters
0040100F push offset defaultCase
00401014 call ds:printf
0040101A add esp, 4
0040101D xor eax, eax           // return 0, duplicated
0040101F retn                   // Function exit, duplicated
```

Each case block ends with its own duplicated `xor eax,eax` / `retn` (the compiler duplicates the epilogue).

**Variant 3: jump table** (slide 18):

```
00401000 mov eax, [esp+4]
00401004 dec eax
00401005 cmp eax, 3
00401008 ja  short loc_401055         ; default
0040100A jmp ds:off_401068[eax*4]     // Jump to a table item
00401011 push offset zeroParameters   ; table entry 0
...
00401022 push offset oneParameter     ; entry 1
00401033 push offset twoParameters    ; entry 2
00401044 push offset threeParameters  ; entry 3
00401055 push offset defaultCase
```

Jump table (data):

```
00401068 dd offset loc_401011
0040106C dd offset loc_401022
00401070 dd offset loc_401033
00401074 dd offset loc_401044
```

**(extra) How the jump table works:**
- `dec eax` maps cases 1..4 to indices 0..3.
- `jmp [table + eax*4]` **reads** a 4-byte code address from the table (it does not "leave" the table), then jumps there. `*4` because each entry is 4 bytes.
- `cmp eax, 3` / `ja` is an **unsigned** compare. `arg = 0` gives `0 - 1 = 0xFFFFFFFF`, which is huge, so it is "above 3" and goes to **default**. One compare catches both "too small" and "too big".

| arg | after `dec` | result |
|---|---|---|
| 0 | `0xFFFFFFFF` | default |
| 1 | 0 | `zeroParameters` (entry 0) |
| 2 | 1 | `oneParameter` |
| 3 | 2 | `twoParameters` |
| 4 | 3 | `threeParameters` |
| 5 | 4 | default |

**CFG (slide 19):** header block (`sub ecx,1`, `cmp [ebp+var_4],5`, `ja default`) -> block with `jmp ds:$LN11[edx*4]` ("switch jump") -> **6 case blocks** side by side (cases 0-5) -> all converge on `loc_228` (default / join). A jump-table switch shows up as a **wide fan-out** in the CFG.

### 1.7 Summary of control flow (slide 20)

You should now:
- understand the prologue and epilogue
- understand the stack frame and its structure
- understand what a Basic Block is
- be able to construct a CFG of a function
- understand how C constructs compile to assembly and translate them back to higher-level code

Next: what the runtime does when a program starts (entry point, initializers, `main`, terminators).

---

## 2. Entry point, initialization, termination

### 2.1 The main entry point (slides 21-23)

`main` / `wmain` / `_tmain` are **not** the real entry point. The real one is the function whose **RVA is in `AddressOfEntryPoint`** in the PE optional header.

Slide 21 finds it from code:

```c
// Get HMODULE of the current process
HMODULE hSelf = GetModuleHandle(NULL);                 // = LoadLibrary, ...
// Cast HMODULE to pointer to PE image start. Points to MZ... - the DOS header
PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hSelf;
// New header is located e_lfanew bytes from the start of the image
PIMAGE_NT_HEADERS32 pNTHeaders =
    (PIMAGE_NT_HEADERS)(((BYTE*)pDosHeader) + pDosHeader->e_lfanew);
// Entry point RVA + image base
void* pfnEntryPoint = (void*)(((BYTE*)pDosHeader)
                      + pNTHeaders->OptionalHeader.AddressOfEntryPoint);
printf("Entry point address: %p\n", pfnEntryPoint);   // 00402390
```

**Call stack** (slide 22, bottom = oldest):

```
004136C0 Tokens.exe!main(int argc, const char* * argv)   // The C entry point
00402259   Tokens.exe!__tmainCRTStartup()
0040239D     Tokens.exe!mainCRTStartup()                 // The main entry point
75C4EE0A       kernel32.dll!@BaseThreadInitThunk@12()
775A37C4         ntdll.dll!___RtlUserThreadStart@8()
775A37A3           ntdll.dll!__RtlUserThreadStart@8()
```

**Who provides it?** The **runtime** (`crtexe.c`), slide 23:

```c
int mainCRTStartup( void )
{
  /* The /GS security cookie must be initialized before any exception
   * handling targetting the current image is registered. No function
   * using exception handling can be called in the current image until
   * after __security_init_cookie has been called. */
  __security_init_cookie();
  return __tmainCRTStartup();
}
```

Name varies with settings (`UNICODE` defined or not; `main` vs `WinMain`):
1. `mainCRTStartup` 2. `wmainCRTStartup` 3. `WinMainCRTStartup` 4. `wWinMainCRTStartup`

### 2.2 `__tmainCRTStartup()` (slide 24)

```c
__declspec(noinline) int __tmainCRTStartup( void )
{
  __try {
    ...
    // Run initializers placed into .crt$xia ... .crt$xiz segs (merged into .rdata)
    // __xi_a and __xi_z bound initializer data start and end
    // calls pre_c_init(), by default initialize C, sets default FPU mode,
    // sets the unhandled exception filter to __CxxUnhandledExceptionFilter
    if( _initterm_e( __xi_a, __xi_z ) != 0 )
      return 255;

    // Run initializers placed into .crt$xca ... .crt$xcz segs (placed into .rdata)
    // calls pre_cpp_init(), sets atexit(_RTC_Terminate), prepares parameters for main,
    // calls all constructors of static objects and registers a stub calling
    // appropriate destructors using the atexit function.
    _initterm( __xc_a, __xc_z );

    // Call whichever main function we have!
    mainret = main(argc, argv, envp);
    ...
    exit(mainret);
  }
  __except( _XcptFilter( GetExceptionCode(), GetExceptionInformation() ) ) {
    // _XcptFilter terminates, inaccessible
    mainret = GetExceptionCode();
    ExitProcess(mainret);
  }
  return mainret;
}
```

> [!tip] Startup order (memorize)
> `__security_init_cookie` -> `_initterm_e` (**C** inits, abort with **255** on non-zero) -> `_initterm` (**C++** inits, incl. global-object constructors) -> `main` -> `exit()` -> atexit handlers in **reverse** order -> pre-terminators `__xp_*` -> terminators `__xt_*` -> `ExitProcess`.

**(extra) Finding `main` on a stripped binary:** start at the entry point, follow `mainCRTStartup` into `__tmainCRTStartup`. After the two `_initterm` calls, look for a call with 3 arguments (`argc`, `argv`, `envp`) whose return value is passed to `exit`. That is `main`.

### 2.3 Initialization code (slides 25-26)

Easy way: a **global C++ object** (slide 25):

```cpp
// A globally initialized class
Initializer g_InitializerClassInstance;

class Initializer {
public:
  Initializer()  { printf("Hello pre-main code.\n"); }
  ~Initializer() { printf("Hello post-main code.\n"); }
};
```

GCC: `__attribute__((constructor))` / `__attribute__((destructor))` give the same for C code.

**Hard way**, fine-grained control with `#pragma` (slide 26):

```c
#pragma section(".CRT$XIB")
__declspec(allocate(".CRT$XIB")) int (*g_MyInit_PreC)(void) = MyInit_PreC;

#pragma section(".CRT$XIY")
__declspec(allocate(".CRT$XIY")) int (*g_MyInit_PostC)(void) = MyInit_PostC;

// XCT = pre static objects constructors
// XCU = post static objects constructors
#pragma section(".CRT$XCB")
__declspec(allocate(".CRT$XCB")) void (*g_MyInit_PreCPP)(void) = MyInit_PreCPP;

#pragma section(".CRT$XCZ")
__declspec(allocate(".CRT$XCZ")) void (*g_MyInit_PostCPP)(void) = MyInit_PostCPP;
```

- `.CRT$XIxxx` initializers **return a value**; **non-zero aborts startup with error 255**.
- **(extra)** The linker merges and sorts `.CRT$...` sections by suffix, so `XIB` runs before `XIY`.

### 2.4 Where are the initializers? (slides 27-29)

`_initterm_e` / `_initterm` take the **begin and end pointer** of an array of function pointers in `.rdata` (following the IAT). Slide 27 shows `__xi_a` to `__xi_z` in a debug build; entries:

```
413940  pre_c_init
41108c  jmp MyInit_PreC     (debug; MyInit_PreC in release)
4110c3  jmp __atonexitinit  (debug; __atonexitinit in release)
4111b3  jmp MyInit_PostC    (debug; MyInit_PostC in release)
411122  jmp ___CxxSetUnhandledExceptionFilter (debug; direct jump in release)
```

(Debug entries are `jmp` thunks, see [[#3.3 Call to a jmp (slides 35-36)]].)

`_initterm_e` (slide 28):

```c
int _initterm_e(int (**pSegStart)(void), int (**pSegEnd)(void))
{
  int initResult = 0;
  while ( pSegStart < pSegEnd && !initResult )
  {
    if ( *pSegStart )
      initResult = (*pSegStart)();
    ++pSegStart;
  }
  return initResult;
}
```

Non-null pointer -> call it. **Aborts as soon as any initializer returns non-zero** (unlike the C++ `_initterm`, which ignores return values).

`__xc_a` to `__xc_z` in release (slide 29), C++-style entries:

```
000000  -
4012dd  pre_cpp_init
401030  MyInit_PreCPP
401000  Initializer ctor stub
401020  MyInit_PostCPP
```

The **constructor stub** for a global object:

```
00401000 mov  ecx,4031B8h          // This pointer
00401005 call Initializer::Initializer
0040100A push 401930h              // Address of the destructor stub
0040100F call atexit               // Register to be called at exit
00401014 pop  ecx                  // Stack cleanup
00401015 ret
...
00401930 mov  ecx,4031B8h          // This pointer
00401935 jmp  Initializer::~Initializer
```

So: constructing a global object **registers its destructor with `atexit`**.

### 2.5 Termination (slides 30-32)

- `atexit` stores **encoded** function pointers in a dynamically allocated array bounded by two encoded globals, `__onexitbegin` and `__onexitend`.
- Calling C `exit` (but **not** `TerminateProcess`) runs the atexit-registered functions.
- With a **statically linked runtime**, pre-termination and termination functions in `.crt$xpXXX` and `.crt$xtXXX` are called the same way as initializers.

`atexit` (slide 31, `atonexit.c`):

```c
int __cdecl atexit(void (__cdecl *func)()) {
  return _onexit(func) == NULL ? -1 : 0;
}
_onexit_t __cdecl _onexit(_onexit_t Func) {
  int (__cdecl *pfnFunc)();
  _lockexit();
  pfnFunc = _onexit_nolock(Func);
  _unlockexit();
  return pfnFunc;
}
```

`exit` (`crt0dat.c`):

```c
void __cdecl exit( int code ) {
  doexit(code, 0, 0); /* full term, kill process */
}
```

`doexit` (slide 32):

```c
void __cdecl doexit(int code, int quick, int retcaller) {
  if ( !retcaller && check_managed_app() ) // If process is managed, call CorExitProcess
    __crtCorExitProcess(uExitCode);
  ...
  if ( !quick ) {
    onexitbegin = DecodePointer(__onexitbegin); onexitend = DecodePointer(__onexitend);
    while ( 1 ) { // Iterate over all exit functions
      // Find the first "non-zero" func
      while ( --onexitend >= onexitbegin && *onexitend == EncodePointer(NULL) );
      // Ending condition
      if ( onexitend < pfn__onexitbegin ) break;
      // Decode, call, and remove the atexit registered function from the list
      pfnExitProc = (void (*)(void))DecodePointer(*onexitend);
      *onexitend = EncodePointer(0);
      pfnExitProc();
      ...
    }
    #ifndef CRTDLL
      _initterm(__xp_a, __xp_z); // Call pre-terminators
    #endif
  }
  #ifndef CRTDLL
    _initterm(__xt_a, __xt_z);   // Call terminators
  #endif
  ...
  if ( ret ) return;
  if ( !ret ) __crtExitProcess(code);
}
```

**(extra) Destructor order:** the loop uses `--onexitend`, walking the array **backwards**. Constructors register destructors in construction order (A, B, C), so destructors run **C, B, A** (last-in-first-out).

**(extra) Things that skip all of this:** `TerminateProcess` (never reaches `exit`, so no atexit handlers run). Also, a destructor does not run when `main` returns; it runs when `main`'s caller `__tmainCRTStartup` calls `exit`.

---

## 3. Miscellaneous

### 3.1 Pointer encoding (slide 33)

Function pointers stored in memory (heap/stack, e.g. the atexit array) could be overwritten to run exploit code. `EncodePointer` / `DecodePointer` make this difficult. They map to `RtlEncodePointer` / `RtlDecodePointer` in `NTDLL.DLL`:

```
77F1A295 RtlEncodePointer:
77F1A295 mov  edi, edi
77F1A297 push ebp
77F1A298 mov  ebp, esp
77F1A29A push ecx
77F1A29B push 0                      ; ReturnLength
77F1A29D push 4                      ; ProcessInformationLength
77F1A29F lea  eax, [ebp+ProcessInformation]
77F1A2A2 push eax                    ; ProcessInformation
77F1A2A3 push 24h                    ; ProcessInformationClass = process cookie
77F1A2A5 push 0FFFFFFFFh             ; ProcessHandle = GetCurrentProcess()
77F1A2A7 call _ZwQueryInformationProcess@20
77F1A2AC test eax, eax
77F1A2AE jl   loc_77F4276F
77F1A2B4 mov  eax, [ebp+ProcessInformation]
77F1A2B7 mov  cl, al
77F1A2B9 xor  eax, [ebp+arg_0]       ; xor pointer with cookie
77F1A2BC and  cl, 1Fh                ; rotate amount = low 5 bits of cookie
77F1A2BF ror  eax, cl                ; rotate right
77F1A2C1 leave
77F1A2C2 retn 4
```

**Algorithm:** get a per-process random **cookie** (class `0x24`) -> `xor` pointer with cookie -> `ror` by `cookie & 0x1F`. Decode = reverse (`rol`, then `xor`).

**(extra) Why a random per-process cookie, not a fixed key?** A fixed key would be the same in every process, so an attacker could learn it once and craft valid encoded pointers everywhere. With a random per-process cookie, they must first leak *that* process's secret.

### 3.2 Hot patching support (slide 34)

Functions start with `mov edi, edi` (a **2-byte NOP**) and have **5 `nop`s** before the function start. That's **7 bytes** of space for replacing the function at runtime without restarting the application. The `mov edi,edi` is replaced by a `jmp short` to the start of the nops, where a `jmp [addr]` is placed.

**Non-patched:**

```
90          nop
90          nop
90          nop
90          nop
90          nop
function_start:
8B FF       mov edi,edi
55          push ebp
8B EC       mov ebp,esp
```

**Patched:**

```
jump_to_patched_function:
  E9 xx xx xx xx   jmp dword ptr [&patched_function]
function_start:
  EB F9            jmp short jump_to_patched_function
  55               push ebp     // Inaccessible
  8B EC            mov ebp,esp  // Inaccessible
```

**(extra) Byte-level explanation:**

```
A-5 .. A-1   5 bytes of padding  -> become E9 xx xx xx xx   (jmp to NEW function)
A   .. A+1   mov edi, edi        -> becomes EB F9           (jmp short -7)
A+2          push ebp ...        (original code, not executed after patching)
```

- `8B FF` = `mov edi, edi` (opcode `8B`, ModRM `FF`). A harmless 2-byte instruction the compiler emits on purpose (`/hotpatch`).
- `EB` = short relative jump, `F9` = signed byte -7 (249 - 256).
- **Short jumps are relative to the END of the instruction.** `EB F9` at `A` ends at `A+2`; `A+2 - 7 = A-5` = start of the 5-byte jump.
- `E9 xx xx xx xx` = 5-byte near jump with 32-bit offset.
- Why 2-byte `mov edi,edi`? Replacing a single 2-byte instruction can be one **atomic write**, so no thread can see half of it. Write the 5-byte jump **first**, then flip the 2-byte one.
- The patch is **in-memory only** and **private to the process** (copy-on-write); the file on disk is unchanged. Making the page writable needs `VirtualProtect` first.
- A hook that wants to run the original function can enter at `A+2` (clean instruction boundary).

### 3.3 Call to a jmp (slides 35-36)

In **debug builds** every function is called through an extra level of indirection common to all functions (slide 35):

```
main:
00413130 push ebp
00413131 mov  ebp,esp
00413133 sub  esp,48h
...
00413140 call PEDUMP (4110BEh)        ; call goes to the thunk
...
PEDUMP_real:
004125F0 push ebp                     ; the real function
...
_GetCurrentProcess@0:   004110B4 jmp GetCurrentProcess (4131D0h)
PEDUMP:                 004110BE jmp PEDUMP_real (4125F0h)
___atonexitinit:        004110C3 jmp __atonexitinit (413220h)
MyInit_PreCPP:          004110D2 jmp MyInit_PreCPP (412340h)
_LoadLibraryW@4:        004110D7 jmp LoadLibraryW (4131EEh)
Initializer::Initializer: 004110E1 jmp Initializer::Initializer (412390h)
```

**Why (slide 36):** with **incremental linking** enabled, all calls go through this indirection. It lets us **replace any function at run time**: new code is compiled, copied into the process's memory, and the **redirection address is updated** to the new implementation. MSVC calls it **"Apply Code Changes"** (Debug menu, `Alt+F10`); Apple calls it **"Fix and Continue"**. Same principle.

**(extra) Terminology:** a **thunk** is a tiny stub whose only job is to forward to the real code; a **thunk table** is a block of them (here `jmp real_function`).

---

## 4. Import Address Table

### 4.1 Import Directory and IAT (slides 37-40)

A module depends on other modules. The modules and symbol names/ordinals are listed in the **Import Directory (ID)** of the PE file. **(extra)** It is data directory entry **1**; entry **0** is the Export Directory.

**Structure (slide 37):**

```
Data Directories[1] -> array of IMAGE_IMPORT_DESCRIPTOR (one per DLL, ends with a zeroed entry)

IMAGE_IMPORT_DESCRIPTOR
  OriginalFirstThunk -> array of IMAGE_THUNK_DATA ("Hints")
                         each -> IMAGE_IMPORT_BY_NAME {Hint, Name}  e.g. "CloseHandle"
                                 or an ordinal  e.g. Ordinal 0034, Ordinal 0371
  TimeDateStamp
  ForwarderChain
  Name               -> "KERNEL32.DLL"
  FirstThunk         -> the IAT (array of IMAGE_THUNK_DATA)
```

**Traversing the Import Directory (slide 38):**

```c
PIMAGE_IMPORT_DESCRIPTOR pImports = (PIMAGE_IMPORT_DESCRIPTOR)(((BYTE*)pDosHeader)
  + pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
PIMAGE_IMPORT_DESCRIPTOR pImportsEnd = (PIMAGE_IMPORT_DESCRIPTOR)(((BYTE*)pImports)
  + pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size);

for (; pImports < pImportsEnd && pImports->Characteristics != NULL; ++pImports)
{
  char* pszDLLName = (char*)((BYTE*)pDosHeader + pImports->Name);
  printf("DLL: %s\n", pszDLLName );

  if (pImports->OriginalFirstThunk != NULL)
  {
    PIMAGE_THUNK_DATA pSymbolData =
      (PIMAGE_THUNK_DATA)(((BYTE*)pDosHeader) + pImports->OriginalFirstThunk);

    for (; pSymbolData->u1.AddressOfData != NULL; ++pSymbolData )
    {
      // note: we should check the import type first...
      PIMAGE_IMPORT_BY_NAME pImport = (PIMAGE_IMPORT_BY_NAME)(((BYTE*)pDosHeader)
        + pSymbolData->u1.AddressOfData);
      printf("%04hx %s\n", pImport->Hint, pImport->Name);
    }
  }
}
```

**Disk vs memory (slide 39):** once an image is loaded, the loader **replaces all IAT references** (RVAs of `IMAGE_THUNK_DATA32` in a 32-bit PE) that point to `IMAGE_IMPORT_BY_NAME` with **real function pointers**.

Example: the first `IMAGE_THUNK_DATA` (4 bytes) contains RVA `0000248A`. Mapped into memory, that address points to an `IMAGE_IMPORT_BY_NAME` containing the hint `0267` followed by the zero-terminated name `GetModuleHandleW`. The function is from `kernel32.dll` and resolves to `75C4CD5C`, **which is written back to the IAT**. The IAT is in `.rdata`, so it is **read-only**.

| | On disk | In memory (after load) |
|---|---|---|
| `OriginalFirstThunk` array | RVAs to hint/name (or ordinals) | **unchanged** (stays as a record of names) |
| `FirstThunk` (the IAT) | **copy of the same RVAs** | **real function addresses**, written by the loader |

**Why an IAT (slide 40):** when an external symbol is bound, its address is resolved and all references updated according to the **relocation table** (see BIE-BEK, lec. 2). That is the approach for **object files**; for executables we would have to relocate **every external call** at startup. Instead, **indirection** is used and only **a single entry per symbol** is modified, the one in the IAT.

```
// A function call
00401072 push 0
00401074 call dword ptr [__imp__GetModuleHandleW@4 (402000h)]   ; indirect call through slot

// IAT
00402000 .dd 075C4CD5Ch   // KERNEL32.DLL!GetModuleHandleW
00402004 .dd 075C42CDDh   // KERNEL32.DLL!VirtualProtect
...
004020B0 .dd 06BACBB8Dh   // MSVCR120.DLL!__amsg_exit
004020B4 .dd 0            // - end -

// Implementation
_GetModuleHandleWStub@4:
75C4CD5C mov edi,edi
75C4CD5E push ebp
75C4CD5F mov ebp,esp
```

**(extra) Why indirection, not just "speed":** the address of a DLL function isn't known at build time (ASLR, different Windows versions). The code is compiled with an empty slot, and the loader fills **one slot per function** at load time. Code pages stay unmodified and can be shared between processes. The Import Directory also lets tools (and the loader) see dependencies without running the program.

**(extra) DLL code is not in your .exe.** The build only records *references* (imports) and empty slots. The DLL stays a separate file, mapped into memory by the loader at start. A debugger sees the DLL code at runtime (e.g. slide 22's call stack shows `kernel32.dll` and `ntdll.dll` frames). Exception: **statically linked** libraries (e.g. `/MT` C runtime) *are* copied into your exe.

### 4.2 IAT hacking (slides 41-42)

Calls to the same external API all go through **one point**, its IAT entry. Change that entry and **all calls to that API throughout the entire program are redirected**.

The IAT is read-only by default, but `VirtualProtect` can make it writable (slide 41):

```c
BOOL WINAPI VirtualProtect(
  LPVOID lpAddress,       // IAT_start
  SIZE_T dwSize,          // ( IAT_size + page_size - 1 ) & ( page_size - 1 )
  DWORD  flNewProtect,    // PAGE_READWRITE
  PDWORD lpflOldProtect
);
```

> [!bug] (slide bug)
> The `dwSize` formula `( IAT_size + page_size - 1 ) & ( page_size - 1 )` is wrong. To round **up** to a page multiple, mask with the complement: `& ~(page_size - 1)`. As written it keeps only the low bits and gives a tiny number.

**Beyond the process boundary (slide 42):** yes. Either use `VirtualAllocEx`, `ReadProcessMemory`, `WriteProcessMemory`, `VirtualProtectEx`, `CreateRemoteThread` to hack other processes and inject code/DLLs, or use the **Native API**:

Win32 API:

```c
BOOL WINAPI VirtualProtectEx(
  _In_  HANDLE hProcess,
  _In_  LPVOID lpAddress,
  _In_  SIZE_T dwSize,
  _In_  DWORD  flNewProtect,
  _Out_ PDWORD lpflOldProtect
);
```

NT API:

```c
NTSYSAPI NTSTATUS NTAPI NtProtectVirtualMemory(
  IN HANDLE ProcessHandle,
  IN OUT PVOID *BaseAddress,
  IN OUT PULONG NumOfBytesToProtect,
  IN ULONG NewAccessProtection,
  OUT PULONG OldAccessProtection
);
```

### 4.3 (extra) IAT hook vs hot-patch hook, and `GetProcAddress`

**Two ways a caller learns a function's address:**

1. **Import (IAT):** the loader writes the address into this module's IAT slot; code does `call [slot]`.
2. **`GetProcAddress(hDll, "Name")`:** looks up the target DLL's **Export Table** at runtime (`IMAGE_EXPORT_DIRECTORY`: names array, name-to-ordinal array, address array) and returns the address. **Does not read any IAT**, even if the caller also imports the same function.

The export table is the source of truth; each module's IAT is a per-module cached copy of the loader's results. Changing the export table affects future lookups (`GetProcAddress`, new loads) but not IAT slots already filled.

| | **IAT hook** | **Hot-patch hook** |
|---|---|---|
| What is modified | one **pointer** in one module's IAT | the **first bytes of the function itself** (inside the DLL) |
| Catches calls via this module's IAT | yes | yes |
| Catches other DLLs' IATs | **no** (own IAT) | yes |
| Catches `GetProcAddress` callers | **no** (export table untouched) | yes |
| Why | callers who don't read the slot get the real address | every route ends at the same address `A`; the CPU executes the bytes at `A` |
| Needs `VirtualProtect` | yes (IAT is read-only) | yes (code page is read+execute) |
| Risk | low (one pointer) | higher: shared code, threads may execute bytes while you write, hook must preserve original behaviour |

**Rule for hooks:** save the original address *before* overwriting. If the hook calls the original through the same slot, it calls itself forever. Restore the old protection with `lpflOldProtect` afterwards.

---

## 5. Cheat sheet and self-test

### One-line summaries

- **BB:** single entry (first instr.), single exit (last instr.); leaders = function start, jump targets, instruction after a jump.
- **CFG:** BBs = vertices, jumps/fall-through = edges.
- **if:** `jxx` skips the body; condition is **inverted**.
- **while:** test at top + `jmp` back. **do-while:** one conditional jump at bottom. **for:** same as while (init before, increment before test). Can't distinguish `for` from `while` in binary.
- **switch:** cmp chain / `dec`-`sub` chain / **jump table** (`jmp [table + idx*4]`, guarded by unsigned `cmp`/`ja`).
- **Entry point:** `AddressOfEntryPoint` in PE optional header, not `main`.
- **Startup:** cookie -> C inits (non-zero -> exit 255) -> C++ inits -> `main` -> `exit` -> atexit (reverse) -> terminators -> `ExitProcess`.
- **Global C++ object:** ctor stub calls ctor and registers the dtor via `atexit`.
- **Pointer encoding:** `ror(ptr xor cookie, cookie & 0x1F)`, random per-process cookie.
- **Hot patch:** 5 nops + `mov edi,edi`; `E9 xx xx xx xx` + `EB F9`.
- **Thunk table (debug):** `call` -> `jmp real`; retargeted by the debugger ("Apply Code Changes").
- **IAT:** loader fills one slot per imported function; hijack the slot = redirect all calls from that module.

### Self-test

1. Find the leaders in a function: `cmp`, `jz L1`, A, `jmp L2`, `L1:` B, `L2:` C. *(4 leaders: cmp, A, L1, L2; if-then-else)*
2. In a jump-table switch with `arg = 0`, where does control go and why? *(default; `0-1` wraps to `0xFFFFFFFF`, unsigned "above" 3)*
3. A `.CRT$XIB` initializer returns 1. What happens? *(exit code 255; neither C++ inits nor `main` run)*
4. Globals A, B, C are constructed in that order. Destructor order? *(C, B, A; `doexit` walks the atexit array backwards)*
5. `main` calls `TerminateProcess` instead of returning. Does `g`'s destructor run? *(no; `exit()` and atexit are never reached)*
6. `EB F9` is at `0x1000`. Where does it land? *(`0x1002 - 7 = 0xFFB`, the start of the 5-byte jump)*
7. Thunk table entry vs IAT slot? *(thunk: code `jmp`, built by the linker, retargeted by the debugger. IAT: data pointer, filled by the loader.)*
8. Why do `OriginalFirstThunk` and `FirstThunk` both exist? *(the first keeps the names; the second becomes real addresses)*
9. Which callers does an IAT hook on `MessageBoxW` miss? *(other modules' IATs, `GetProcAddress` users)*
10. Why does a hot-patch hook catch them? *(it modifies the function's own bytes, where every route ends)*

### Sources

- Slides: Zahradnický, Kokeš: *NIE-REV, 2026, Lecture 2: Analysis of a Program's Flow*, CTU FIT Prague, version Sept 1, 2026.
- Bibliography on slide 43: Russinovich, Solomon, Ionescu: *Windows Internals Part 1* and *Part 2*, 6th ed., 2012.
