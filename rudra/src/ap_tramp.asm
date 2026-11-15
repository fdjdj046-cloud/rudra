; Трамплин SIPI. Вход в реальном режиме: CS = phys>>4, IP = 0.
; Код должен уместиться до 0xE0. Параметры пишет ядро перед SIPI.
; Собирать: nasm -f bin ap_tramp.asm -o ap_tramp.bin

bits 16
org 0

start:
    cli
    cld
    mov ax, cs
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, 0x0FE0

    movzx ebp, ax
    shl ebp, 4

    mov eax, ebp
    add eax, gdt
    mov [gdtr + 2], eax
    lgdt [gdtr]

    mov eax, ebp
    add eax, pm
    mov [far_pm], eax
    mov word [far_pm + 4], 0x08

    mov eax, cr0
    or eax, 1
    mov cr0, eax
    jmp dword far [far_pm]

bits 32
pm:
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov fs, ax
    mov gs, ax
    mov esp, ebp
    add esp, 0x0FE0

    mov eax, cr4
    or eax, (1 << 5) | (1 << 7) | (1 << 9) | (1 << 10)
    mov cr4, eax

    mov eax, [ebp + param_cr3]
    mov cr3, eax

    mov ecx, 0xC0000080
    rdmsr
    or eax, (1 << 8) | (1 << 11)
    wrmsr

    mov eax, ebp
    add eax, lm
    mov edi, ebp
    add edi, far_lm
    mov [edi], eax
    mov word [edi + 4], 0x18

    mov eax, cr0
    or eax, 0x80010022
    mov cr0, eax
    jmp dword far [edi]

bits 64
lm:
    lgdt [ebp + param_gdtr]
    push 0x08
    lea rax, [rel lm_cs]
    push rax
    retfq
lm_cs:
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov ss, ax
    xor ax, ax
    mov fs, ax
    mov gs, ax
    cld
    mov rsp, [ebp + param_stack]
    mov rax, [ebp + param_entry]
    jmp rax

times (0xE0 - ($ - $$)) db 0

param_cr3:   dq 0
param_stack: dq 0
param_entry: dq 0
param_gdtr:
    dw 0
    dq 0

times (0x108 - ($ - $$)) db 0
far_pm: dd 0
        dw 0
far_lm: dd 0
        dw 0

times (0x120 - ($ - $$)) db 0
gdtr:
    dw gdt_end - gdt - 1
    dd 0
gdt:
    dq 0
    dw 0xFFFF
    dw 0
    db 0
    db 10011010b
    db 11001111b
    db 0
    dw 0xFFFF
    dw 0
    db 0
    db 10010010b
    db 11001111b
    db 0
    dw 0xFFFF
    dw 0
    db 0
    db 10011010b
    db 10101111b
    db 0
gdt_end:
