; Columnar Transposition Cipher (32-bit Linux, NASM, int 0x80)
; Assignment-ready upgrades:
;   - Select 1 of 3 plaintext files (msg1.txt/msg2.txt/msg3.txt), load into memory
;   - Support 500+ chars (buffer size increased)
;   - Ask user for key length (5–10)
;   - Random key permutation (Fisher–Yates with time-based seed)
;   - Encrypt + decrypt
;   - Print approximate key entropy (log2(L!)) from a table
;   - Optional brute-force crack without secret key via permutation search + crib substring
;
; Assemble:
;   nasm -f elf32 cipher.asm -o cipher.o
; Link:
;   ld -m elf_i386 -L. -lAlong32 -o cipher cipher.o

%define MAX_TEXT_LEN 2048
%define MIN_KEY_LEN  5
%define MAX_KEY_LEN 10
%define MAX_INPUT_LEN 64
%define MAX_CRIB_LEN  32

section .data
    ; --- Filenames ---
    file1       db "msg1.txt",0
    file2       db "msg2.txt",0
    file3       db "msg3.txt",0

    ; --- Prompts / labels ---
    promptFile  db "Select plaintext file (1=msg1.txt, 2=msg2.txt, 3=msg3.txt): ",0
    promptKeyL  db "Enter key length (5-10): ",0
    promptCrack db "Brute-force crack without key? (y/n): ",0
    promptCrib  db "Enter crib substring to search for (example:  the  ): ",0

    promptPT    db "Plaintext:     ",0
    promptKey   db "Key (order):   ",0
    promptEnt   db "Entropy(bits): ",0
    promptCT    db "Ciphertext:    ",0
    promptDT    db "Decrypted text:",0

    promptFound db "[CRACK FOUND] Key: ",0
    promptFail  db "[CRACK] Not found (ran out of permutations).",0

    newlineStr  db 10,0

    ; --- State ---
    textLen     dd 0
    keyLen      dd 0
    numRows     dd 0
    totalCells  dd 0
    cipherLen   dd 0

    seed        dd 0
    tmpChar     db 0

    ; Entropy strings for log2(L!) for L=5..10
    ; (approx): 5!=120->6.91, 6!=720->9.49, 7!=5040->12.30, 8!=40320->15.30,
    ;           9!=362880->18.47, 10!=3628800->21.79
    ent5        db "6.91",0
    ent6        db "9.49",0
    ent7        db "12.30",0
    ent8        db "15.30",0
    ent9        db "18.47",0
    ent10       db "21.79",0

section .bss
    ; Buffers
    inputBuf    resb MAX_INPUT_LEN
    cribBuf     resb MAX_CRIB_LEN

    plainBuf    resb MAX_TEXT_LEN + 1
    matrix      resb MAX_TEXT_LEN
    cipherText  resb MAX_TEXT_LEN + 1
    decryptText resb MAX_TEXT_LEN + 1

    key         resb MAX_KEY_LEN

section .text
    global _start

; ------------------------------------------------------------
; syscalls helpers:
;   sys_read  eax=3, ebx=fd, ecx=buf, edx=len
;   sys_write eax=4, ebx=fd, ecx=buf, edx=len
;   sys_open  eax=5, ebx=filename, ecx=flags, edx=mode
;   sys_close eax=6, ebx=fd
;   sys_time  eax=13, ebx=tloc
; ------------------------------------------------------------

_start:
    ; 1) Select file and load plaintext into plainBuf, set textLen
    call select_and_load_plaintext

    ; 2) Ask user for key length 5-10
    call ask_key_length

    ; 3) Compute numRows and totalCells
    call compute_dimensions

    ; 4) Build matrix row-wise, pad with '_'
    call build_matrix

    ; 5) RNG seed from time()
    call init_rng

    ; 6) key = 0..keyLen-1 and shuffle
    call init_key
    call shuffle_key

    ; 7) Encrypt & decrypt
    call encrypt
    call decrypt

    ; 8) Print results (includes entropy)
    call print_all

    ; 9) Optional brute-force crack (without key) using crib
    call crack_prompt_and_run

    ; Exit
    mov eax, 1
    xor ebx, ebx
    int 0x80

; ------------------------------------------------------------
; print_string: ESI -> zero-terminated string
; ------------------------------------------------------------
print_string:
    push eax
    push ebx
    push ecx
    push edx
    push edi

    mov edi, esi
    xor ecx, ecx
.ps_len_loop:
    cmp byte [edi], 0
    je  .ps_len_done
    inc edi
    inc ecx
    jmp .ps_len_loop
.ps_len_done:
    mov eax, 4
    mov ebx, 1
    mov edx, ecx
    mov ecx, esi
    int 0x80

    pop edi
    pop edx
    pop ecx
    pop ebx
    pop eax
    ret

; ------------------------------------------------------------
; print_n: ESI -> buffer, ECX -> length
; ------------------------------------------------------------
print_n:
    push eax
    push ebx
    push ecx
    push edx

    mov eax, 4
    mov ebx, 1
    mov edx, ecx
    mov ecx, esi
    int 0x80

    pop edx
    pop ecx
    pop ebx
    pop eax
    ret

; ------------------------------------------------------------
; read_line: reads up to EDX bytes into ECX (fd=0)
; returns EAX=bytes_read
; ------------------------------------------------------------
read_line:
    mov eax, 3
    mov ebx, 0
    int 0x80
    ret

; ------------------------------------------------------------
; strip_newline: (ECX=buf, EAX=len) => new len in EAX
; removes trailing '\n' and optional '\r'
; ------------------------------------------------------------
strip_newline:
    cmp eax, 0
    jle .done
    mov edx, eax
    dec edx
    cmp byte [ecx + edx], 10
    jne .check_cr
    dec eax
.check_cr:
    cmp eax, 0
    jle .done
    mov edx, eax
    dec edx
    cmp byte [ecx + edx], 13
    jne .done
    dec eax
.done:
    ret

; ------------------------------------------------------------
; parse_int: parse positive integer from buffer ECX length EAX
; returns EAX=value (0 if none)
; ------------------------------------------------------------
parse_int:
    push ebx
    push edx
    xor ebx, ebx        ; value
    xor edx, edx        ; i
.pi_loop:
    cmp edx, eax
    jge .pi_done
    mov dl, [ecx + edx]
    cmp dl, '0'
    jb  .pi_done
    cmp dl, '9'
    ja  .pi_done
    ; value = value*10 + (dl-'0')
    imul ebx, ebx, 10
    sub dl, '0'
    movzx edx, dl
    add ebx, edx
    ; restore i by recomputing from stack-free approach:
    ; we used edx for digit; so we need a separate counter.
    ; easiest: use ESI as counter instead
.pi_done:
    ; This approach consumed EDX. We'll re-implement cleanly below.
    pop edx
    pop ebx
    xor eax, eax
    ret

; ------------------------------------------------------------
; parse_int_simple: ECX=buf, EAX=len => EAX=value
; (uses ESI as index)
; ------------------------------------------------------------
parse_int_simple:
    push ebx
    push esi
    xor ebx, ebx
    xor esi, esi
.pis_loop:
    cmp esi, eax
    jge .pis_done
    mov dl, [ecx + esi]
    cmp dl, '0'
    jb  .pis_done
    cmp dl, '9'
    ja  .pis_done
    imul ebx, ebx, 10
    sub dl, '0'
    movzx edx, dl
    add ebx, edx
    inc esi
    jmp .pis_loop
.pis_done:
    mov eax, ebx
    pop esi
    pop ebx
    ret

; ------------------------------------------------------------
; select_and_load_plaintext
;  - asks user 1/2/3
;  - opens msg#.txt
;  - reads file into plainBuf
;  - sets textLen
; ------------------------------------------------------------
select_and_load_plaintext:
.ask:
    mov esi, promptFile
    call print_string

    mov ecx, inputBuf
    mov edx, MAX_INPUT_LEN
    call read_line            ; EAX=bytes
    mov ecx, inputBuf
    call strip_newline        ; EAX=new len

    ; read first char
    cmp eax, 0
    jle .ask
    mov al, [inputBuf]
    cmp al, '1'
    je  .use1
    cmp al, '2'
    je  .use2
    cmp al, '3'
    je  .use3
    jmp .ask

.use1: mov ebx, file1
      jmp .open
.use2: mov ebx, file2
      jmp .open
.use3: mov ebx, file3

.open:
    ; fd = open(filename, O_RDONLY=0, mode=0)
    mov eax, 5
    mov ecx, 0
    mov edx, 0
    int 0x80
    cmp eax, 0
    jl  .ask                ; if open failed, reprompt
    mov edi, eax            ; fd

    ; read(fd, plainBuf, MAX_TEXT_LEN)
    mov eax, 3
    mov ebx, edi
    mov ecx, plainBuf
    mov edx, MAX_TEXT_LEN
    int 0x80
    cmp eax, 0
    jle .close
    ; strip trailing newline from file read
    mov ecx, plainBuf
    call strip_newline
    mov [textLen], eax
    ; null-terminate for safety
    mov edx, eax
    mov byte [plainBuf + edx], 0

.close:
    mov eax, 6
    mov ebx, edi
    int 0x80
    ret

; ------------------------------------------------------------
; ask_key_length: prompts, parses int, enforces 5..10
; sets [keyLen]
; ------------------------------------------------------------
ask_key_length:
.loop:
    mov esi, promptKeyL
    call print_string

    mov ecx, inputBuf
    mov edx, MAX_INPUT_LEN
    call read_line
    mov ecx, inputBuf
    call strip_newline          ; EAX=len

    mov ecx, inputBuf
    call parse_int_simple       ; EAX=value
    cmp eax, MIN_KEY_LEN
    jl  .loop
    cmp eax, MAX_KEY_LEN
    jg  .loop
    mov [keyLen], eax
    ret

; ------------------------------------------------------------
; compute_dimensions
;   numRows   = ceil(textLen / keyLen)
;   totalCells = numRows * keyLen
; ------------------------------------------------------------
compute_dimensions:
    mov eax, [keyLen]
    dec eax
    add eax, [textLen]
    mov ebx, [keyLen]
    xor edx, edx
    div ebx
    mov [numRows], eax

    mov eax, [numRows]
    mov ebx, [keyLen]
    mul ebx
    mov [totalCells], eax
    ret

; ------------------------------------------------------------
; build_matrix: fill row-wise from plainBuf, pad with '_'
; ------------------------------------------------------------
build_matrix:
    mov esi, plainBuf
    mov edi, matrix
    mov ecx, [totalCells]
    xor ebx, ebx

.bm_loop:
    cmp ebx, [textLen]
    jae .pad
    mov al, [esi + ebx]
    inc ebx
    jmp .store
.pad:
    mov al, '_'
.store:
    mov [edi], al
    inc edi
    loop .bm_loop
    ret

; ------------------------------------------------------------
; init_rng: seed=time(NULL)
; ------------------------------------------------------------
init_rng:
    xor ebx, ebx
    mov eax, 13
    int 0x80
    mov [seed], eax
    ret

; ------------------------------------------------------------
; rand32: LCG
; ------------------------------------------------------------
rand32:
    mov eax, [seed]
    mov ebx, 1103515245
    mul ebx
    add eax, 12345
    mov [seed], eax
    ret

; ------------------------------------------------------------
; init_key: key[i]=i
; ------------------------------------------------------------
init_key:
    mov ecx, [keyLen]
    mov edi, key
    xor eax, eax
.ik_loop:
    cmp ecx, 0
    je  .done
    mov [edi], al
    inc edi
    inc al
    dec ecx
    jmp .ik_loop
.done:
    ret

; ------------------------------------------------------------
; shuffle_key: Fisher-Yates
; ------------------------------------------------------------
shuffle_key:
    mov esi, [keyLen]
    dec esi
.outer:
    cmp esi, 0
    jle .done
    push esi
    call rand32
    pop esi

    mov ebx, esi
    inc ebx
    xor edx, edx
    div ebx            ; remainder in EDX = j

    mov edi, key
    mov bl, [edi + esi]
    mov cl, [edi + edx]
    mov [edi + esi], cl
    mov [edi + edx], bl

    dec esi
    jmp .outer
.done:
    ret

; ------------------------------------------------------------
; encrypt: read columns in key order -> cipherText
; ------------------------------------------------------------
encrypt:
    mov edi, cipherText
    mov eax, [totalCells]
    mov [cipherLen], eax

    xor ecx, ecx
.enc_outer:
    cmp ecx, [keyLen]
    jge .done
    movzx ebx, byte [key + ecx]   ; column
    xor esi, esi                  ; row
.enc_inner:
    cmp esi, [numRows]
    jge .next_col
    mov eax, esi
    mul dword [keyLen]
    add eax, ebx
    mov dl, [matrix + eax]
    mov [edi], dl
    inc edi
    inc esi
    jmp .enc_inner
.next_col:
    inc ecx
    jmp .enc_outer
.done:
    mov byte [edi], 0
    ret

; ------------------------------------------------------------
; decrypt: fill columns from cipherText using current key -> matrix
; then copy first textLen bytes -> decryptText
; ------------------------------------------------------------
decrypt:
    mov esi, cipherText
    xor ecx, ecx
.dec_outer:
    cmp ecx, [keyLen]
    jge .cols_done
    movzx ebx, byte [key + ecx]   ; column
    xor edi, edi                  ; row
.dec_inner:
    cmp edi, [numRows]
    jge .next_col
    mov eax, edi
    mul dword [keyLen]
    add eax, ebx
    mov dl, [esi]
    mov [matrix + eax], dl
    inc esi
    inc edi
    jmp .dec_inner
.next_col:
    inc ecx
    jmp .dec_outer
.cols_done:
    mov esi, matrix
    mov edi, decryptText
    mov ecx, [textLen]
.copy:
    cmp ecx, 0
    je  .done
    mov al, [esi]
    mov [edi], al
    inc esi
    inc edi
    dec ecx
    jmp .copy
.done:
    mov byte [edi], 0
    ret

; ------------------------------------------------------------
; print_key: prints digits of key
; ------------------------------------------------------------
print_key:
    push eax
    push ebx
    push ecx
    push edx
    push esi
    push edi

    mov esi, key
    mov eax, [keyLen]
    add eax, key
    mov edi, eax
.loop:
    cmp esi, edi
    jae .done
    movzx eax, byte [esi]
    add al, '0'
    mov [tmpChar], al
    mov eax, 4
    mov ebx, 1
    mov ecx, tmpChar
    mov edx, 1
    int 0x80
    inc esi
    jmp .loop
.done:
    pop edi
    pop esi
    pop edx
    pop ecx
    pop ebx
    pop eax
    ret

; ------------------------------------------------------------
; print_entropy: prints log2(L!) approx string
; ------------------------------------------------------------
print_entropy:
    mov eax, [keyLen]
    cmp eax, 5
    je .e5
    cmp eax, 6
    je .e6
    cmp eax, 7
    je .e7
    cmp eax, 8
    je .e8
    cmp eax, 9
    je .e9
    cmp eax, 10
    je .e10
    ret
.e5:  mov esi, ent5  ; "6.91"
      jmp .out
.e6:  mov esi, ent6
      jmp .out
.e7:  mov esi, ent7
      jmp .out
.e8:  mov esi, ent8
      jmp .out
.e9:  mov esi, ent9
      jmp .out
.e10: mov esi, ent10
.out:
    call print_string
    ret

; ------------------------------------------------------------
; print_all: plaintext, key, entropy, ciphertext, decrypted
; ------------------------------------------------------------
print_all:
    mov esi, promptPT
    call print_string
    mov esi, plainBuf
    mov ecx, [textLen]
    call print_n
    mov esi, newlineStr
    call print_string

    mov esi, promptKey
    call print_string
    call print_key
    mov esi, newlineStr
    call print_string

    mov esi, promptEnt
    call print_string
    call print_entropy
    mov esi, newlineStr
    call print_string

    mov esi, promptCT
    call print_string
    mov esi, cipherText
    mov ecx, [cipherLen]
    call print_n
    mov esi, newlineStr
    call print_string

    mov esi, promptDT
    call print_string
    mov esi, decryptText
    mov ecx, [textLen]
    call print_n
    mov esi, newlineStr
    call print_string
    ret

; ============================================================
; ===============  BRUTE FORCE CRACK SECTION  =================
; Strategy:
;   - Ask y/n
;   - If yes: read crib substring (strip newline, store cribLen)
;   - Set key = 0..L-1 (identity)
;   - For each permutation:
;       decrypt with current key
;       if decrypted contains crib -> print key + decrypted and stop
;       else next_permutation; if none -> fail
; ============================================================

crack_prompt_and_run:
    mov esi, promptCrack
    call print_string
    mov ecx, inputBuf
    mov edx, MAX_INPUT_LEN
    call read_line
    cmp eax, 0
    jle .done
    mov al, [inputBuf]
    cmp al, 'y'
    je  .do
    cmp al, 'Y'
    je  .do
    jmp .done

.do:
    mov esi, promptCrib
    call print_string
    mov ecx, cribBuf
    mov edx, MAX_CRIB_LEN
    call read_line
    mov ecx, cribBuf
    call strip_newline        ; EAX=cribLen
    mov ebx, eax              ; EBX = cribLen
    cmp ebx, 1
    jl  .done

    ; Reset key to identity for brute force
    call init_key

.loop:
    ; Decrypt using current key
    call decrypt

    ; Check contains( decryptText, cribBuf )
    push ebx
    call contains_crib
    pop ebx
    cmp eax, 1
    je  .found

    ; next permutation; if none, fail
    call next_permutation
    cmp eax, 1
    je  .loop

    ; fail
    mov esi, promptFail
    call print_string
    mov esi, newlineStr
    call print_string
    jmp .done

.found:
    mov esi, promptFound
    call print_string
    call print_key
    mov esi, newlineStr
    call print_string

    ; print decrypted text (full)
    mov esi, decryptText
    mov ecx, [textLen]
    call print_n
    mov esi, newlineStr
    call print_string
.done:
    ret

; ------------------------------------------------------------
; contains_crib:
; returns EAX=1 if cribBuf occurs in decryptText, else 0
; Assumes EBX=cribLen
; ------------------------------------------------------------
contains_crib:
    push ebx
    push ecx
    push edx
    push esi
    push edi

    mov edx, ebx          ; cribLen in EDX
    mov eax, [textLen]
    cmp eax, edx
    jl  .no

    xor esi, esi          ; pos = 0
.outer:
    ; if pos > textLen - cribLen -> no
    mov eax, [textLen]
    sub eax, edx
    cmp esi, eax
    jg  .no

    ; compare cribLen bytes
    xor edi, edi          ; i=0
.inner:
    cmp edi, edx
    jge .yes
    mov al, [decryptText + esi + edi]
    mov cl, [cribBuf + edi]
    cmp al, cl
    jne .next
    inc edi
    jmp .inner

.next:
    inc esi
    jmp .outer

.yes:
    mov eax, 1
    jmp .done
.no:
    xor eax, eax
.done:
    pop edi
    pop esi
    pop edx
    pop ecx
    pop ebx
    ret

; ------------------------------------------------------------
; next_permutation on key[0..L-1] lexicographic
; returns EAX=1 if next exists, EAX=0 if last permutation reached
; ------------------------------------------------------------
next_permutation:
    push ebx
    push ecx
    push edx
    push esi
    push edi

    mov ecx, [keyLen]
    cmp ecx, 2
    jl  .none

    ; i = L-2
    mov esi, ecx
    sub esi, 2

.find_i:
    ; find largest i where a[i] < a[i+1]
    mov al, [key + esi]
    mov bl, [key + esi + 1]
    cmp al, bl
    jb  .found_i
    dec esi
    cmp esi, -1
    jne .find_i
    jmp .none

.found_i:
    ; j = L-1, find largest j where a[j] > a[i]
    mov edi, ecx
    dec edi
    mov dl, [key + esi]        ; pivot

.find_j:
    mov al, [key + edi]
    cmp al, dl
    ja  .found_j
    dec edi
    jmp .find_j

.found_j:
    ; swap a[i], a[j]
    mov al, [key + esi]
    mov bl, [key + edi]
    mov [key + esi], bl
    mov [key + edi], al

    ; reverse suffix i+1 .. L-1
    mov ebx, esi
    inc ebx                    ; left = i+1
    mov edx, ecx
    dec edx                    ; right = L-1

.rev_loop:
    cmp ebx, edx
    jge .ok
    mov al, [key + ebx]
    mov bl, [key + edx]
    mov [key + ebx], bl
    mov [key + edx], al
    inc ebx
    dec edx
    jmp .rev_loop

.ok:
    mov eax, 1
    jmp .done

.none:
    xor eax, eax
.done:
    pop edi
    pop esi
    pop edx
    pop ecx
    pop ebx
    ret
