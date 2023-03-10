 ;   This is the ISHAE 128-bit encryption system, written in x86 Assembly
 ;   Copyright (C) 2022 stringzzz, Ghostwarez Co.
 ;
 ;   This program is free software: you can redistribute it and/or modify
 ;   it under the terms of the GNU General Public License as published by
 ;   the Free Software Foundation, either version 3 of the License, or
 ;   (at your option) any later version.
 ;
 ;   This program is distributed in the hope that it will be useful,
 ;   but WITHOUT ANY WARRANTY# without even the implied warranty of
 ;   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 ;   GNU General Public License for more details.
 ;
 ;   You should have received a copy of the GNU General Public License
 ;   along with this program.  If not, see <https://www.gnu.org/licenses/>.

; ISHAE-128 Version 0.03
; ISHAE: Intersperse Substitution Harmony Assembly Encryption
; Now with ARIANA PRNG

; By stringzzz
; Ghostwarez Co.
; 4-26-2022

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
; Key Schedule	Bytes	% Key	Key Bytes	Key Bits
;
; S-Box			1216	59.375	9.5			76
; P-Box			320		15.625	2.5			20
; XOR1			256		12.5	2			16
; XOR2			256		12.5	2			16
; Total			2048	100		16			128
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;;;;;;;;;;;;;;; ISHAE Algorithm ;;;;;;;;;;;;;;;;;;;
; 1. Choose e/d (encryption/decryption)
; 2. Choose the key option
; 3. Input or generated key is expanded 128 times by 
;	the key schedule (KISS)
; 4. The Key Schedule is split, some bytes used
;	to initialize the S-Box and P-Box. The rest is
;	used in the encryption/decryption loop
; 5. The encryption/decryption loop works on 128-Bit
;	blocks, for 16 cycles. Cycle below (Encryption):
;
;	a. S-Box
;	b. XOR with KS 1
;	c. S-Box
;	d. XOR with KS 2
;	e. If cycles is multiple of 4, P-Box
;
;	Decryption is simply the reverse of this
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

INCLUDE asmlib.inc							; Include library of i/o functions

CreateFileA Proto,
	fileName: PTR BYTE,
	accessMode: DWORD,
	shareMode : DWORD,
	securityAttrib : DWORD,
	creationDispo : DWORD,
	flagsAndAttrib : DWORD,
	hTemplateFile : DWORD

ReadFile PROTO,		
	hHandle:DWORD ,		
	lpBuffer:PTR BYTE,		
	nNumberOfBytesToRead: DWORD,		
	pNumberOfBytesRead: PTR DWORD,	
	lpOverlapped:PTR DWORD	
	
WriteFile PROTO,
  hHandle : DWORD,
  lpBuffer : PTR BYTE,
  nNumberOfBytesToWrite : DWORD,
  pNumberOfBytesWritten : PTR DWORD,
  lpOverlapped : PTR DWORD

CloseHandle PROTO, hObject : DWORD

GENERIC_READ     = 80000000h
GENERIC_WRITE    = 40000000h

OPEN_EXISTING      = 3
OPEN_ALWAYS        = 4

FILE_ATTRIBUTE_NORMAL  = 80h

NULL = 0

.data	
	sbox BYTE 256 DUP(0)		; Substitution Box
	revSbox BYTE 256 DUP(0)		; Reverse Substitution Box

	KSbytes_SBOX BYTE 1216 DUP(?)	; For the bytes from the Key Schedule, for use in generating S-Box
    KSbits_SBOX BYTE 1216*8 DUP(?)	; The bits from the key schedule made with sp1_8, used in TeaPArty2 to shuffle S-Box
    numBytes DWORD 1216

	pbox BYTE 32 DUP(0)		; Permutation Box
	revPbox BYTE 32 DUP(0)		; Reverse Permutation Box

	KSbytes_PBOX BYTE 320 DUP(?)	; For the bytes from the Key Schedule, for use in generating P-Box
    KSbits_PBOX BYTE 320*8 DUP(?)	; The bits from the key schedule made with sp1_8, used in TeaPArty2 to shuffle P-Box
	numNybbles DWORD 32

	KSbytes_XOR1 BYTE 256 DUP(0)	; Bytes for XORING during main encryption/decryption loop
	KSbytes_XOR2 BYTE 256 DUP(0)	; Same as above
	XOR_INDEX DWORD ?

	; TeaParty2 variables
	TeaCup1 BYTE 256 DUP(?)
	TeaCupCounter1 DWORD ?
	TeaCup2 BYTE 256 DUP(?)
	TeaCupCounter2 DWORD ?
	TeaKettle BYTE 256 DUP(?)
	TempCounter DWORD 0
	TeaShuffles DWORD ?
	TeaBoxSize DWORD ?

	; ISHAE_KISS variables
	InitKey BYTE 16 DUP(0)
	KS_Nybbles BYTE 2048*2 DUP(0)
	KS_Nybbles_Block BYTE 32 DUP(0)
	KS_Nybbles_Block2 BYTE 32 DUP(0)
	KS_ALL BYTE 2048 DUP(0)

	; File I/O Variables
	fname BYTE 64 DUP(0)
	fname2 BYTE 64 DUP(0)
	newExtension BYTE ".ISHAE_128", 0 ; 10 char
	fHandle DWORD ?	
	fHandle2 DWORD ?
	bytesRead DWORD 0
	bytesWritten DWORD 0

	; Block variables
	block BYTE 17 DUP(0)
	block2 BYTE 17 DUP(0)
	blockNybbles BYTE 32 DUP(0)
	blockNybbles2 BYTE 32 DUP(0)
	lastBlock BYTE 0
	div4 DWORD 4		; For checking if cycles is a multiple of 4

	; Encryption or Decryption prompts
	eORd BYTE 0
	eORdPrompt BYTE "Enter 'e' for encryption or 'd' for decryption: ", 0
	filenamePromptE BYTE "Enter the full name of the file to encrypt: ", 0
	filenamePromptD BYTE "Enter the full name of the file to decrypt: ", 0
	filenamePromptD2 BYTE "Enter the full name of the newly decrypted file: ", 0
	
	; For dealing with the different key options
	eKeyOptions1 BYTE "Enter an option for the key: ", 0
	eKeyOptions2 BYTE "'r': Generate PRNG key with ARIANA", 0
	eKeyOptions3 BYTE "'h': enter key as string of hex digits", 0
	eKeyOptions4 BYTE "'s': Enter the key as a string", 0
	dKeyOptions1 BYTE "Enter an option for the key: ", 0
	dKeyOptions2 BYTE "'h': enter key as string of hex digits", 0
	dKeyOptions3 BYTE "'s': Enter the key as a string", 0
	hexPrompt BYTE "Enter the key as a hex string: ", 0
	hexString BYTE 32 DUP(0)
	hexNybbles BYTE 32 DUP(0)
	keyPrompt BYTE "Enter the 16 byte key: ", 0
	genKeyMessage BYTE "Generated key in hex: ", 0

	; Status messages
	eMessage BYTE "Encrypting...", 0
	eFinMessage BYTE "Encryption complete", 0
	dMessage BYTE "Decrypting...", 0
	dFinMessage BYTE "Decryption complete", 0

	; For ARIANA PRNG
	rngPool BYTE 2048 DUP(0)
	generatedKey BYTE 16

	; Invalid input option message
	invalidMessage BYTE "Invalid option entered.", 0
				
.code

sp1_8 PROC
    ; ebx: bits array
    ; edx: bytes array
    mov ecx, numBytes
OUTER_LOOP_1:
    mov al, [edx]
    shr al, 7
    mov [ebx], al
    inc ebx
    push ecx
    mov al, 2
    movzx ecx, al
INNER_LOOP_1:
    mov al, 8
    sub al, cl
    mov ah, [edx]
    push ecx
    mov cl, al
    shr ah, cl
    pop ecx
    and ah, 1
    mov [ebx], ah
    inc ebx
    inc cl
    cmp cl, 9
    je EXIT_INNER_LOOP_1
    jmp INNER_LOOP_1
EXIT_INNER_LOOP_1:
    inc edx
    pop ecx
    loop OUTER_LOOP_1
    ret
sp1_8 ENDP

sp1_2 PROC
    ; ebx: nybbles array
    ; edx: bytes array
	; numBytes number of bytes in the bytes array
    mov ecx, numBytes
SPLIT1TO2_LOOP_1:
    mov al, [edx]
    shr al, 4
    mov [ebx], al
    inc ebx
    mov al, [edx]
    and al, 15
    mov [ebx], al
    inc ebx
    inc edx
    loop SPLIT1TO2_LOOP_1
    ret
sp1_2 ENDP

jn2_1 PROC
    ; ebx: bytes array
	; edx: nybbles array
	; numNybbles number of nybbles in the nybbles array
	push edx
    mov eax, numNybbles
    mov edx, 0
    mov ecx, 2
    div ecx
    mov ecx, eax
    pop edx
JOIN2TO1_LOOP:
   mov al, [edx]
   shl al, 4
   inc edx
   mov ah, 0
   mov ah, [edx]
   xor al, ah
   inc edx
   mov [ebx], al
   inc ebx
   loop JOIN2TO1_LOOP
    
    ret
jn2_1 ENDP

RotateBytes PROC
    ; al byte to rotate
    mov ah, al
    shr al, 7
    shl ah, 1
    xor al, ah
    ret
RotateBytes ENDP

TeaParty2 PROC
	; ebx list of KS bits
	; eax initial S-Box or P-Box
	; TeaBoxSize size of Box in bytes
	; TeaShuffles, 38 for S-Box, 80 for P-Box
	; Output in TeaKettle

	mov ecx, 0
MOVE_TO_KETTLE:					; Move the initial P-Box in eax to the TeaKettle
	mov dl, [eax]
	inc eax
	mov TeaKettle[ecx], dl
	inc ecx
	cmp ecx, TeaBoxSize
	jne MOVE_TO_KETTLE

	mov ecx, TeaShuffles			; Repeat the shuffling process TeaShuffles times
INNER_TP_LOOP1:
	push ecx
	mov ecx, TeaBoxSize				; Repeat for each output byte of the Box
	mov TeaCupCounter1, 0
	mov TeaCupCounter2, 0
	mov TempCounter, 0
BREW_LOOP:						; If current KS bit is 1, current TeaKettle bytes goes in Teacup1, else TeaCup2
	push ecx
	mov ecx, 0
	mov dl, [ebx]
	inc ebx
	cmp dl, 1
	je CUP1
	mov ecx, TempCounter
	mov dl, TeaKettle[ecx]
	inc ecx
	mov TempCounter, ecx
	mov ecx, TeaCupCounter2
	mov TeaCup2[ecx], dl
	inc ecx
	mov TeaCupCounter2, ecx
	jmp OUTSIDE_CUP
CUP1:
	mov ecx, TempCounter
	mov dl, TeaKettle[ecx]
	inc ecx
	mov TempCounter, ecx
	mov ecx, TeaCupCounter1
	mov TeaCup1[ecx], dl
	inc ecx
	mov TeaCupCounter1, ecx
OUTSIDE_CUP:
	pop ecx
	loop BREW_LOOP

	; Reassemble the bytes in TeaKettle, TeaCup2 + TeaCup1 (Concatenate the bytes into TeaKettle)
	mov ecx, 0
	mov TempCounter, 0
	cmp TeaCupCounter2, 0
	je MOVE_CUP1_TO_KETTLE
MOVE_CUP2_TO_KETTLE:
	mov dl, TeaCup2[ecx]
	inc ecx
	push ecx
	mov ecx, TempCounter
	mov TeaKettle[ecx], dl
	inc ecx
	mov TempCounter, ecx
	pop ecx
	cmp ecx, TeaCupCounter2
	jne MOVE_CUP2_TO_KETTLE

	mov ecx, 0
	cmp TeaCupCounter1, 0
	je OUTSIDE_TO_KETTLE
MOVE_CUP1_TO_KETTLE:
	mov dl, TeaCup1[ecx]
	inc ecx
	push ecx
	mov ecx, TempCounter
	mov TeaKettle[ecx], dl
	inc ecx
	mov TempCounter, ecx
	pop ecx
	cmp ecx, TeaCupCounter1
	jne MOVE_CUP1_TO_KETTLE

OUTSIDE_TO_KETTLE:				; Shuffle cycle complete, check if outer loops complete
	pop ecx
	dec ecx
	cmp ecx, 0
	jne INNER_TP_LOOP1

	ret
TeaParty2 ENDP

Build_SBOX PROC
	; Generate starting S-Box values
	; Need 1216 bytes in KSbytes_SBOX

	mov ecx, 0					; Set ecx to zero for indexing
SBOX_initLoop:					; Loop for S-Box initilization
	mov sbox[ecx], cl			; store current cl into sbox at index ecx
	inc ecx						; Increment ecx
	cmp ecx, 256				; Compare ecx with 256, quit loop if at 256
	jne SBOX_initLoop			; reloop if not at 256

	; Split the KS bytes into bits
	mov ebx, OFFSET KSbits_SBOX
	mov edx, OFFSET KSbytes_SBOX
	mov numBytes, 1216
	call sp1_8

	; Use TeaParty2 to shuffle the output bytes of the S-Box
	mov eax, OFFSET sbox
	mov ebx, OFFSET KSbits_SBOX
	mov TeaShuffles, 38
	mov TeaBoxSize, 256
	call TeaParty2

	; Move the shuffled output bytes back into sbox
	mov ecx, 0
	mov eax, OFFSET sbox
	mov edx, 0
MOVE_SB_KETTLE_TO_EAX:
	mov dl, TeaKettle[ecx]
	inc ecx
	mov [eax], dl
	inc eax
	cmp ecx, 256
	jne MOVE_SB_KETTLE_TO_EAX

	ret
Build_SBOX ENDP

Build_REV_SBOX PROC
	; Generate reverse S-Box
	mov ecx, 0					; Move zero into ecx for indexing
	mov eax, 0					; Clear out eax, for safety
revSBLoop:						; Loop to generate reverse S-Box
	mov al, sbox[ecx]			; Move S-Box output byte at index ecx to al
	mov revSbox[eax], cl		; Move current cl number into revSbox at index eax
	inc ecx						; Increment ecx
	cmp ecx, 256				; Compare ecx to 256, quit loop if matched
	jne revSBLoop				; No match? Continue loop

	ret
Build_REV_SBOX ENDP

Build_PBOX PROC
	; Generate starting P-Box values
	; Need 320 bytes in KSbytes_PBOX

	mov ecx, 0					; Set ecx to zero for indexing
initLoop_PB:					; Loop for P-Box initilization
	mov pbox[ecx], cl			; store current cl into pbox at index ecx
	inc ecx						; Increment ecx
	cmp ecx, 32					; Compare ecx with 32, quit loop if at 32
	jne initLoop_PB				; reloop if not at 32

	; Split the KS bytes into bits
	mov ebx, OFFSET KSbits_PBOX
	mov edx, OFFSET KSbytes_PBOX
	mov numBytes, 320
	call sp1_8

	; Use TeaParty2 to shuffle the output bytes of the P-Box
	mov eax, OFFSET pbox
	mov ebx, OFFSET KSbits_PBOX
	mov TeaShuffles, 80
	mov TeaBoxSize, 32
	call TeaParty2

	; Move the shuffled output bytes back into pbox
	mov ecx, 0
	mov eax, OFFSET pbox
MOVE_PB_KETTLE_TO_EAX:
	mov dl, TeaKettle[ecx]
	inc ecx
	mov [eax], dl
	inc eax
	cmp ecx, TeaBoxSize
	jne MOVE_PB_KETTLE_TO_EAX

	ret
Build_PBOX ENDP

Build_REV_PBOX PROC
	; Generate reverse P-Box
	mov ecx, 0					; Move zero into ecx for indexing
	mov eax, 0					; Clear out eax, for safety
revPBLoop:						; Loop to generate reverse P-Box
	mov al, pbox[ecx]			; Move P-Box output byte at index ecx to al
	mov revPbox[eax], cl		; Move current cl number into revPbox at index eax
	inc ecx						; Increment ecx
	cmp ecx, 32					; Compare ecx to 32, quit loop if matched
	jne revPBLoop				; No match? Continue loop

	ret
Build_REV_PBOX ENDP

transferKS PROC
COPY_TO_KS_BYTES:
	mov dl, [eax]
	inc eax
	mov [ebx], dl
	inc ebx
	loop COPY_TO_KS_BYTES

	ret
transferKS ENDP

ISHAE_KISS PROC
	; ISHAE-128 Key Initialize Scheduling Subroutine
	; Expands the 16-byte initial key 128 times to be 2048 bytes

	; Create 16 blocks of 16 bytes by xoring the initial key with each byte of the initial key,
	; one byte xors one block each
	; Skip the byte being used for xoring
	mov edx, OFFSET KS_ALL
	mov ecx, 0

IK_XOR_OUTER_LOOP:
	mov ebx, OFFSET InitKey
	mov al, [ebx + ecx]
	mov ah, cl
	push ecx
	mov ecx, 0

IK_XOR_INNER_LOOP:
	cmp ah, cl
	je SKIP_BYTE
	xor [ebx + ecx], al

SKIP_BYTE:
	mov ah, [ebx + ecx]
	mov [edx], ah
	inc edx
	inc ecx
	cmp ecx, 16
	jne IK_XOR_INNER_LOOP

	pop ecx
	inc ecx
	cmp ecx, 16
	jne IK_XOR_OUTER_LOOP

	; Create 7 additional 256 blocks for KS by rotating the bytes of each of the previous blocks

	mov ecx, 1
	mov edx, 256
IK_ROTATE_OUTER_LOOP:
	push ecx
	mov ecx, edx
	sub ecx, 256
	mov ebx, 0

IK_ROTATE_INNER_LOOP:
	mov eax, 0
	mov al, KS_ALL[ecx]
	call RotateBytes
	mov KS_ALL[edx + ebx], al
	inc ebx
	inc ecx
	cmp ecx, edx
	jne IK_ROTATE_INNER_LOOP

	add edx, 256
	pop ecx
	inc ecx
	cmp ecx, 8
	jne IK_ROTATE_OUTER_LOOP

	; Mix up the KS with S-Box and P-Box, twice
	mov ecx, 2
IK_MIXUP_LOOP:
	push ecx

	mov eax, OFFSET KS_ALL
	mov ebx, OFFSET KSbytes_PBOX
	mov ecx, 320
	call transferKS

	; Run KS through P-Box
	call Build_PBOX
	mov edx, OFFSET KS_ALL
	mov ebx, OFFSET KS_Nybbles
	mov numBytes, 2048
	call sp1_2

	mov ecx, 128
PRE_IK_PBOX:
	push ecx
	mov ecx, 32
IK_PBOX_OUTER_LOOP:
	mov ebx, OFFSET KS_Nybbles_Block
	mov edx, OFFSET KS_Nybbles
	mov al, [edx]
	inc edx
	mov [ebx], al
	inc ebx
	loop IK_PBOX_OUTER_LOOP

	mov ecx, 0					
	mov eax, 0					
IK_INNER_PBOX_LOOP:				
	mov al, KS_Nybbles_Block[ecx]	
	movzx ebx, pbox[ecx]		
	mov KS_Nybbles_Block2[ebx], al	
	inc ecx						
	cmp ecx, 32					
	jne IK_INNER_PBOX_LOOP		

	sub edx, 32
	mov ecx, 32
IK_PBOX_COPY_LOOP:
	mov ebx, OFFSET KS_Nybbles_Block2
	mov al, [ebx]
	inc ebx
	mov [edx], al
	inc edx
	loop IK_PBOX_COPY_LOOP

	pop ecx
	loop PRE_IK_PBOX

	mov ebx, OFFSET KS_ALL
	mov edx, OFFSET KS_Nybbles
	mov numNybbles, 4096
	call jn2_1

	; Run KS through S-Box

	mov eax, OFFSET KS_ALL
	mov ebx, OFFSET KSbytes_SBOX
	mov ecx, 1216
	call transferKS

	call Build_SBOX
	mov ecx, 0
	mov eax, 0
IK_SBOX_LOOP:					
	mov al, KS_ALL[ecx]		
	mov bl, sbox[eax]			
	mov KS_ALL[ecx], bl		
	inc ecx						
	cmp ecx, 2048				
	jne IK_SBOX_LOOP			

	pop ecx
	dec ecx
	cmp ecx, 0
	jne IK_MIXUP_LOOP

	ret
ISHAE_KISS ENDP

ARIANA PROC
	; Assembly Random Intersperse Algorithm Number Automator
	; Generates a pseudorandom 16 byte key

	; Set the rand seed from the clock
	mov eax, 0
	call randSeed

	; Generate the initial pool of random bytes
	mov ebx, OFFSET rngPool
	mov ecx, 2048
POOL_LOOP:
	mov eax, 256
	call randRange
	mov [ebx], al
	inc ebx
	loop POOL_LOOP

	; Mix up the RNG Pool
		mov ecx, 3
ARIANA_MIXUP_LOOP:
	push ecx

	mov eax, OFFSET rngPool
	mov ebx, OFFSET KSbytes_PBOX
	mov ecx, 320
	call transferKS

	; Run RNG Pool through P-Box
	call Build_PBOX
	mov edx, OFFSET rngPool
	mov ebx, OFFSET KS_Nybbles
	mov numBytes, 2048
	call sp1_2

	mov ecx, 128
PRE_ARIANA_PBOX:
	push ecx
	mov ecx, 32
ARIANA_PBOX_OUTER_LOOP:
	mov ebx, OFFSET KS_Nybbles_Block
	mov edx, OFFSET KS_Nybbles
	mov al, [edx]
	inc edx
	mov [ebx], al
	inc ebx
	loop ARIANA_PBOX_OUTER_LOOP

	mov ecx, 0					
	mov eax, 0					
ARIANA_INNER_PBOX_LOOP:				
	mov al, KS_Nybbles_Block[ecx]	
	movzx ebx, pbox[ecx]		
	mov KS_Nybbles_Block2[ebx], al	
	inc ecx						
	cmp ecx, 32					
	jne ARIANA_INNER_PBOX_LOOP		

	sub edx, 32
	mov ecx, 32
ARIANA_PBOX_COPY_LOOP:
	mov ebx, OFFSET KS_Nybbles_Block2
	mov al, [ebx]
	inc ebx
	mov [edx], al
	inc edx
	loop ARIANA_PBOX_COPY_LOOP

	pop ecx
	loop PRE_ARIANA_PBOX

	mov ebx, OFFSET rngPool
	mov edx, OFFSET KS_Nybbles
	mov numNybbles, 4096
	call jn2_1

	; Run RNG Pool through S-Box

	mov eax, OFFSET rngPool
	mov ebx, OFFSET KSbytes_SBOX
	mov ecx, 1216
	call transferKS

	call Build_SBOX
	mov ecx, 0
	mov eax, 0
ARIANA_SBOX_LOOP:					
	mov al, rngPool[ecx]		
	mov bl, sbox[eax]			
	mov rngPool[ecx], bl		
	inc ecx						
	cmp ecx, 2048				
	jne ARIANA_SBOX_LOOP			

	pop ecx
	dec ecx
	cmp ecx, 0
	jne ARIANA_MIXUP_LOOP

	; XOR all blocks of bytes with the inital block
	mov ecx, 127
	mov ebx, OFFSET rngPool
	mov eax, 0
ARIANA_OUTER_SPONGE_LOOP:
	push ecx
	mov ecx, 0
ARIANA_INNER_SPONGE_LOOP:
	mov al, [ebx]
	inc ebx
	xor rngPool[ecx], al
	inc ecx
	cmp ecx, 16
	jne ARIANA_INNER_SPONGE_LOOP
	pop ecx
	loop ARIANA_OUTER_SPONGE_LOOP

	; Transfer generated key to InitKey
	mov ebx, OFFSET InitKey
	mov ecx, 0
ARIANA_TRANSFER_LOOP:
	mov al, rngPool[ecx]
	inc ecx
	mov [ebx], al
	inc ebx
	cmp ecx, 16
	jne ARIANA_TRANSFER_LOOP

	ret
ARIANA ENDP

OUTPUT_HEX_KEY PROC
	; Output the key in hex to the console

	; Split the key into nybbles
	mov edx, OFFSET InitKey
	mov ebx, OFFSET hexNybbles
	mov numBytes, 16
	call sp1_2

	mov ecx, 32
	mov edx, OFFSET hexNybbles
	mov eax, 0
OUTPUT_HEX_LOOP:
	mov bl, [edx]
	inc edx

	cmp bl, 0
	jne OHK_ONE
	mov al, '0'
	jmp AFTER_HEX
OHK_ONE:
	cmp bl, 1
	jne OHK_TWO
	mov al, '1'
	jmp AFTER_HEX
OHK_TWO:
	cmp bl, 2
	jne OHK_THREE
	mov al, '2'
	jmp AFTER_HEX
OHK_THREE:
	cmp bl, 3
	jne OHK_FOUR
	mov al, '3'
	jmp AFTER_HEX
OHK_FOUR:
	cmp bl, 4
	jne OHK_FIVE
	mov al, '4'
	jmp AFTER_HEX
OHK_FIVE:
	cmp bl, 5
	jne OHK_SIX
	mov al, '5'
	jmp AFTER_HEX
OHK_SIX:
	cmp bl, 6
	jne OHK_SEVEN
	mov al, '6'
	jmp AFTER_HEX
OHK_SEVEN:
	cmp bl, 7
	jne OHK_EIGHT
	mov al, '7'
	jmp AFTER_HEX
OHK_EIGHT:
	cmp bl, 8
	jne OHK_NINE
	mov al, '8'
	jmp AFTER_HEX
OHK_NINE:
	cmp bl, 9
	jne OHK_CHAR_A
	mov al, '9'
	jmp AFTER_HEX
OHK_CHAR_A:
	cmp bl, 10
	jne OHK_CHAR_B
	mov al, 'A'
	jmp AFTER_HEX
OHK_CHAR_B:
	cmp bl, 11
	jne OHK_CHAR_C
	mov al, 'B'
	jmp AFTER_HEX
OHK_CHAR_C:
	cmp bl, 12
	jne OHK_CHAR_D
	mov al, 'C'
	jmp AFTER_HEX
OHK_CHAR_D:
	cmp bl, 13
	jne OHK_CHAR_E
	mov al, 'D'
	jmp AFTER_HEX
OHK_CHAR_E:
	cmp bl, 14
	jne OHK_CHAR_F
	mov al, 'E'
	jmp AFTER_HEX
OHK_CHAR_F:
	cmp bl, 15
	jne AFTER_HEX
	mov al, 'F'
	jmp AFTER_HEX
AFTER_HEX:
	call writeChar
	dec ecx
	cmp ecx, 0
	jne OUTPUT_HEX_LOOP
	endl

	ret
OUTPUT_HEX_KEY ENDP

convertKey PROC
	; Converts the hex key input into an array of 16 bytes

	mov ecx, 32
	mov ebx, OFFSET hexString
	mov edx, OFFSET hexNybbles
	mov eax, 0
CONVERT_KEY_LOOP:
	mov al, [ebx]
	inc ebx
	push ebx

	cmp al, '0'
	jne ONE
	mov bl, 0
	mov [edx], bl
	jmp AFTER_CHAR
ONE:
	cmp al, '1'
	jne TWO
	mov bl, 1
	mov [edx], bl
	jmp AFTER_CHAR
TWO:
	cmp al, '2'
	jne THREE
	mov bl, 2
	mov [edx], bl
	jmp AFTER_CHAR
THREE:
	cmp al, '3'
	jne FOUR
	mov bl, 3
	mov [edx], bl
	jmp AFTER_CHAR
FOUR:
	cmp al, '4'
	jne FIVE
	mov bl, 4
	mov [edx], bl
	jmp AFTER_CHAR
FIVE:
	cmp al, '5'
	jne SIX
	mov bl, 5
	mov [edx], bl
	jmp AFTER_CHAR
SIX:
	cmp al, '6'
	jne SEVEN
	mov bl, 6
	mov [edx], bl
	jmp AFTER_CHAR
SEVEN:
	cmp al, '7'
	jne EIGHT
	mov bl, 7
	mov [edx], bl
	jmp AFTER_CHAR
EIGHT:
	cmp al, '8'
	jne NINE
	mov bl, 8
	mov [edx], bl
	jmp AFTER_CHAR
NINE:
	cmp al, '9'
	jne CHAR_A
	mov bl, 9
	mov [edx], bl
	jmp AFTER_CHAR
CHAR_A:
	cmp al, 'A'
	jne CHAR_low_a
	mov bl, 10
	mov [edx], bl
	jmp AFTER_CHAR
CHAR_low_a:
	cmp al, 'a'
	jne CHAR_B
	mov bl, 10
	mov [edx], bl
	jmp AFTER_CHAR
CHAR_B:
	cmp al, 'B'
	jne CHAR_low_b
	mov bl, 11
	mov [edx], bl
	jmp AFTER_CHAR
CHAR_low_b:
	cmp al, 'b'
	jne CHAR_C
	mov bl, 11
	mov [edx], bl
	jmp AFTER_CHAR
CHAR_C:
	cmp al, 'C'
	jne CHAR_low_c
	mov bl, 12
	mov [edx], bl
	jmp AFTER_CHAR
CHAR_low_c:
	cmp al, 'c'
	jne CHAR_D
	mov bl, 12
	mov [edx], bl
	jmp AFTER_CHAR
CHAR_D:
	cmp al, 'D'
	jne CHAR_low_d
	mov bl, 13
	mov [edx], bl
	jmp AFTER_CHAR
CHAR_low_d:
	cmp al, 'd'
	jne CHAR_E
	mov bl, 13
	mov [edx], bl
	jmp AFTER_CHAR
CHAR_E:
	cmp al, 'E'
	jne CHAR_low_e
	mov bl, 14
	mov [edx], bl
	jmp AFTER_CHAR
CHAR_low_e:
	cmp al, 'e'
	jne CHAR_F
	mov bl, 14
	mov [edx], bl
	jmp AFTER_CHAR
CHAR_F:
	cmp al, 'F'
	jne CHAR_low_f
	mov bl, 15
	mov [edx], bl
	jmp AFTER_CHAR
CHAR_low_f:
	cmp al, 'f'
	jne AFTER_CHAR
	mov bl, 15
	mov [edx], bl
	jmp AFTER_CHAR
AFTER_CHAR:
	inc edx
	dec ecx
	pop ebx
	cmp ecx, 0
	jne CONVERT_KEY_LOOP

	mov ebx, OFFSET InitKey
	mov edx, OFFSET hexNybbles
	mov numNybbles, 32
	call jn2_1

	ret
convertKey ENDP

main PROC	
	;Input e or d
	mov edx, OFFSET eORdPrompt
	call writeString
	call readChar
	mov eORd, al


	cmp eORd, 'e'
	jne KEY_OPTIONS_D

	; Choose key option for encryption
	mov edx, OFFSET eKeyOptions1
	call writeLine
	mov edx, OFFSET eKeyOptions2
	call writeLine
	mov edx, OFFSET eKeyOptions3
	call writeLine
	mov edx, OFFSET eKeyOptions4
	call writeLine
	call readChar
	cmp al, 'r'
	jne E_OPTION_H
	call ARIANA
	mov edx, OFFSET genKeyMessage
	call writeString
	call OUTPUT_HEX_KEY
	endl
	jmp AFTER_KEY
E_OPTION_H:
	cmp al, 'h'
	jne E_OPTION_S
	mov edx, OFFSET hexPrompt
	call writeString
	mov edx, OFFSET hexString
	call readString
	call convertKey
	jmp AFTER_KEY
E_OPTION_S:
	cmp al, 's'
	jne INVALID_OPTION
	mov edx, OFFSET keyPrompt
	call writeString
	mov edx, OFFSET InitKey
	call readString
	jmp AFTER_KEY

	; Choose key option for decryption
KEY_OPTIONS_D:
	cmp eORd, 'd'
	jne INVALID_OPTION
	mov edx, OFFSET dKeyOptions1
	call writeLine
	mov edx, OFFSET dKeyOptions2
	call writeLine
	mov edx, OFFSET dKeyOptions3
	call writeLine
	call readChar
	cmp al, 'h'
	jne D_OPTION_S
	mov edx, OFFSET hexPrompt
	call writeString
	mov edx, OFFSET hexString
	call readString
	call convertKey
	jmp AFTER_KEY
D_OPTION_S:
	cmp al, 's'
	jne INVALID_OPTION
	mov edx, OFFSET keyPrompt
	call writeString
	mov edx, OFFSET InitKey
	call readString
	jmp AFTER_KEY
AFTER_KEY:
	
	; Create the Key Schedule
	call ISHAE_KISS

	; Split up the Key Schedule into parts
	mov eax, OFFSET KS_ALL
	mov ebx, OFFSET KSbytes_SBOX
	mov ecx, 1216
	call transferKS

	mov ebx, OFFSET KSbytes_PBOX
	mov ecx, 320
	call transferKS

	mov ebx, OFFSET KSbytes_XOR1
	mov ecx, 256
	call transferKS

	mov ebx, OFFSET KSbytes_XOR2
	mov ecx, 256
	call transferKS

	; Build the S-Box and P-Box
	call Build_SBOX
	call Build_PBOX

	mov al, eORd
	cmp al, "e"
	jne DECRYPT_BLOCK

	; Else, Encrypt block
	mov edx, OFFSET filenamePromptE
	call writeString
	mov edx, OFFSET fname
	call readString

	; Add new extension to output filename
	mov ebx, OFFSET fname
	mov edx, OFFSET fname2
	mov al, [ebx]
EXT_LOOP1:
	inc ebx
	mov [edx], al
	inc edx
	mov al, [ebx]
	cmp al, 0
	jne EXT_LOOP1

	mov ebx, OFFSET newExtension
	mov al, [ebx]
EXT_LOOP2:
	inc ebx
	mov [edx], al
	inc edx
	mov al, [ebx]
	cmp al, 0
	jne EXT_LOOP2

	; Encrypt file:
	mov edx, OFFSET eMessage
	call writeLine

	; Open file for reading plaintext from
	mov eax, 0
	mov edx, OFFSET fname									
	INVOKE  CreateFileA, edx, GENERIC_READ, NULL, NULL,		
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
	mov fHandle, eax										

	; Open file for writing the ciphertext blocks to
	mov eax, 0
	mov edx, OFFSET fname2
	INVOKE  CreateFileA, edx, GENERIC_WRITE, NULL, NULL,	
		OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL	
	mov fHandle2, eax					

BLOCK_LOOP1:
	; Read in the current plaintext block into block
	mov bytesRead, 0
	INVOKE ReadFile, fHandle, ADDR block, 16, ADDR bytesRead, NULL

	; Check if last block
	cmp bytesRead, 0
	jne NOT_LAST_BLOCK
	mov lastBlock, 1
NOT_LAST_BLOCK:
	; If current block less than 16 bytes, add padding
	; Also, last block
	cmp bytesRead, 16
	je OUTPUT_BYTES1
	mov lastBlock, 1
	mov eax, 0
	mov bl, 16
	sub ebx, bytesRead
	inc ebx
	mov eax, bytesRead
PADDING_LOOP:
	mov block[eax], bl
	inc al
	cmp al, 16
	jne PADDING_LOOP	

OUTPUT_BYTES1:
	; Encrypt loop
	mov ecx, 0
	mov eax, 0
	mov ebx, 0
	mov XOR_INDEX, ebx
ENCRYPT_LOOP:
	inc ecx
	push ecx
	mov ecx, 0
	mov ebx, XOR_INDEX
ENCRYPT_INNER_LOOP:
	mov eax, 0

	; S-Box 1
	push ebx
	mov al, block[ecx]		
	mov bl, sbox[eax]			
	mov block[ecx], bl
	pop ebx

	; XOR 1
	mov al, KSbytes_XOR1[ebx]
	xor block[ecx], al

	; S-Box 2
	push ebx
	mov al, block[ecx]		
	mov bl, sbox[eax]			
	mov block[ecx], bl
	pop ebx

	; XOR 2
	mov al, KSbytes_XOR2[ebx]
	xor block[ecx], al

	; Check if end of cycle
	inc ecx
	inc ebx
	mov XOR_INDEX, ebx
	cmp ecx, 16
	jne ENCRYPT_INNER_LOOP

	; Check if 4 cycles
	pop ecx
	mov edx, 0
	mov eax, ecx
	div div4
	cmp edx, 0
	jne ENCRYPT_LOOP

	; Else, 4 cycles, P-Box
	; Split the block into 32 nybbles
	push ecx
	mov edx, OFFSET block	
	mov ebx, OFFSET blockNybbles
	mov numBytes, 16			
	call sp1_2

	; Run the block nybbles through the P-Box
	mov ecx, 0					
	mov eax, 0					
pboxLoop:						
	mov al, blockNybbles[ecx]	
	movzx ebx, pbox[ecx]		
	mov blockNybbles2[ebx], al	
	inc ecx						
	cmp ecx, 32					
	jne pboxLoop				

	; Join the nybbles after P-Box usage
	mov edx, OFFSET blockNybbles2
	mov ebx, OFFSET block
	mov numNybbles, 32
	call jn2_1
	; Check if end of all 16 cycles
	pop ecx
	cmp ecx, 16
	jne ENCRYPT_LOOP

	; Write the current encrypted block to the output file
	INVOKE WriteFile, fHandle2, ADDR block, SIZEOF block - 1, ADDR bytesWritten, NULL ;write text to file

	; NULL out the block
	mov edx, OFFSET block
	mov al, 0
	mov ecx, 16
NULL_LOOP1:
	mov [edx], al
	inc edx
	loop NULL_LOOP1
	cmp lastBlock, 1
	jne BLOCK_LOOP1

OUTSIDE_BLOCK_LOOP1:
	; Close files, output finish message
	INVOKE CloseHandle, fHandle		
	INVOKE CloseHandle, fHandle2		
	mov edx, OFFSET eFinMessage
	call writeLine
	jmp END_OF_PROGRAM


DECRYPT_BLOCK:
	cmp eORd, 'd'
	jne INVALID_OPTION

	; Build reverse S-Box and P-Box
	call Build_REV_SBOX
	call Build_REV_PBOX

	; Get the file to decrypt
	mov edx, OFFSET filenamePromptD
	call writeString
	mov edx, OFFSET fname
	call readString

	; Get the new name of the decrypted file
	mov edx, OFFSET filenamePromptD2
	call writeString
	mov edx, OFFSET fname2
	call readString

	; File decrypt:
	mov edx, OFFSET dMessage
	call writeLine

	; Encrypted File to read from
	mov eax, 0
	mov edx, OFFSET fname								
	INVOKE  CreateFileA, edx, GENERIC_READ, NULL, NULL,		
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
	mov fHandle, eax										

	; File to write to
	mov eax, 0
	mov edx, OFFSET fname2
	INVOKE  CreateFileA, edx, GENERIC_WRITE, NULL, NULL,	
		OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL	
	mov fHandle2, eax					

	; Read in the initial block
	mov bytesRead, 0
	INVOKE ReadFile, fHandle, ADDR block, 16, ADDR bytesRead, NULL 

BLOCK_LOOP2:
	mov ebx, OFFSET block
	mov edx, OFFSET block2
	mov ecx, 16
TRANSFER_BLOCK:
	mov al, [ebx]
	inc ebx
	mov [edx], al
	inc edx
	loop TRANSFER_BLOCK

	; Decrypt loop
	; Repeat 16 cycles
	mov ecx, 17
	mov eax, 0
	mov ebx, 255		; Running index for the XORS, start at end for decryption
	mov XOR_INDEX, ebx
DECRYPT_LOOP:	
	dec ecx

	mov XOR_INDEX, ebx

	; Check if 4 cycles
	cmp ecx, 0
	je DECRYPT_MAIN_LOOP
	mov edx, 0
	mov eax, ecx
	div div4
	cmp edx, 0
	jne DECRYPT_MAIN_LOOP

	; Else, 4 cycles, P-Box
	push ecx
	mov edx, OFFSET block2	; Split the block into nybbles for P-Box
	mov ebx, OFFSET blockNybbles
	mov numBytes, 16			
	call sp1_2

	; Run the block nybbles through the P-Box
	mov ecx, 0					
	mov eax, 0					
pboxLoop2:						
	mov al, blockNybbles[ecx]	
	movzx ebx, revPbox[ecx]		
	mov blockNybbles2[ebx], al	
	inc ecx						
	cmp ecx, 32					
	jne pboxLoop2				

	; Join the nybbles after P-Box usage
	mov edx, OFFSET blockNybbles2
	mov ebx, OFFSET block2
	mov numNybbles, 32
	call jn2_1
	pop ecx

DECRYPT_MAIN_LOOP:
	; Repeat this loop 16 times, one for each ciphertext byte
	push ecx
	mov ecx, 15
	mov eax, 0
	mov ebx, XOR_INDEX	; Running index for the XORs
DECRYPT_INNER_LOOP:
	mov eax, 0

	; Reverse XOR 2
	mov al, KSbytes_XOR2[ebx]
	xor block2[ecx], al

	; Reverse S-Box 1
	push ebx
	mov al, block2[ecx]		
	mov bl, revSbox[eax]			
	mov block2[ecx], bl
	pop ebx
	
	; Reverse XOR 1
	mov al, KSbytes_XOR1[ebx]
	xor block2[ecx], al

	; Reverse S-Box 2
	push ebx
	mov al, block2[ecx]		
	mov bl, revSbox[eax]			
	mov block2[ecx], bl
	pop ebx

	; Check if end of cycle
	dec ecx
	dec ebx
	cmp ecx, -1
	jne DECRYPT_INNER_LOOP

	; Check if end of all cycles
	pop ecx
	cmp ecx, 1
	jne DECRYPT_LOOP

	; NULL out block
	mov edx, OFFSET block
	mov al, 0
	mov ecx, 16
NULL_LOOP2:
	mov [edx], al
	inc edx
	loop NULL_LOOP2

	; Read next block from file
	mov bytesRead, 0
	INVOKE ReadFile, fHandle, ADDR block, 16, ADDR bytesRead, NULL

	; If bytes read is zero, last block
	cmp bytesRead, 0
	jne NO_PADDING
	; Get the padding size from last byte, store 16 - padding in al
	mov eax, 0
	mov al, 16
	sub al, block2[15]
	inc al
	; Write current block to file, minus padding
	INVOKE WriteFile, fHandle2, ADDR block2, eax, ADDR bytesWritten, NULL 
	jmp EXIT_OUTPUT

NO_PADDING:
	; Write current block to file
	INVOKE WriteFile, fHandle2, ADDR block2, 16, ADDR bytesWritten, NULL 
	jmp BLOCK_LOOP2

EXIT_OUTPUT:

OUTSIDE_BLOCK_LOOP2:
	; Close files, output finish message
	INVOKE CloseHandle, fHandle		
	INVOKE CloseHandle, fHandle2
	mov edx, OFFSET dFinMessage
	call writeLine
	jmp END_OF_PROGRAM

INVALID_OPTION:
	mov edx, OFFSET invalidMessage
	call writeLine

END_OF_PROGRAM:

  	exit						; macro for exiting the program

main ENDP 
END main