; ------------
; CONSTANTS
; ------------

%define SECRECY_BUFFER_OFFSET -0x2ffff000
%define MASK_BUFFER_OFFSET -0x3ffff000
%define MANAGEMENT_OBJECT_ADDRESS 0x700000000000
%define MANAGEMENT_OBJECT_SIZE 0x1000

; int3 hash tables
%define MO_INT3_HT_LIST_OFFSET 0x0
%define MO_INT3_HT_LIST_COUNT 16

; List of instrument_header_begin base addresses
%define MO_HEADER_ADDR_LIST_OFFSET (MO_INT3_HT_LIST_OFFSET+MO_INT3_HT_LIST_COUNT*8)
%define MO_HEADER_ADDR_LIST_COUNT MO_INT3_HT_LIST_COUNT

; Heap allocation "secret" tracker
; For each call, we shift this tracker to the left, and add
;   0 if the call is not part of a call stack that leads to allocating secret heap memory;
;   1 if the call is part of such a call stack.
%define MO_ALLOC_TRACKER_OFFSET (MO_HEADER_ADDR_LIST_OFFSET+MO_HEADER_ADDR_LIST_COUNT*8)
%define MO_ALLOC_TRACKER_SIZE 8


; Offset of the chunk length for a heap object (depends on the malloc implementation)
%define HEAP_CHUNK_LENGTH_OFFSET -8

; ------------
; CODE
; ------------

[section .text]
align 4096

; The header part contains the entrypoint and generic management functions.
[global instrument_header_begin]
instrument_header_begin:

; Entrypoint, called from _start
; This MUST be the very first label in the instrument section.
[global instrument_entrypoint]
instrument_entrypoint:
	
	; We are coming from _start. All arguments for __libc_start_main are in the respective registers,
	; so we save those first
	push rdi
	push rsi
	push rdx
	push rcx
	push r8
	push r9
	push r10
	push r11
	
	; Ensure that the management object is present, and register this library
	call register_management_object
	
	; Allocate masks for data segments
	call allocate_data_block_masks
	
	; Go to __libc_start_main
	pop r11
	pop r10
	pop r9
	pop r8
	pop rcx
	pop rdx
	pop rsi
	pop rdi
	
[global instrument_entrypoint_main_call]
instrument_entrypoint_main_call:

	; Placeholder for the indirect call to __libc_start_main
	; This will be replaced by the instrumentation code
	db 0x48, 0xa3, 0, 0, 0, 0, 0, 0, 0, 0 ; mov qword [0], rax

; Constructor for shared libraries.
; Initializes the instrumentation of the library.
[global library_init]
library_init:
	push r15
	push r14
	push r11
	push r10
	push r9
	push r8
	push rsi
	push rdi
	push rdx
	push rcx
	push rax
	
	; Ensure that the management object is present, and register this library
	call register_management_object
	
	; Allocate masks for image data blocks
	call allocate_data_block_masks
	
	pop rax
	pop rcx
	pop rdx
	pop rdi
	pop rsi
	pop r8
	pop r9
	pop r10
	pop r11
	pop r14
	pop r15

[global library_init.constructor_jump]
library_init.constructor_jump:

	; Placeholder for jump to first constructor
	; This will be replaced by the instrumentation code
	db 0x48, 0xa3, 0, 0, 0, 0, 0, 0, 0, 0 ; mov qword [0], rax

; Allocates the shared management object and registers the current library.
; As the shared management object allocation serves as some kind of "initialized?" flag, this
; function additionally calls some initialization functions which must run once and as early as possible.
register_management_object:
	
	; State for fast RNG
	sub rsp, 16*0x10

	; Allocate
	mov eax, 9 ; mmap(2)
	mov rdi, MANAGEMENT_OBJECT_ADDRESS ; addr
	mov rsi, MANAGEMENT_OBJECT_SIZE ; length
	mov edx, 0x3 ; prot = PROT_READ | PROT_WRITE
	mov r10d, 0x100022 ; flags = MAP_FIXED_NOREPLACE | MAP_ANONYMOUS | MAP_PRIVATE
	mov r8, -1 ; fd
	xor r9d, r9d ; offset
	syscall
	
	; If we got a return value > 0, the allocation was successful
	test rax, rax
	jns .init
	
	; EEXIST implies that the object has already been allocated and initialized
	cmp rax, -17
	je .register_library
	
	call instrument_error

.init:
	
	; Ensure that the entire memory area is zeroed
	mov rax, MANAGEMENT_OBJECT_ADDRESS
	lea rdx, [rax+MANAGEMENT_OBJECT_SIZE]
	xor edi, edi
	
	.clear_loop:
		mov qword [rax], rdi
		
		add rax, 8
		
		cmp rax, rdx
		jne .clear_loop

	; Initialize allocation tracker
	mov rdi, MANAGEMENT_OBJECT_ADDRESS+MO_ALLOC_TRACKER_OFFSET
	mov qword [rdi], 1

	; Initialize RNG
	mov rax, 32
	.rng_loop:
		rdrand rdi
		jnc .rng_loop

		mov qword [rsp+8*rax-8], rdi

		dec rax
		jne .rng_loop
	
	vmovdqu xmm0, oword [rsp+0x00]
	vmovdqu xmm1, oword [rsp+0x10]
	vmovdqu xmm2, oword [rsp+0x20]
	vmovdqu xmm3, oword [rsp+0x30]
	vmovdqu xmm4, oword [rsp+0x40]
	vmovdqu xmm5, oword [rsp+0x50]
	vmovdqu xmm6, oword [rsp+0x60]
	vmovdqu xmm7, oword [rsp+0x70]
	vmovdqu xmm8, oword [rsp+0x80]
	vmovdqu xmm9, oword [rsp+0x90]
	vmovdqu xmm10, oword [rsp+0xa0]
	vmovdqu xmm11, oword [rsp+0xb0]
	vmovdqu xmm12, oword [rsp+0xc0]
	vmovdqu xmm13, oword [rsp+0xd0]
	vmovdqu xmm14, oword [rsp+0xe0]
	vmovdqu xmm15, oword [rsp+0xf0]
	
	; Install int3 signal handler
	call set_up_signal_handler
	
	; Set up mask buffer for stack pointer
	call allocate_stack_mask

.register_library:
	; Register int3 signal handler hash table pointer in management object
	; Skip existing entries until empty one is encountered
	mov rax, MANAGEMENT_OBJECT_ADDRESS+MO_INT3_HT_LIST_OFFSET
	xor ecx, ecx

.next_table_entry:
	cmp qword [rax+8*rcx], 0
	je .store_hash_table
	inc rcx
	jmp .next_table_entry
	
.store_hash_table:
	lea rdx, [rel instrument_signal_handler_hash_table]
	mov qword [rax+8*rcx], rdx
	
	; Also store base address of instrumentation section of this binary, so
	; we can correctly resolve int3 addresses
	mov rax, MANAGEMENT_OBJECT_ADDRESS+MO_HEADER_ADDR_LIST_OFFSET
	lea rdx, [rel instrument_header_begin]
	mov qword [rax+8*rcx], rdx
	
	add rsp, 16*0x10

	ret


; Initialization function. Sets up the int3 signal handler.
[global set_up_signal_handler]
set_up_signal_handler:

	; Local variables
	; - kernel_sigaction (40 bytes)
	%define _NSIG_WORDS 1 ; from <linux>/arch/x86/include/asm/signal.h
	sub rsp, (32+8*_NSIG_WORDS)
	
	; kernel_sigaction.k_sa_handler = instrument_signal_handler
	lea rax, [rel instrument_signal_handler]
	mov qword [rsp+0x0], rax
	
	; kernel_sigaction.sa_flags = SA_RESTORER | SA_SIGINFO
	mov eax, 0x04000000 | 0x00000004
	mov qword [rsp+0x8], rax
	
	; kernel_sigaction.sa_restorer = instrument_signal_restorer
	lea rax, [rel instrument_signal_restorer]
	mov qword [rsp+0x10], rax 
	
	; kernel_sigaction.sa_mask = []
	xor eax, eax
	mov qword [rsp+0x18], rax
	
	mov eax, 13 ; sigaction(2)
	mov edi, 5 ; signum = SIGTRAP
	mov rsi, rsp ; sigaction
	xor edx, edx ; oldact = NULL
	mov r10d, 8*_NSIG_WORDS ; sigsetsize
	syscall
	
	test rax, rax
	jns .done
	call instrument_error

.done:
	add rsp, (32+8*_NSIG_WORDS)
	ret
	

; Initialization function. Allocates a mask buffer for the stack.
[global allocate_stack_mask]
allocate_stack_mask:

	; Local variables
	; - struct rlimit64 (16 bytes)
	sub rsp, 0x10
	
	; Create and store stack memory block
	; First get stack size
	mov eax, 97 ; getrlimit(2)
	mov rdi, 3 ; resource = RLIMIT_STACK
	mov rsi, rsp ; rlim
	syscall
	
	; If we got a return value < 0, fail
	test rax, rax
	jns .allocate_stack_mask_buffer
	call instrument_error
	
.allocate_stack_mask_buffer:
	; We take the current stack pointer as base address and subtract the rlimit value to get an estimated top address
	mov rdi, rsp
	mov rsi, qword [rsp] ; rlimit64.rlim_cur (current stack size)
	
	; Compute and align top address
	sub rdi, rsi
	and rdi, ~0xfff
	
	; Align stack size
	add rsi, 2*4096
	and rsi, ~0xfff
	
	; Allocate mask and secrecy buffer for stack memory block
	push rsi
	call allocate_mask_buffers
	pop rsi
	
	; The secrecy buffer is zeroed at allocation time (anonymous mmap)
	
	add rsp, 0x10
	ret
	

; Initialization function. Allocates mask buffers for static data blocks.
[global allocate_data_block_masks]
allocate_data_block_masks:

	push r15
	push r14

	; Allocate mask buffers for data segments
	lea r15, [rel instrument_header_begin]
	mov r14, qword [rel segments_pointer]
	add r14, r15

.next_segment:
	mov rdi, qword [r14+0]
	test rdi, rdi
	je .segments_done
	
	; Convert relative address into absolute address
	add rdi, r15
	
	; Allocate mask buffer
	mov esi, dword [r14+8]
	call allocate_mask_buffers
	
	add r14, 16
	jmp .next_segment
	
.segments_done:

	; Initialize masks for private data blocks
	mov r14, qword [rel private_data_blocks_pointer]
	add r14, r15

.next_block:
	mov rdi, qword [r14+0]
	test rdi, rdi
	je .end
	
	; Convert relative address into absolute address
	add rdi, r15
	
	; If the block is writable, initialize mask buffer with random bytes,
	; else zero it
	mov dl, byte [r14+12]
	test dl, dl
	jne .randomize_mask_buffer
	
	; The secrecy buffer is already filled with zeroes (anonymous mmap)
	
	jmp .end

.randomize_mask_buffer:
	
	; Fill secrecy buffer with ones
	add rdi, SECRECY_BUFFER_OFFSET
	mov ecx, dword [r14+8]
	mov al, -1
	rep stosb
	
	; Fill mask with random bytes
	add rdi, (MASK_BUFFER_OFFSET - SECRECY_BUFFER_OFFSET)
	mov esi, dword [r14+8]
	call get_random_bytes
	
	; Initially apply mask to existing data
	mov rdi, qword [r14+0]
	add rdi, r15
	mov esi, dword [r14+8]
	add rsi, rdi
	.mask_loop:
		cmp rdi, rsi
		je .mask_loop_end
		
		mov al, byte [rdi+MASK_BUFFER_OFFSET]
		xor byte [rdi], al
		
		inc rdi
		jmp .mask_loop
	
	.mask_loop_end:
	
	add r14, 16
	jmp .next_block 

.end:
	pop r14
	pop r15
	ret
	

[global segments_pointer]
segments_pointer:
	dq 0
[global private_data_blocks_pointer]
private_data_blocks_pointer:
	dq 0


; Signal handler for int3 traps in original code, where direct jumps to instrumentation code
; were not possible. Resolves the corresponding instrumentation code section, and adjusts the
; saved instruction pointer to jump back on sigreturn.
; Parameters:
; - rdi: signum
; - rsi: info
; - rdx: context
align 64
instrument_signal_handler:
	
	; The [RIP -> instrumentation section address] mapping is stored in a hash table
	; Keys: Distance between instrument_header_begin and instruction after int3 (RIP)
	; Values: Distance between instrument_header_begin and instrumentation code
	; Hash function: Bits (n+2)...3 (ignore bits 2...0 due to alignment)
	%define SIGNAL_HANDLER_TABLE_COUNT 16 ; = 2^n
	
	
	; Get RIP from saved context
	mov rax, qword [rdx+8+8+24+16*8] ; context.uc_mcontext[REG_RIP]
	
	; Iterate through hash tables
	mov r10, MANAGEMENT_OBJECT_ADDRESS
	mov r11, MO_INT3_HT_LIST_COUNT

.loop_hash_table:
	; Get address of hash table
	mov rcx, [r10+MO_INT3_HT_LIST_OFFSET+8*r11-8]
	
	; Check whether hash table is in use
	test rcx, rcx
	je .list_end
	
	; Compute relative address to current library's instrumentation header
	mov r9, [r10+MO_HEADER_ADDR_LIST_OFFSET+8*r11-8]
	mov r12, rax
	sub r12, r9
	
	; Compute hash
	; Each hash table entry has a size of 8 bytes, so we don't need shifting
	mov r8, r12
	and r8d, (SIGNAL_HANDLER_TABLE_COUNT - 1) << 3
	
	; Read pointer to (RIP, offset) list of this hash table key
	mov rcx, qword [rcx+r8]
	add rcx, r9
	
	; Find current RIP
.loop:
	mov rsi, qword [rcx+0]
	
	test rsi, rsi
	je .list_end
	
	cmp r12, rsi
	je .found
	
	add rcx, 16
	jmp .loop
	
.list_end:
	; Is there another hash table?
	dec r11
	jne .loop_hash_table
	
	; Could not find table entry, something went really wrong
	call instrument_error

.found:
	; Store new RIP
	add r9, qword [rcx+8]
	mov qword [rdx+8+8+24+16*8], r9 ; context.uc_mcontext[REG_RIP]
	
	ret
	
; int3 address mapping.
; Each entry contains an offset to its (RIP, offset) list, relative to this table.
align 64
[global instrument_signal_handler_hash_table]
instrument_signal_handler_hash_table:
%rep SIGNAL_HANDLER_TABLE_COUNT
	dq 0
%endrep

; Signal restorer.
align 64
instrument_signal_restorer:
	
	mov eax, 15 ; sigreturn(2)
	syscall
	
	; This syscall does not return. If it still does for some reason, fail
	call instrument_error


; Instrumentation for application system calls.
; Currently only tracks memory allocations and allocates corresponding mask buffers.
; This ensures that every allocated address is always backed by a mask buffer, even
; if it does not (yet) contain private data.
[global handle_system_call]
handle_system_call:
	
	; Check type of system call
	cmp eax, 9
	je .handle_mmap
	cmp eax, 11
	je .handle_munmap
	cmp eax, 25
	je .handle_mremap
	cmp eax, 12
	je .handle_brk
	jmp .end

.handle_mmap:
	
	; Execute system call
	syscall
	test rax, rax
	js .end ; Abort if something went wrong
	
	; Allocation successful, allocate mask buffer
	push r10
	push r9
	push r8
	push rsi
	push rdi
	push rdx
	push rax
	
	mov rdi, rax
	call allocate_mask_buffers
	
	pop rax
	pop rdx
	pop rdi
	pop rsi
	pop r8
	pop r9
	pop r10
	
	jmp .end

.handle_munmap:
	
	; TODO
	call instrument_error
	
	jmp .end

.handle_mremap:

	; TODO
	call instrument_error
	
	jmp .end

.handle_brk:
	
	; Only handle actual changes of brk
	test rdi, rdi
	je .handle_others

	; Determine current brk value
	push r10
	push r9
	push r8
	push rsi
	push rdi
	push rdx
	mov rsi, rdi
	
	xor edi, edi
	syscall
	mov rdi, rsi
	mov rsi, rax
	
	; Execute brk as requested
	mov eax, 12
	syscall
	push rax
	
	; Find out by how much brk has changed
	cmp rax, rsi
	jb .handle_brk.dealloc
	je .handle_brk.end
	
	.handle_brk.alloc:

		; Increase size of mask buffer
		mov rdi, rsi ; Base address
		mov rsi, rax
		sub rsi, rdi
		call allocate_mask_buffers
		
		jmp .handle_brk.end

	.handle_brk.dealloc:
		
		; TODO
		call instrument_error

	.handle_brk.end:
		
		pop rax
		pop rdx
		pop rdi
		pop rsi
		pop r8
		pop r9
		pop r10
		jmp .end

.handle_others:
	
	; Execute original system call
	syscall
	
.end:
	ret

; Instrumentation for malloc() calls which allocate secret memory.
; Initializes the corresponding mask buffer.
; Parameters:
; - rdi: Size of secret memory area.
; - rax: Address of malloc() function. We don't use the other argument registers as those
;        may contain additional arguments for that particular allocation function (e.g.,
;        CRYPTO_malloc(num, file, line) in OpenSSL).
; Returns the allocated address in rax.
[global handle_malloc]
handle_malloc:
	
	push r15 ; Allocation size
	push r14 ; Allocation tracker
	push r13 ; Returned address
	; Stack is now 16-byte aligned
	
	; Remember allocation size
	mov r15, rdi

.continue_malloc:	
	; Read allocation tracker and overwrite it with 0b10
	; This way, we ensure that subsequent calls to handle_malloc() do not needlessly generate a
	; random mask (e.g., OpenSSL's CRYPTO_malloc may internally call libc's malloc)
	mov r13, MANAGEMENT_OBJECT_ADDRESS+MO_ALLOC_TRACKER_OFFSET
	mov r14, qword [r13]
	mov qword [r13], 2 ; 0b10

	; Call malloc()
	call rax
	
	; Error check
	test rax, rax
	je .end
	
	; Remember returned address
	mov r13, rax
	
	; Ensure that secrecy buffer behind the boundaries is zero (needed for rewriting of single-byte accesses)
	mov qword [r13-8+SECRECY_BUFFER_OFFSET], 0
	mov qword [r13+r15+SECRECY_BUFFER_OFFSET], 0
	
	; Initialize mask and secrecy buffers
	; If the alloc tracker has value 2^k-1, we are in a call stack allocating a secret block and
	; need a random mask. Else, we set the entire secrecy buffer to zero.
	
	test r14, r14
	je .init_zero_mask   ; tracker == 0 ?
	
	lea rax, [r14+1]
	and rax, r14
	jne .init_zero_mask  ; (tracker & (tracker + 1)) != 0 ?
	
.init_random_mask:
	lea rdi, [r13+SECRECY_BUFFER_OFFSET]
	mov al, -1
	mov rcx, r15
	rep stosb
	
	jmp .mask_init_done
	
.init_zero_mask:
	lea rdi, [r13+SECRECY_BUFFER_OFFSET]
	xor eax, eax
	mov rcx, r15
	rep stosb

.mask_init_done:
	
	; Return address of allocated memory
	mov rax, r13
	
.end:
	; Restore allocation tracker
	mov r13, MANAGEMENT_OBJECT_ADDRESS+MO_ALLOC_TRACKER_OFFSET
	mov qword [r13], r14

	pop r13
	pop r14
	pop r15
	ret

; Instrumentation for realloc() calls which reallocate secret memory.
; Copies the mask buffer to the new memory location, and extends it if necessary.
; Parameters:
; - rdi: Pointer to old memory location.
; - rsi: New size of secret memory area.
; - rax: Address of realloc() function. We don't use the other argument registers as those
;        may contain additional arguments for that particular allocation function (e.g.,
;        CRYPTO_realloc(p, num, file, line) in OpenSSL).
; Returns the allocated address in rax.
[global handle_realloc]
handle_realloc:

	; If the old address is zero, we redirect to malloc
	test rdi, rdi
	jne .continue_realloc

	; Prepare fitting register state for handle_malloc.continue_malloc
	
	push r15 ; Allocation size
	push r14 ; Allocation tracker
	push r13 ; Returned address
	; Stack is now 16-byte aligned
	
	; Remember allocation size
	mov r15, rsi
	
	jmp handle_malloc.continue_malloc

.continue_realloc:
	push r15 ; Old memory location
	push r14 ; Size of old memory location
	push r13 ; Size of new memory location
	push r12 ; Address of secondary data buffer
	push rbp ; Address of secondary mask buffer
	push rbx ; Address of realloc() / afterwards: Address of new memory location
	sub rsp, 8
	; Stack is now 16-byte aligned
	
	; r10: Address of secondary secrecy buffer
	; r11: Old allocation tracker value
	
	; Read allocation tracker and overwrite it with 0b10
	; This way, we ensure that subsequent calls to handle_malloc()/handle_realloc()
	; do not needlessly generate a random mask (e.g., OpenSSL's CRYPTO_realloc may
	; internally call libc's realloc)
	mov r13, MANAGEMENT_OBJECT_ADDRESS+MO_ALLOC_TRACKER_OFFSET
	mov r11, qword [r13]
	mov qword [r13], 2 ; 0b10
	
	; Copy parameters
	mov r15, rdi ; Old memory location
	mov r13, rsi ; Size of new memory location
	mov rbx, rax ; Address of realloc()
	
	; Get size of old memory location
	; We assume that the allocator never gets tainted, else we would need to XOR the mask here
	mov r14, [rdi+HEAP_CHUNK_LENGTH_OFFSET]
	and r14, ~0x7
	
.allocate_secondary_data:

	; We cannot assume that realloc() keeps the old data and mask.
	; We thus allocate two secondary buffers using mmap(), copy the data and mask there, run
	; realloc(), and then copy everything again.
	
	push r11 ; clobbered by syscall
	push r9
	push r8
	push rcx ; clobbered by syscall
	push rdx
	push rsi
	push rdi
	
	; Convert size to multiple of page size
	mov rsi, r14 ; Size of old memory location
	add rsi, 0x1000
	and rsi, ~0xfff
	
	; Allocate data buffer
	mov eax, 9 ; mmap(2)
	xor edi, edi ; addr
	; rsi = length
	mov edx, 0x3 ; prot = PROT_READ | PROT_WRITE
	mov r10d, 0x22 ; flags = MAP_ANONYMOUS | MAP_PRIVATE
	mov r8, -1 ; fd
	xor r9d, r9d ; offset
	syscall
	
	; If we got a return value < 0, fail
	test rax, rax
	jns .allocate_secondary_mask
	call instrument_error
	
.allocate_secondary_mask:
	
	; Remember address of secondary buffer
	mov r12, rax
	
	; Allocate mask buffer
	mov eax, 9
	; We can reuse all other arguments
	syscall
	
	; If we got a return value < 0, fail
	test rax, rax
	jns .allocate_secondary_secrecy
	call instrument_error
	
.allocate_secondary_secrecy:
	
	; Remember address of secondary mask buffer
	mov rbp, rax
	
	; Allocate secrecy buffer
	mov eax, 9
	; We can reuse all other arguments
	syscall
	
	; If we got a return value < 0, fail
	test rax, rax
	jns .copy_old_to_secondary
	call instrument_error
	
.copy_old_to_secondary:

	; Remember address of secondary secrecy buffer
	mov r10, rax
	
	; Copy old data
	mov rsi, r15 ; Old memory location
	mov rdi, r12 ; Address of secondary data buffer
	mov rcx, r14 ; Size of old memory location
	rep movsb

	; Copy old mask
	lea rsi, [r15+MASK_BUFFER_OFFSET] ; Old memory location + mask buffer offset
	mov rdi, rbp ; Address of secondary mask buffer
	mov rcx, r14 ; Size of old memory location
	rep movsb
	
	; Copy old secrecy
	lea rsi, [r15+SECRECY_BUFFER_OFFSET] ; Old memory location + secrecy buffer offset
	mov rdi, r10 ; Address of secondary secrecy buffer
	mov rcx, r14 ; Size of old memory location
	rep movsb
	
	pop rdi
	pop rsi
	pop rdx
	pop rcx
	pop r8
	pop r9
	pop r11
	
.call_realloc:

	; Ensure that r10 and r11 don't get clobbered
	push r11
	push r10

	; Call realloc()
	; All argument registers still have their original values
	call rbx
	
	; Restore registers
	pop r10
	pop r11
	
	; Error check
	test rax, rax
	je .end
	mov rbx, rax ; Address of new memory location
	
	; Ensure that secrecy buffer behind the boundaries is zero (needed for rewriting of single-byte accesses)
	mov qword [rbx-8+SECRECY_BUFFER_OFFSET], 0
	mov qword [rbx+r13+SECRECY_BUFFER_OFFSET], 0 ; Size of new memory location

.new_mask:

	; Initialize new mask buffer
	; If the alloc tracker has value 2^k-1, we are in a call stack allocating a secret block and
	; need a random mask. Else, we set the entire mask buffer to zero. 
	; Subsequently, we copy the data from the secondary buffer, while decoding/re-encoding it.
		
	test r11, r11 ; Old allocation tracker value
	je .copy_with_zero_mask   ; tracker == 0 ?
	
	lea rax, [r11+1]
	and rax, r11
	jne .copy_with_zero_mask  ; (tracker & (tracker + 1)) != 0 ?
	
	.copy_with_random_mask:

		; Fill underlying mask buffer with fresh random mask
		lea rdi, [rbx+MASK_BUFFER_OFFSET] ; Address of new memory location + mask buffer offset
		mov rsi, r13 ; Size of new memory location
		call get_random_bytes
		
		; Set secrecy buffer to all ones
		lea rdi, [rbx+SECRECY_BUFFER_OFFSET] ; Address of new memory location + secrecy buffer offset
		mov rcx, r13 ; Size of new memory location
		mov al, -1
		rep stosb
		
		; We only want to copy necessary data
		; len = min(oldLength, newLength)
		cmp r14, r13
		mov rdx, r13
		cmovbe rdx, r14
		
		; Copy, decode, re-encode data
		lea rsi, [rbx+MASK_BUFFER_OFFSET] ; Address of new memory location + mask buffer offset
		xor ecx, ecx ; Loop counter
		
		.copy_with_random_mask_loop:
			cmp rcx, rdx ; counter >= len
			jae .unmap_secondary_data
			
			; Read old mask
			mov rax, qword [rbp+rcx] ; Address of secondary mask buffer
			
			; Apply old secrecy
			and rax, qword [r10+rcx] ; Address of secondary secrecy buffer
			
			; Decode old data
			xor rax, qword [r12+rcx] ; Address of secondary data buffer
			
			; Apply new mask
			xor rax, qword [rsi+rcx] ; Address of new mask buffer
			
			; Store
			mov qword [rbx+rcx], rax ; Address of new memory location
			
			add rcx, 8
			jmp .copy_with_random_mask_loop
		
	.copy_with_zero_mask:
		
		; Set secrecy buffer to all zeroes
		lea rdi, [rbx+SECRECY_BUFFER_OFFSET] ; Address of new memory location + secrecy buffer offset
		xor eax, eax
		mov rcx, r13 ; Size of new memory location
		rep stosb
		
		; We only want to copy necessary data
		; len = min(oldLength, newLength)
		cmp r14, r13
		mov rdx, r13
		cmovbe rdx, r14
		
		; Copy and decode data
		xor ecx, ecx ; Loop counter
		
		.copy_with_zero_mask_loop:
			cmp rcx, rdx ; counter >= len?
			jae .unmap_secondary_data
			
			; Read old mask
			mov rax, qword [rbp+rcx] ; Address of secondary mask buffer
			
			; Apply old secrecy
			and rax, qword [r10+rcx] ; Address of secondary secrecy buffer
			
			; Decode old data
			xor rax, qword [r12+rcx] ; Address of secondary data buffer
			
			; Store
			mov qword [rbx+rcx], rax ; Address of new memory location
			
			add rcx, 8
			jmp .copy_with_zero_mask_loop

.unmap_secondary_data:
	
	push r11 ; Clobbered by syscall
	
	; Convert size to multiple of page size
	mov rsi, r14 ; Size of old memory location
	add rsi, 0x1000
	and rsi, ~0xfff
	
	; Deallocate secondary data buffer
	mov eax, 11 ; munmap(2)
	mov rdi, r12 ; Address of secondary data buffer
	; rsi = length
	syscall
	
	; If we got a return value < 0, fail
	test rax, rax
	jns .unmap_secondary_mask
	call instrument_error
	
.unmap_secondary_mask:
	
	; Deallocate secondary mask buffer
	mov eax, 11 ; munmap(2)
	mov rdi, rbp ; Address of secondary mask buffer
	; rsi = length
	syscall
	
	; If we got a return value < 0, fail
	test rax, rax
	jns .unmap_secondary_secrecy
	call instrument_error
	
.unmap_secondary_secrecy:
	
	; Deallocate secondary secrecy buffer
	mov eax, 11 ; munmap(2)
	mov rdi, r10 ; Address of secondary secrecy buffer
	; rsi = length
	syscall
	
	; If we got a return value < 0, fail
	test rax, rax
	jns .restore_return_address
	call instrument_error
	
.restore_return_address:
	
	pop r11

	; Restore return address
	mov rax, rbx ; Address of new memory location
	
.end:
	; Restore allocation tracker
	mov r13, MANAGEMENT_OBJECT_ADDRESS+MO_ALLOC_TRACKER_OFFSET
	mov qword [r13], r11
	
	add rsp, 8
	pop rbx
	pop rbp
	pop r12
	pop r13
	pop r14
	pop r15
	ret


; Allocates a new mask and secrecy buffer for the given memory block.
; The new mask und secrecy buffers are not initialized.
; Parameters:
; - rdi: Memory block begin address (multiple of page size).
; - rsi: Memory block size (multiple of page size).
; Returns the address of the secrecy buffer.
[global allocate_mask_buffers]
allocate_mask_buffers:
	
	push rbp
	push rbx
	push r15
	push r14
	
	; Input check
	test rsi, rsi
	je .done
	
	mov rbp, rdi
	mov rbx, rsi
	mov r14, rdx

.mask:	
	; Apply offset
	lea r15, [rdi+MASK_BUFFER_OFFSET]

	; Allocate
	mov eax, 9 ; mmap(2)
	mov rdi, r15 ; addr
	mov rsi, rbx ; length
	mov edx, 0x3 ; prot = PROT_READ | PROT_WRITE
	mov r10d, 0x32 ; flags = MAP_ANONYMOUS | MAP_FIXED | MAP_PRIVATE
	mov r8, -1 ; fd
	xor r9d, r9d ; offset
	syscall
	
	; If we got a return value < 0, fail
	test rax, rax
	jns .secrecy
	call instrument_error
	
.secrecy:
	; Apply offset of secrecy buffer
	add r15, (SECRECY_BUFFER_OFFSET - MASK_BUFFER_OFFSET)

	; Allocate
	mov eax, 9 ; mmap(2)
	mov rdi, r15 ; addr
	mov rsi, rbx ; length
	mov edx, 0x3 ; prot = PROT_READ | PROT_WRITE
	mov r10d, 0x32 ; flags = MAP_ANONYMOUS | MAP_FIXED | MAP_PRIVATE
	mov r8, -1 ; fd
	xor r9d, r9d ; offset
	syscall
	
	; If we got a return value < 0, fail
	test rax, rax
	jns .done
	call instrument_error
	
.done:
	mov rax, r15
	
	pop r14
	pop r15
	pop rbx
	pop rbp
	ret


; Stores the given number of random bytes at the given location.
; Parameters:
; - rdi: Pointer to buffer for storing the random bytes.
; - rsi: Number of random bytes to generate (will be rounded up to a multiple of 8).
; ** Only uses registers RDI, RSI, RCX, RAX **
get_random_bytes:
	
	; Ensure that byte count is multiple of 8
	lea rax, [rsi+8]
	and rax, -8
	test sil, 7
	cmovne rsi, rax
	
	; Generate random number
.get_random_number:
	; Random masks
	rdrand rax
	jnc .get_random_number

	; Constant masks
	;mov rax, 0xc0ffee11c0ffee11

	; Zero masks
	;xor eax, eax
	
	; Fill buffer
	mov rcx, rsi
	shr rcx, 3
	
	; rdi: Pointer
	; rcx: Counter
	; rax: Value
	rep stosq

	; Done
	ret

	
; Utility label for errors
instrument_error:
	db 0x48, 0xa3, 0, 0, 0, 0, 0, 0, 0, 0 ; mov qword [0], rax

[global instrument_header_end]
instrument_header_end:
