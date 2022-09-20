.data
	wSystemCall DWORD 000h

.code 

HellsGate PROC
	mov wSystemCall, 000h
	mov wSystemCall, ecx
	ret
HellsGate ENDP

HellDescent PROC
	mov rax, rcx
	mov r10, rax
	mov eax, wSystemCall
	syscall
	ret
HellDescent ENDP
end