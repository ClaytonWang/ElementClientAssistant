
EXTERN g_val1:DQ
EXTERN g_val2:DQ

.CODE

Int_3 PROC
		;mov rax,g_val1
		;mov rbx,g_val2
		mov rax,rcx
		mov rbx,rdx
		add rax,rbx 
		ret
Int_3 ENDP

Int_4 PROC
	mov rax,23	;·µ»Ø123
	ret
Int_4 ENDP

END