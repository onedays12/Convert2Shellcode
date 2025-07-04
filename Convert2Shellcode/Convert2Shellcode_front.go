package main

import (
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"log"
	"os"
)

// 反射式加载器的 shellcode (占位符，实际使用时需替换)
var rdiShellcode64 = []byte{
    0x50, 0x48, 0x8B, 0x45, 0x08, 0x44, 0x8B, 0x60,
    0x3C, 0x4C, 0x03, 0xE0, 0x41, 0x8B, 0x54, 0x24,
    0x50, 0x48, 0x33, 0xC9, 0x41, 0xB8, 0x00, 0x10,
    0x00, 0x00, 0x41, 0xB9, 0x40, 0x00, 0x00, 0x00,
    0x49, 0xBA, 0xAF, 0x86, 0xFA, 0xFB, 0x00, 0x00,
    0x00, 0x00, 0xE8, 0x37, 0x02, 0x00, 0x00, 0x48,
    0x83, 0xC4, 0x20, 0x48, 0x89, 0x45, 0x10, 0x41,
    0x8B, 0x4C, 0x24, 0x54, 0x48, 0x8B, 0x75, 0x08,
    0x48, 0x8B, 0xF8, 0xF3, 0xA4, 0x44, 0x8B, 0x60,
    0x3C, 0x4C, 0x03, 0xE0, 0x4C, 0x89, 0x65, 0x18,
    0x41, 0x0F, 0xB7, 0x44, 0x24, 0x14, 0x4D, 0x8D,
    0x74, 0x04, 0x18, 0x45, 0x0F, 0xB7, 0x6C, 0x24,
    0x06, 0x41, 0x83, 0x7E, 0x10, 0x00, 0x74, 0x16,
    0x41, 0x8B, 0x76, 0x14, 0x48, 0x03, 0x75, 0x08,
    0x41, 0x8B, 0x7E, 0x0C, 0x48, 0x03, 0x7D, 0x10,
    0x41, 0x8B, 0x4E, 0x10, 0xF3, 0xA4, 0x49, 0x83,
    0xC6, 0x28, 0x41, 0xFF, 0xCD, 0x75, 0xDA, 0x48,
    0x8B, 0x45, 0x18, 0x48, 0x8B, 0x5D, 0x10, 0x48,
    0x2B, 0x58, 0x30, 0x53, 0x48, 0x8D, 0x90, 0xB0,
    0x00, 0x00, 0x00, 0x8B, 0x12, 0x48, 0x03, 0x55,
    0x10, 0x8B, 0x02, 0x85, 0xC0, 0x74, 0x40, 0x8B,
    0x4A, 0x04, 0x48, 0x8D, 0x72, 0x08, 0x48, 0x03,
    0xCA, 0x0F, 0xB7, 0x06, 0x8B, 0xD8, 0xC1, 0xEB,
    0x0C, 0x66, 0x83, 0xFB, 0x0A, 0x75, 0x15, 0x25,
    0xFF, 0x0F, 0x00, 0x00, 0x03, 0x02, 0x48, 0x03,
    0x45, 0x10, 0x48, 0x8B, 0x18, 0x48, 0x03, 0x1C,
    0x24, 0x48, 0x89, 0x18, 0x48, 0x3B, 0xCE, 0x74,
    0x06, 0x48, 0x83, 0xC6, 0x02, 0xEB, 0xD2, 0x8B,
    0x42, 0x04, 0x48, 0x03, 0xD0, 0xEB, 0xBA, 0x5B,
    0x48, 0x8B, 0x45, 0x18, 0x8B, 0x80, 0x90, 0x00,
    0x00, 0x00, 0x4C, 0x8B, 0x65, 0x10, 0x4C, 0x03,
    0xE0, 0x41, 0x83, 0x3C, 0x24, 0x00, 0x0F, 0x84,
    0x8B, 0x00, 0x00, 0x00, 0x41, 0x8B, 0x4C, 0x24,
    0x0C, 0x48, 0x03, 0x4D, 0x10, 0x49, 0xC7, 0xC2,
    0xE9, 0x0A, 0x59, 0x56, 0xE8, 0x4D, 0x01, 0x00,
    0x00, 0x48, 0x83, 0xC4, 0x20, 0x48, 0x93, 0x41,
    0x8B, 0x34, 0x24, 0x48, 0x03, 0x75, 0x10, 0x41,
    0x8B, 0x7C, 0x24, 0x10, 0x48, 0x03, 0x7D, 0x10,
    0x83, 0x3E, 0x00, 0x74, 0x51, 0x48, 0x8B, 0x06,
    0x48, 0x8B, 0xD0, 0x48, 0x85, 0xC0, 0x78, 0x1C,
    0x48, 0x8B, 0xCB, 0x48, 0x03, 0x55, 0x10, 0x48,
    0x83, 0xC2, 0x02, 0x49, 0xBA, 0x05, 0xB9, 0x58,
    0xE6, 0x00, 0x00, 0x00, 0x00, 0xE8, 0x0C, 0x01,
    0x00, 0x00, 0xEB, 0x19, 0x48, 0x81, 0xE2, 0xFF,
    0xFF, 0x00, 0x00, 0x48, 0x8B, 0xCB, 0x49, 0xBA,
    0x05, 0xB9, 0x58, 0xE6, 0x00, 0x00, 0x00, 0x00,
    0xE8, 0xF1, 0x00, 0x00, 0x00, 0x48, 0x83, 0xC4,
    0x20, 0x48, 0x89, 0x07, 0x48, 0x83, 0xC6, 0x08,
    0x48, 0x83, 0xC7, 0x08, 0xEB, 0xAA, 0x49, 0x83,
    0xC4, 0x14, 0xE9, 0x6A, 0xFF, 0xFF, 0xFF, 0x48,
    0x8B, 0x5D, 0x18, 0x0F, 0xB7, 0x43, 0x14, 0x4C,
    0x8D, 0x64, 0x03, 0x18, 0x44, 0x0F, 0xB7, 0x6B,
    0x06, 0x41, 0x8B, 0x44, 0x24, 0x24, 0x25, 0x00,
    0x00, 0x00, 0xE0, 0xC1, 0xE8, 0x1D, 0xE8, 0x08,
    0x00, 0x00, 0x00, 0x01, 0x10, 0x02, 0x20, 0x08,
    0x80, 0x04, 0x40, 0x5E, 0x44, 0x0F, 0xB6, 0x04,
    0x06, 0x41, 0x8B, 0x4C, 0x24, 0x0C, 0x48, 0x03,
    0x4D, 0x10, 0x41, 0x8B, 0x54, 0x24, 0x10, 0x48,
    0x83, 0xEC, 0x08, 0x4C, 0x8B, 0xCC, 0x49, 0xBA,
    0x76, 0x82, 0x91, 0xE3, 0x00, 0x00, 0x00, 0x00,
    0xE8, 0x81, 0x00, 0x00, 0x00, 0x48, 0x83, 0xC4,
    0x28, 0x49, 0x83, 0xC4, 0x28, 0x41, 0xFF, 0xCD,
    0x45, 0x85, 0xED, 0x75, 0xAC, 0x48, 0x8B, 0x45,
    0x18, 0x48, 0x8D, 0x80, 0xD0, 0x00, 0x00, 0x00,
    0x83, 0x78, 0x04, 0x00, 0x74, 0x27, 0x8B, 0x10,
    0x48, 0x03, 0x55, 0x10, 0x48, 0x8B, 0x7A, 0x18,
    0x48, 0x83, 0x3F, 0x00, 0x74, 0x17, 0x48, 0x8B,
    0x07, 0x48, 0x8B, 0x4D, 0x10, 0xBA, 0x01, 0x00,
    0x00, 0x00, 0x45, 0x33, 0xC0, 0xFF, 0xD0, 0x48,
    0x83, 0xC7, 0x08, 0xEB, 0xE3, 0x48, 0x8B, 0x75,
    0x18, 0x66, 0x8B, 0x46, 0x16, 0x66, 0xA9, 0x00,
    0x20, 0x74, 0x20, 0x48, 0x83, 0xEC, 0x20, 0x8B,
    0x5E, 0x28, 0x48, 0x03, 0x5D, 0x10, 0x48, 0x8B,
    0x4D, 0x10, 0x48, 0xC7, 0xC2, 0x01, 0x00, 0x00,
    0x00, 0x45, 0x33, 0xC0, 0xFF, 0xD3, 0x48, 0x83,
    0xC4, 0x28, 0xC3, 0x8B, 0x5E, 0x28, 0x48, 0x03,
    0x5D, 0x10, 0xFF, 0xD3, 0x58, 0xC3, 0x41, 0x51,
    0x41, 0x50, 0x52, 0x51, 0x56, 0x41, 0x54, 0x48,
    0x33, 0xD2, 0x65, 0x48, 0x8B, 0x52, 0x60, 0x48,
    0x8B, 0x52, 0x18, 0x48, 0x8B, 0x52, 0x20, 0x48,
    0x8B, 0x72, 0x50, 0x48, 0x0F, 0xB7, 0x4A, 0x48,
    0x4D, 0x33, 0xC0, 0x48, 0x33, 0xC0, 0xAC, 0x3C,
    0x61, 0x7C, 0x02, 0x2C, 0x20, 0x41, 0xC1, 0xC8,
    0x0D, 0x44, 0x03, 0xC0, 0xFF, 0xC9, 0x75, 0xEB,
    0x52, 0x41, 0x50, 0x48, 0x8B, 0x52, 0x20, 0x8B,
    0x42, 0x3C, 0x48, 0x03, 0xC2, 0x66, 0x81, 0x78,
    0x18, 0x0B, 0x02, 0x75, 0x79, 0x8B, 0x80, 0x88,
    0x00, 0x00, 0x00, 0x48, 0x85, 0xC0, 0x74, 0x6E,
    0x48, 0x03, 0xC2, 0x50, 0x8B, 0x48, 0x18, 0x44,
    0x8B, 0x48, 0x20, 0x4C, 0x03, 0xCA, 0x48, 0x85,
    0xC9, 0x74, 0x5A, 0x48, 0xFF, 0xC9, 0x41, 0x8B,
    0x34, 0x89, 0x48, 0x03, 0xF2, 0x4D, 0x33, 0xC0,
    0x48, 0x33, 0xC0, 0xAC, 0x84, 0xC0, 0x74, 0x09,
    0x41, 0xC1, 0xC8, 0x0D, 0x44, 0x03, 0xC0, 0xEB,
    0xEF, 0x4C, 0x03, 0x44, 0x24, 0x08, 0x45, 0x3B,
    0xC2, 0x75, 0xD3, 0x58, 0x44, 0x8B, 0x48, 0x24,
    0x4C, 0x03, 0xCA, 0x66, 0x41, 0x8B, 0x0C, 0x49,
    0x44, 0x8B, 0x48, 0x1C, 0x4C, 0x03, 0xCA, 0x41,
    0x8B, 0x04, 0x89, 0x48, 0x03, 0xC2, 0x41, 0x58,
    0x41, 0x58, 0x41, 0x5C, 0x5E, 0x59, 0x5A, 0x41,
    0x58, 0x41, 0x59, 0x41, 0x5A, 0x48, 0x83, 0xEC,
    0x20, 0x41, 0x52, 0xFF, 0xE0, 0x58, 0x41, 0x58,
    0x5A, 0x48, 0x8B, 0x12, 0xE9, 0x46, 0xFF, 0xFF,
    0xFF}

// 辅助函数：将32位整数打包为小端字节序
func pack(val uint32) []byte {
	bytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(bytes, val)
	return bytes
}

func main() {
	fmt.Printf(`
╔══════════════════════════════════════════════════════════════════════════════════════╗
║                           Convert2Shellcode_front                                    ║
║------------------------------------------------------------------------------------- ║
║ Function: Use front-style RDI to convert EXE/DLL into position-independent shellcode ║
║ Author：oneday                                                                       ║
╚══════════════════════════════════════════════════════════════════════════════════════╝
`)

	if len(os.Args) < 2 {
		log.Fatal("\n[-] Error: Missing DLL/EXE path parameter\n" +
			"[*] Usage: program <DLL/EXE Path> [Output File Path]\n" +
			"[*] Example 1: program C:\\path\\to\\Test.dll\n" +
			"[*] Example 2: program C:\\path\\to\\ReflectiveDLL.dll C:\\path\\to\\Shellcode.bin")
			os.Exit(1)
	}

	// 构建引导代码
	bootstrapSize := 58

	// cld
	bootstrap := []byte{0xFC}

	/*
	   ; 保存非易失性寄存器
	   push rbx
	   push rbp
	   push rsi
	   push rdi
	   push r12
	   push r13
	   push r14
	   push r15
	*/
	bootstrap = append(bootstrap, 0x53, 0x55, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57)

	// call next instruction
	bootstrap = append(bootstrap, 0xE8, 0x00, 0x00, 0x00, 0x00)

	// 计算 DLL 偏移量
	dllOffset := bootstrapSize - len(bootstrap) + len(rdiShellcode64)

	// pop rax
	bootstrap = append(bootstrap, 0x58)

	// add rax, <Offset of the DLL>
	bootstrap = append(bootstrap, 0x48, 0x05)
	dllOffsetBytes := pack(uint32(dllOffset))
	bootstrap = append(bootstrap, dllOffsetBytes...)

	// mov rbp, rsp
	bootstrap = append(bootstrap, 0x48, 0x8B, 0xEC)

	// sub rsp, 18h
	bootstrap = append(bootstrap, 0x48, 0x83, 0xEC, 0x18)

	// mov qword ptr [rbp+8], rax
	bootstrap = append(bootstrap, 0x48, 0x89, 0x45, 0x08)

	// call ReflectiveLoader
	bootstrap = append(bootstrap, 0xE8)
	callOffset := bootstrapSize - len(bootstrap) - 4
	callOffsetBytes := pack(uint32(callOffset))
	bootstrap = append(bootstrap, callOffsetBytes...)

	// add rsp, 18h
	bootstrap = append(bootstrap, 0x48, 0x83, 0xC4, 0x18)

	/*
	   ;-------------------------------------------------------------------
	   ; 恢复到调用ReflectiveLoader之前的栈空间和寄存器状态
	   ;-------------------------------------------------------------------
	       pop r15
	       pop r14
	       pop r13
	       pop r12
	       pop rdi
	       pop rsi
	       pop rbp
	       pop rbx
	       ret
	*/
	bootstrap = append(bootstrap, 0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5D, 0x41, 0x5C, 0x5F, 0x5E, 0x5D, 0x5B, 0xC3)

	// 读取 DLL/EXE 文件
	dllPath := os.Args[1]
	dllBytes, err := ioutil.ReadFile(dllPath)
	if err != nil {
		fmt.Printf("[-] Error opening file: %v", err)
		os.Exit(1)
	}
	fmt.Printf("[+] Successfully opened %s (%d bytes)\n", dllPath, len(dllBytes))

	// 组合最终 shellcode
	finalsize := bootstrapSize + len(rdiShellcode64) + len(dllBytes)
	finalShellcode := make([]byte, 0, finalsize)
	finalShellcode = append(finalShellcode, bootstrap...)
	finalShellcode = append(finalShellcode, rdiShellcode64...)
	finalShellcode = append(finalShellcode, dllBytes...)

	// 确定输出路径
	outputPath := "shellcode_front.bin"
	if len(os.Args) >= 3 {
		outputPath = os.Args[2]
	}

	// 写入文件
	if err := os.WriteFile(outputPath, finalShellcode, 0644); err != nil {
		fmt.Printf("[-] Error writing file: %v", err)
		os.Exit(1)
	}
	fmt.Printf("[+] Successfully generated shellcode file: %s (%d bytes)\n", outputPath, len(finalShellcode))
}
