package main

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"log"
	"os"
)

const (
	IMAGE_DIRECTORY_ENTRY_EXPORT = 0
)

func main() {

	// 输出banner
	fmt.Println(`╔══════════════════════════════════════════════════════════════════════════════════════╗`)
	fmt.Println(`║                           Convert2Shellcode_embed                                    ║`)
	fmt.Println(`║------------------------------------------------------------------------------------- ║`)
	fmt.Println(`║ Function: An improved version of RDI requires implementing the ReflectLoader function║`)
	fmt.Println(`║           in the DLL by yourself and also needs to be exported.                      ║`)
	fmt.Println(`║ Author：oneday                                                                       ║`)
	fmt.Println(`╚══════════════════════════════════════════════════════════════════════════════════════╝`)
	fmt.Println()

	if len(os.Args) < 2 {
		fmt.Println("[-] Error: Missing DLL path parameter")
		fmt.Println("[*] Usage: Convert2Shellcode_embed.exe <DLL Path> [Output File Path] [The Export Function Name of Loader]")
		fmt.Println("[*] Example 1: Convert2Shellcode_embed.exe C:\\path\\to\\ReflectiveDLL.dll")
		fmt.Println("[*] Example 2: Convert2Shellcode_embed.exe C:\\path\\to\\ReflectiveDLL.dll C:\\path\\to\\Shellcode.bin")
		fmt.Println("[*] Example 3: Convert2Shellcode_embed.exe C:\\path\\to\\ReflectiveDLL.dll C:\\path\\to\\Shellcode.bin ReflectiveLoader")
		os.Exit(1)
	}

	// 待转换的DLL路径和输出文件路径
	dllPath := os.Args[1]
	outputPath := "shellcode_embed.bin"
	if len(os.Args) >= 3 {
		outputPath = os.Args[2]
	}

	// 导出函数名称
	loaderName := "ReflectiveLoader"
	if len(os.Args) >= 4 {
		loaderName = os.Args[3]
	}

	fmt.Printf("[+] Opening DLL: %s\n", dllPath)
	dllData, err := os.ReadFile(dllPath)
	if err != nil {
		log.Fatalf("[-] Error reading DLL: %v", err)
	}

	fmt.Printf("[*] DLL size: %d bytes\n", len(dllData))

	// 解析PE文件
	peFile, err := pe.NewFile(bytes.NewReader(dllData))
	if err != nil {
		log.Fatalf("[-] Error parsing PE file: %v", err)
	}
	defer peFile.Close()

	// 获取Loader的文件偏移
	offset, err := getLoaderOffset(peFile, loaderName, dllData)
	if err != nil {
		log.Fatalf("[-] Error getting loader offset: %v", err)
	}
	fmt.Printf("[+] Found %s at file offset: 0x%X\n", loaderName, offset)

	// 创建stub
	stub := buildStub(offset)
	fmt.Printf("[+] Generated %d byte stub\n", len(stub))

	// 覆盖DOS头部
	if len(stub) > len(dllData) {
		log.Fatalf("[-] Stub larger than DLL")
	}
	copy(dllData, stub)

	// 输出shellcode
	fmt.Printf("[+] Writing shellcode to: %s\n", outputPath)
	if err := os.WriteFile(outputPath, dllData, 0644); err != nil {
		log.Fatalf("[-] Error writing output: %v", err)
	}

	fmt.Printf("[+] Successfully generated shellcode (Size: %d bytes)\n", len(dllData))
}

// 创建stub
func buildStub(funcOffset uint32) []byte {
	// x64 机器码
	/*
		4D 5A          pop    r10
		41 52          push   r10
		E8 00 00 00 00 call   0
		5B             pop    rbx
		48 81 C3 XX XX XX XX add rbx, (funcOffset - 9)
		55             push   rbp
		48 89 E5       mov    rbp, rsp
		FF D3          call   rbx
	*/
	stub := []byte{
		0x4D, 0x5A, // pop r10
		0x41, 0x52, // push r10
		0xE8, 0x00, 0x00, 0x00, 0x00, // call 0
		0x5B,             // pop rbx
		0x48, 0x81, 0xC3, // add rbx, imm32
	}

	// 调整loader的偏移
	offsetBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(offsetBytes, funcOffset-9)
	stub = append(stub, offsetBytes...)

	// 切换堆栈和调用loader
	stub = append(stub, []byte{
		0x55,             // push rbp
		0x48, 0x89, 0xE5, // mov rbp, rsp
		0xFF, 0xD3, // call rbx
	}...)

	return stub
}

// 获取Loader的偏移
func getLoaderOffset(f *pe.File, funcName string, data []byte) (uint32, error) {
	// 找到导出目录
	exportDir := f.OptionalHeader.(*pe.OptionalHeader64).DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
	if exportDir.VirtualAddress == 0 {
		return 0, fmt.Errorf("no export directory found")
	}

	// RVAs to file offsets
	exportSec := findSection(f, exportDir.VirtualAddress)
	if exportSec == nil {
		return 0, fmt.Errorf("could not find section for export directory")
	}
	exportOffset := rvaToOffset(exportDir.VirtualAddress, exportSec)

	// 解析导出目录
	exportDirData := data[exportOffset : exportOffset+uint32(exportDir.Size)]
	ed := parseExportDirectory(exportDirData)

	// 遍历导出表
	namePtrs := data[rvaToOffset(ed.AddressOfNames, exportSec):]
	ordinals := data[rvaToOffset(ed.AddressOfNameOrdinals, exportSec):]
	funcAddrs := data[rvaToOffset(ed.AddressOfFunctions, exportSec):]

	for i := uint32(0); i < ed.NumberOfNames; i++ {
		// 获取函数名称RVA
		nameRVA := binary.LittleEndian.Uint32(namePtrs[i*4:])
		nameSec := findSection(f, nameRVA)
		if nameSec == nil {
			continue
		}

		// Read function name
		nameOffset := rvaToOffset(nameRVA, nameSec)
		name := readCString(data[nameOffset:])
		if name != funcName {
			continue
		}

		// Get function ordinal
		ordinal := binary.LittleEndian.Uint16(ordinals[i*2:])
		if int(ordinal) >= int(ed.NumberOfFunctions) {
			return 0, fmt.Errorf("invalid ordinal")
		}

		// Get function RVA
		funcRVA := binary.LittleEndian.Uint32(funcAddrs[ordinal*4:])
		funcSec := findSection(f, funcRVA)
		if funcSec == nil {
			return 0, fmt.Errorf("could not find section for function")
		}

		// Convert to file offset
		return rvaToOffset(funcRVA, funcSec), nil
	}

	return 0, fmt.Errorf("function '%s' not found in export table", funcName)
}

func findSection(f *pe.File, rva uint32) *pe.Section {
	for _, sec := range f.Sections {
		if rva >= sec.VirtualAddress && rva < sec.VirtualAddress+sec.VirtualSize {
			return sec
		}
	}
	return nil
}

func rvaToOffset(rva uint32, sec *pe.Section) uint32 {
	return sec.Offset + (rva - sec.VirtualAddress)
}

func parseExportDirectory(data []byte) *exportDirectory {
	return &exportDirectory{
		Characteristics:       binary.LittleEndian.Uint32(data[0:]),
		TimeDateStamp:         binary.LittleEndian.Uint32(data[4:]),
		MajorVersion:          binary.LittleEndian.Uint16(data[8:]),
		MinorVersion:          binary.LittleEndian.Uint16(data[10:]),
		Name:                  binary.LittleEndian.Uint32(data[12:]),
		Base:                  binary.LittleEndian.Uint32(data[16:]),
		NumberOfFunctions:     binary.LittleEndian.Uint32(data[20:]),
		NumberOfNames:         binary.LittleEndian.Uint32(data[24:]),
		AddressOfFunctions:    binary.LittleEndian.Uint32(data[28:]),
		AddressOfNames:        binary.LittleEndian.Uint32(data[32:]),
		AddressOfNameOrdinals: binary.LittleEndian.Uint32(data[36:]),
	}
}

type exportDirectory struct {
	Characteristics       uint32
	TimeDateStamp         uint32
	MajorVersion          uint16
	MinorVersion          uint16
	Name                  uint32
	Base                  uint32
	NumberOfFunctions     uint32
	NumberOfNames         uint32
	AddressOfFunctions    uint32
	AddressOfNames        uint32
	AddressOfNameOrdinals uint32
}

func readCString(data []byte) string {
	end := bytes.IndexByte(data, 0)
	if end == -1 {
		return ""
	}
	return string(data[:end])
}
