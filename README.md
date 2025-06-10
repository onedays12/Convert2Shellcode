[English](README.md) | [中文](README_zh.md)
# Introduce

Two types of SRDI implemented in MASM assembly—**front-style RDI** and **post-tyle RDI**—can convert EXE/DLL into position-independent shellcode.

An **embedded RDI** (improved variant) only supports DLL-to-shellcode conversion. This DLL must export a loader function (e.g., `ReflectiveLoader` or custom names like `HahaLoader`). While challenging for practitioners unfamiliar with RDI, its simplicity has led to wide adoption by C2 frameworks.

**Current SRDI Limitations**:
1. EXE's `main` or `wmain` can have parameters.
2. DLL's `DllMain` must adhere to Microsoft's official specifications. 
3. EXEs/DLLs written in C# are unsupported.
4. x64 architecture only.
   

**Embedded RDI Specifics**:
1. DLL-exclusive conversion.
2. Requires an exported loader function (name flexibility exists, e.g., `HahaLoader`).

# Project Structure

Convert2Shellcode
- `Convert2Shellcode_embed.cpp`：C++ version, uses improved RDI (embedded) to convert DLL to shellcode
- `Convert2Shellcode_embed.go`：Go version, uses improved RDI (embedded) to convert DLL to shellcode
- `Convert2Shellcode_front.cpp`：C++ version, uses front-style RDI to convert EXE/DLL to shellcode
- `Convert2Shellcode_front.go`：Go version, uses front-style RDI to convert EXE/DLL to shellcode
- `Convert2Shellcode_post.cpp`：C++ version, uses post-style RDI to convert EXE/DLL to shellcode
- `Convert2Shellcode_post.go`：Go version, uses post-style RDI to convert EXE/DLL to shellcode

Debug
- `DebugForRDI.asm`：ASM file created for debugging and developing RDI, verified for functionality
- `Sever.py`：Python-written TCP server used with `DebugForRDI.asm`

SRDI Asm
- `RDI_front.asm`：Front-style RDI shellcode
- `RDI_post.asm`：Post-style RDI shellcode

Test
- `ReflectiveDLL.cpp`：DLL source code with exported `ReflectiveLoader` function
- `ReflectiveDLL.dll`：Compiled DLL binary with exported `ReflectiveLoader` function
- `stager_x64_reverseTcp.asm`：Cobalt Strike-like stager; execute `Sever.py` to start server, then run this ASM to fetch/execute payload
- `Test_for_dll.cpp`：Test DLL source code
- `Test_for_dll.dll`：Test DLL binary
- `Test_for_exe.cpp`：Test EXE source code
- `Test_for_exe.exe`：Test EXE binary

# Usage

```
1.Convert2Shellcode_post.exe <DLL/EXE Path> [Output File Path]  
2.Convert2Shellcode_post.exe <DLL/EXE Path> [Output File Path]  
3.Convert2Shellcode_embed.exe <DLL Path> [Output File Path] [The Export Function Name of Loader]
```

Example
```
PS C:\Users\xxxxxxxxxx\Desktop\Conver2Shellcode\bin> .\Convert2Shellcode_front.exe mimikatz.exe  
[+] Successfully opened m  
[*] File size is 1355264  
[+] Memory allocation successful, address is 0xc6759040  
[*] 1355264 bytes read into memory  
[+] Memory allocation successful, address is 0xc68ba040  
[+] Successfully generated shellcode file: s (Size: 1356147 bytes)
```

Use runshc64.exe with pe2shellcode for verification：[hasherezade/pe_to_shellcode: Converts PE into a shellcode](https://github.com/hasherezade/pe_to_shellcode), or you can write your own loader.

![](https://images-of-oneday.oss-cn-guangzhou.aliyuncs.com/images/2025/06/09/19-07-36-0b50c72fe124b9742c6fec8c67ce04cf-20250609190736-4d79d7.png)

# For More Details

If you are interested in the implementation details, you can check out this article I wrote：[从SRDI原理剖析再到PE2Shellcode的实现-先知社区](https://xz.aliyun.com/news/18239)

My blog：[关于这个博客 | onedaybook](https://oneday.gitbook.io/onedaybook)

# TODO

**I will maintain this project, focusing on the following key points:**
1. **Add x86 support**
2. **Introduce advanced features**, such as supporting user data, obfuscating PE headers, etc.
3. **Add support for .NET assemblies**
4. **Enhance RDI functionalities**, including deferred imports, export conversion, etc.
5. **Further reduce the size of the srdi shellcode**
6. **Fix bugs and address issues raised by community members**

# Disclaimer

This tool is provided for educational and research purposes only. It is intended for use by security professionals in legally authorized engagements. The author is not responsible for any misuse of this software. Users must ensure that they have proper authorization before using this tool on any system.

One more thing, I am no longer working in security, don't trace me.