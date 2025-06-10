[English](README.md) | [中文](README_zh.md)
# 介绍

两种使用MASM汇编实现的SRDI（前置式RDI和后置式RDI）可以将EXE/DLL转换为位置无关Shellcode。

一种改良型RDI（内嵌式RDI）只能将DLL转换为shellcode，且这个DLL必须导出ReflectiveLoader函数，对于不熟悉RDI的师傅使用相对困难，但因原理和其制作简单，被大量C2广泛使用。

**目前两种SRDI有以下要求**：
1. main或者wmain可以有参数
2. DLL的dllmain按微软官方定义（大多数都满足）
3. 不支持用C# 编写的EXE和DLL
4. 只支持x64
   

**一种改良型RDI**：
1. 只支持DLL
2. 必须在DLL内部编写ReflectiveLoader函数，且导出，当然不一定要将Loader命名为“ReflectiveLoader”，也可以命名为“HahaLoader”
   
# 项目结构

Convert2Shellcode
- `Convert2Shellcode_embed.cpp`：cpp语言版本，使用改良型RDI（内嵌式）将DLL转换为shellcode
- `Convert2Shellcode_embed.go`：go语言版本，使用改良型RDI（内嵌式）将DLL转换为shellcode
- `Convert2Shellcode_front.cpp`：cpp语言版本，使用前置式RDI将EXE/DLL转换为shellcode
- `Convert2Shellcode_front.go`：go语言版本，使用前置式RDI将EXE/DLL转换为shellcode
- `Convert2Shellcode_post.cpp`：cpp语言版本，使用后置式RDI将EXE/DLL转换为shellcode
- `Convert2Shellcode_post.go`：go语言版本，使用后置式RDI将EXE/DLL转换为shellcode

Debug
- `DebugForRDI.asm`：在调试和编写RDI时创建了这个asm文件，并最终完成了验证。
- `Sever.py`：一个使用python编写的TCP服务器，配合 `DebugForRDI.asm` 一起使用

SRDI Asm
- `RDI_front.asm`：前置式RDI shellcode
- `RDI_post.asm`：后置式RDI shellcode

Test
- `ReflectiveDLL.cpp`：具有导出函数ReflectiveLoader的DLL源码
- `ReflectiveDLL.dll`：具有导出函数ReflectiveLoader的DLL二进制版本
- `stager_x64_reverseTcp.asm`：一个类似于 Cobalt Strike 的stager，使用 Server.py 启动服务器，然后运行这个汇编文件从服务器下载并执行该stage
- `Test_for_dll.cpp`：测试DLL源码
- `Test_for_dll.dll`：测试DLL二进制版本
- `Test_for_exe.cpp`：测试EXE源码
- `Test_for_exe.exe`：测试EXE二进制版本

# 使用

```
1.Convert2Shellcode_post.exe <DLL/EXE Path> [Output File Path]  
2.Convert2Shellcode_post.exe <DLL/EXE Path> [Output File Path]  
3.Convert2Shellcode_embed.exe <DLL Path> [Output File Path] [The Export Function Name of Loader]
```

例子
```
PS C:\Users\xxxxxxxxxx\Desktop\Conver2Shellcode\bin> .\Convert2Shellcode_front.exe mimikatz.exe  
[+] Successfully opened m  
[*] File size is 1355264  
[+] Memory allocation successful, address is 0xc6759040  
[*] 1355264 bytes read into memory  
[+] Memory allocation successful, address is 0xc68ba040  
[+] Successfully generated shellcode file: s (Size: 1356147 bytes)
```

使用pe2shellcode的runshc64.exe：[hasherezade/pe_to_shellcode: Converts PE into a shellcode](https://github.com/hasherezade/pe_to_shellcode)进行验证，也可以自己编写一个loader

![](https://images-of-oneday.oss-cn-guangzhou.aliyuncs.com/images/2025/06/09/19-07-36-0b50c72fe124b9742c6fec8c67ce04cf-20250609190736-4d79d7.png)

# 更多细节

如果你对实现细节感兴趣，可以去看看我写的这篇文章：[从SRDI原理剖析再到PE2Shellcode的实现-先知社区](https://xz.aliyun.com/news/18239)

我的博客：[关于这个博客 | onedaybook](https://oneday.gitbook.io/onedaybook)

# TODO

这个项目，我会去维护，主要是以下几点

1. 增加x86的支持
2. 增加高级功能，比如说支持用户数据、混淆PE特征等等
3. 增加对 .NET程序的支持
4. 继续完善RDI的功能，比如说增加延迟导入、导出转换等等
5. 进一步缩小srdi的体积
6. 修复bug和解决师傅们提出的issue

# 声明

本工具仅提供给安全研究人员进行合法安全研究及学习使用。使用者应遵守当地相关法律，未经授权不得对任何计算机系统进行测试。作者不对任何滥用此工具的行为负责，包括但不限于未经授权的入侵、破坏、数据窃取等行为。使用者应对其行为负全部责任。

还有一点，现在我不干安全了，别溯源我。