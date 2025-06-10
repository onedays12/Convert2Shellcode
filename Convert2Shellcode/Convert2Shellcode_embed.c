#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

DWORD RVAtoFileOffset(DWORD RVA, PIMAGE_NT_HEADERS pNtHeader, PIMAGE_SECTION_HEADER pSec);
DWORD GetProcOffset(const char* funcName, LPVOID pBuf);

// 辅助函数：将32位整数打包为小端字节序
void pack(uint32_t val, uint8_t* bytes) {
    bytes[0] = val & 0xFF;
    bytes[1] = (val >> 8) & 0xFF;
    bytes[2] = (val >> 16) & 0xFF;
    bytes[3] = (val >> 24) & 0xFF;
}

int wmain(int argc, wchar_t* argv[]) {

    printf("╔══════════════════════════════════════════════════════════════════════════════════════╗\n");
    printf("║                           Convert2Shellcode_embed                                    ║\n");
    printf("║------------------------------------------------------------------------------------- ║\n");
    printf("║ Function: An improved version of RDI requires implementing the ReflectLoader function║\n");
    printf("║           in the DLL by yourself and also needs to be exported.                      ║\n");
    printf("║ Author：oneday                                                                       ║\n");
    printf("║ Compilation Date：%hs %hs                                               ║\n", __DATE__, __TIME__);
    printf("╚══════════════════════════════════════════════════════════════════════════════════════╝\n");
    printf("\n");

    // 检查参数数量
    if (argc < 2) {
        printf("[-] Error: Missing DLL path parameter\n");
        printf("[*] Usage: Convert2Shellcode_embed.exe <DLL Path> [Output File Path] [The Export Function Name of Loader]\n");
        printf("[*] Example 1: Convert2Shellcode_embed.exe C:\\path\\to\\ReflectiveDLL.dll\n");
        printf("[*] Example 2: Convert2Shellcode_embed.exe C:\\path\\to\\ReflectiveDLL.dll C:\\path\\to\\Shellcode.bin\n");
        printf("[*] Example 3: Convert2Shellcode_embed.exe C:\\path\\to\\ReflectiveDLL.dll C:\\path\\to\\Shellcode.bin ReflectiveLoader\n");
        return 1;
    }

    uint8_t bootstrap[24];
    uint8_t* dllBytes = NULL;
    size_t dllSize = 0;

    const wchar_t* dllPath = argv[1];
    FILE* dllFile = _wfopen(dllPath, L"rb");
    if (!dllFile) {
        printf("[-] Error: Unable to open file %s (Error code: %d)\n", dllPath, GetLastError());
        return 1;
    }
    printf("[+] Successfully opened %s\n", dllPath);

    // 获取文件大小
    fseek(dllFile, 0, SEEK_END);
    dllSize = ftell(dllFile);
    fseek(dllFile, 0, SEEK_SET);
    if (dllSize == 0) {
        printf("[-] Error: File size is 0 - %s\n", dllPath);
        fclose(dllFile);
        return 1;
    }
    printf("[*] File size is %zu\n", dllSize);

    // 读取文件内容
    dllBytes = (uint8_t*)malloc(dllSize);
    if (!dllBytes) {
        printf("[-] Error: Memory allocation failed (requested dllSize: %zu bytes)\n", dllSize);
        fclose(dllFile);
        return 1;
    }
    printf("[+] Memory allocation successful, address is 0x%x\n", dllBytes);

    size_t bytesRead = fread(dllBytes, 1, dllSize, dllFile);
    fclose(dllFile);
    if (bytesRead != dllSize) {
        printf("[-] Error: File read incomplete (read %zu/%zu bytes)\n", bytesRead, dllSize);
        free(dllBytes);
        return 1;
    }
    printf("[*] %zu bytes read into memory\n", bytesRead);

    // 假设 ReflectLoader 是目标函数名
    const wchar_t* Wide_ReflectiveLoaderName = (argc >= 4) ? argv[3] : L"ReflectiveLoader";


    // 计算所需缓冲区大小
    size_t size = wcstombs(NULL, Wide_ReflectiveLoaderName, 0) + 1;
    char* ReflectiveLoaderName = (char*)malloc(size);

    // 执行转换
    wcstombs(ReflectiveLoaderName, Wide_ReflectiveLoaderName, size);

    DWORD RDIOffset = 0;
    RDIOffset = GetProcOffset(ReflectiveLoaderName, dllBytes);

    if (!RDIOffset) {
        printf("[-] Error: fail to get RDIOffset)\n");
        free(dllBytes);
        free(ReflectiveLoaderName);
        return 1;
    }

    free(ReflectiveLoaderName);

    // 构建stub
    int index = 0;
    uint8_t stub[23];

    // pop    r10
    stub[index++] = 0x4D;
    stub[index++] = 0x5A;

    // push   r10
    stub[index++] = 0x41;
    stub[index++] = 0x52;

    // call   0
    stub[index++] = 0xE8;
    stub[index++] = 0x00;
    stub[index++] = 0x00;
    stub[index++] = 0x00;
    stub[index++] = 0x00;

    // pop    rbx
    stub[index++] = 0x5B;

    // add rbx,<RDIOffset-9>
    stub[index++] = 0x48;
    stub[index++] = 0x81;
    stub[index++] = 0xC3;
    pack(RDIOffset - 9, stub + index);
    index += 4;

    // push   rbp
    stub[index++] = 0x55;

    // mov    rbp, rsp
    stub[index++] = 0x48;
    stub[index++] = 0x89;
    stub[index++] = 0xE5;

    // call   rbx
    stub[index++] = 0xFF;
    stub[index++] = 0xD3;

    uint8_t* finalcode = (uint8_t*)malloc(dllSize);
    if (!finalcode) {
        printf("[-] Error: Memory allocation failed (requested finalSize: %zu bytes)\n", dllSize);
        free(dllBytes);
        return 1;
    }
    printf("[+] Memory allocation successful, address is 0x%x\n", finalcode);

    // 构造最终的shellcode
    memcpy(finalcode, dllBytes, dllSize);
    memcpy(finalcode, stub, index);

    // 释放 DLL 缓冲区
    free(dllBytes);
    dllBytes = NULL;

    // 处理输出文件参数
    const wchar_t* outputPath = (argc >= 3) ? argv[2] : L"shellcode_embed.bin";

    // 写入文件
    HANDLE hFile = CreateFileW(
        outputPath,
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Error: Unable to create output file %s (Error code: %d)\n", outputPath, GetLastError());
        free(finalcode);
        return 1;
    }

    DWORD bytesWritten;
    BOOL writeResult = WriteFile(
        hFile,
        finalcode,
        (DWORD)dllSize,
        &bytesWritten,
        NULL
    );

    if (!writeResult || bytesWritten != dllSize) {
        printf("[-] Error: Failed to write to file (wrote %lu/%zu bytes, error code: %d)\n",
            bytesWritten, dllSize, GetLastError());
        CloseHandle(hFile);
        free(finalcode);
        return 1;
    }

    FlushFileBuffers(hFile);
    CloseHandle(hFile);
    printf("[+] Successfully generated shellcode file: %s (Size: %zu bytes)\n", outputPath, dllSize);

    return 0;
}

//作用：RVA->文件偏移地址
//公式：文件偏移 = 节区文件起始地址（PointerToRawData） + （RVA - 节区虚拟起始地址（VirtualAddress））
DWORD RVAtoFileOffset(DWORD RVA, PIMAGE_NT_HEADERS pNtHeader, PIMAGE_SECTION_HEADER pSec) {

    // 遍历节区表
    DWORD SectionNumber = pNtHeader->FileHeader.NumberOfSections;
    for (int i = 0; i < SectionNumber; i++) {
        // 检查RVA是否在当前节区的范围内
        if (RVA >= pSec[i].VirtualAddress && RVA < pSec[i].VirtualAddress + pSec[i].SizeOfRawData) {
            // 转换RVA到文件偏移地址
            return pSec[i].PointerToRawData + (RVA - pSec[i].VirtualAddress);
        }
    }
    // 如果未找到对应的节区，返回无效值
    return 0xFFFFFFFF;
}

//作用：该函数通过导出表获得指定函数的地址
DWORD GetProcOffset(const char* funcName, LPVOID pBuf) {

    //定位一些相关文件头
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBuf;
    PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((BYTE*)pBuf + pDosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER pSec = (PIMAGE_SECTION_HEADER)((LPBYTE)pNtHeader + sizeof(IMAGE_NT_HEADERS));

    //获取导出表地址及大小，注意这里是RVA
    DWORD exportDirRVA = pNtHeader->OptionalHeader.DataDirectory[0].VirtualAddress;
    DWORD exportDirSize = pNtHeader->OptionalHeader.DataDirectory[0].Size;

    if (!exportDirRVA) {
        printf("[-] Error: This DLL does not have an export table.\n");
        return NULL;
    }
    //定位导出表
    //得到的偏移地址是RVA，但是咱们的文件现在只是磁盘文件,所以需要转换为文件偏移
    DWORD exportDirFileOffset = RVAtoFileOffset((DWORD)exportDirRVA, pNtHeader, pSec);

    //转换之后RVA就变成了文件偏移，然后再定位
    PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)pBuf + exportDirFileOffset);

    //解析导出表，这里同理都是RVA
    DWORD pRNames = pExportDir->AddressOfNames;
    DWORD pFNames = RVAtoFileOffset(pRNames, pNtHeader, pSec);
    DWORD* pNames = (DWORD*)((PBYTE)pBuf + pFNames);

    DWORD pRFunctions = pExportDir->AddressOfFunctions;
    DWORD pFFunctions = RVAtoFileOffset(pRFunctions, pNtHeader, pSec);
    DWORD* pFunctions = (DWORD*)((PBYTE)pBuf + pFFunctions);

    WORD pRNameOrdinals = pExportDir->AddressOfNameOrdinals;
    WORD pFNameOrdinals = RVAtoFileOffset(pRNameOrdinals, pNtHeader, pSec);
    WORD* pNameOrdinals = (WORD*)((PBYTE)pBuf + pFFunctions);

    // 遍历查找目标函数
    DWORD funcRVA = 0;
    for (DWORD i = 0; i < pExportDir->NumberOfNames; i++) {
        DWORD functionNameRVA = pNames[i];
        DWORD functionNameFileOffset = RVAtoFileOffset(functionNameRVA, pNtHeader, pSec);
        const char* pName = (char*)((PBYTE)pBuf + functionNameFileOffset);
        if (strcmp(pName, funcName) == 0) {
            funcRVA = pFunctions[i];
            break;
        }
    }
    if (funcRVA == 0) {
        printf("\n[-] Function %s not found.\n", funcName);
        return NULL;
    }

    DWORD fileOffset = RVAtoFileOffset(funcRVA, pNtHeader, pSec);
    return fileOffset;
}