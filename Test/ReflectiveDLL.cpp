// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include <windows.h>
#include <stdbool.h>
#include <winternl.h>
typedef struct
{
    WORD	offset : 12;
    WORD	type : 4;
} IMAGE_RELOC, * PIMAGE_RELOC;

#define RVA(type, base, rva) (type)((ULONG_PTR) base + rva)
#define Kernel32_GetProcAddress 0xe658b905
#define Kernel32_LoadLibraryA 0x56590ae9
#define Kernel32_VirtualAlloc 0xfbfa86af
#define Kernel32_VirtualProtect 0xe3918276
#define Kernel32_GetNativeSystemInfo 0x4775dcb8

static inline size_t
AlignValueUp(size_t value, size_t alignment) {
    return (value + alignment - 1) & ~(alignment - 1);
}

// rot hash 算法
#define ROTR32(value, shift)	(((DWORD) value >> (BYTE) shift) | ((DWORD) value << (32 - (BYTE) shift)))

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{

    // 弹窗代码
    MessageBoxW(NULL, L"Hello Oneday!!!!!", L"注入程序检测中...", MB_YESNO | MB_ICONASTERISK);

    char processName[MAX_PATH] = { 0 }; // 存储进程路径的缓冲区

    // 获取当前进程的可执行文件路径
    DWORD length = GetModuleFileNameA(NULL, processName, MAX_PATH);
    MessageBoxA(NULL, processName, "当前进程路径: ", MB_YESNO | MB_ICONASTERISK);

    Sleep(99999999);

    return TRUE;
}


// 自定义LDR_DATA_TABLE_ENTRY 数据结构
typedef struct _MY_LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} MY_LDR_DATA_TABLE_ENTRY, * PMY_LDR_DATA_TABLE_ENTRY;


FARPROC GetApiAddressByHash(DWORD dwModuleFunctionHash) {

    DWORD dwModuleHash;
    DWORD dwFunctionHash;
    WORD Modulelenth;
    WCHAR* ModuleName;
    DWORD dwExportDirRVA;
    LPVOID lpModuleBase;
    PCSTR pTempChar;
    PIMAGE_NT_HEADERS pNtHeaders;
    PMY_LDR_DATA_TABLE_ENTRY pEntry;

    // 从获取 PEB 地址
    PPEB pPEB = (PPEB)__readgsqword(0x60);

    // 获取 PEB.Ldr
    PPEB_LDR_DATA pLdr = pPEB->Ldr;

    // 遍历模块列表
    PLIST_ENTRY pListHead = &pLdr->InMemoryOrderModuleList;  //本进程
    PLIST_ENTRY pCurrentEntry = pListHead->Flink;           // 第一个模块
    pEntry = (PMY_LDR_DATA_TABLE_ENTRY)CONTAINING_RECORD(pCurrentEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

    while (pEntry->DllBase != NULL) {

        lpModuleBase = pEntry->DllBase;
        dwModuleHash = 0;
        Modulelenth = pEntry->BaseDllName.Length;
        ModuleName = pEntry->BaseDllName.Buffer;

        // 分析 PE 文件找到导出表
        pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)lpModuleBase + ((PIMAGE_DOS_HEADER)lpModuleBase)->e_lfanew);

        // 获取导出表RVA
        dwExportDirRVA = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

        // Get the next loaded module entry
        pEntry = (PMY_LDR_DATA_TABLE_ENTRY)pEntry->InLoadOrderLinks.Flink;

        // 如果导出表RVA为0，则跳转到下一个循环
        if (dwExportDirRVA == 0) {
            continue;
        }

        for (DWORD i = 0; i < Modulelenth; i++) {

            // 取字符
            pTempChar = ((PCSTR)ModuleName + i);
            dwModuleHash = ROTR32(dwModuleHash, 13);

            // 如果为小写字母，则转成大写字母
            if (*pTempChar >= 0x61) {
                dwModuleHash += *pTempChar - 0x20;
            }
            else {
                dwModuleHash += *pTempChar;
            }
        }


        // 获取导出表的各个信息
        PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)lpModuleBase + dwExportDirRVA);
        PDWORD pFunctionNames = (PDWORD)((BYTE*)lpModuleBase + pExportDirectory->AddressOfNames);
        PDWORD pFunctionAddresses = (PDWORD)((BYTE*)lpModuleBase + pExportDirectory->AddressOfFunctions);
        PWORD pFunctionOrdinals = (PWORD)((BYTE*)lpModuleBase + pExportDirectory->AddressOfNameOrdinals);

        for (DWORD i = 0; i < pExportDirectory->NumberOfNames; i++) {

            dwFunctionHash = 0;
            PCSTR pFunctionName = (PCSTR)((BYTE*)lpModuleBase + pFunctionNames[i]);
            pTempChar = pFunctionName;

            while (*pTempChar != '\0') {
                dwFunctionHash = ROTR32(dwFunctionHash, 13);
                dwFunctionHash += *pTempChar;
                pTempChar++;
            }

            dwFunctionHash += dwModuleHash;
            if (dwFunctionHash == dwModuleFunctionHash) {
                return (FARPROC)((BYTE*)lpModuleBase + pFunctionAddresses[pFunctionOrdinals[i]]);
            }
        }
    }
    return NULL;
}

extern "C" __declspec(dllexport) BOOL ReflectiveLoader()
{

    /*---------------------第一步：暴力搜索DLL的基址---------------------------------*/

    // 获得ReflectiveLoader函数的地址，如果找到了DLL基址，则将其存储到uiLibraryAddress，pNtHeader就是NT头的地址
    ULONG_PTR uiLibraryAddress = (ULONG_PTR)ReflectiveLoader;
    ULONG_PTR uiHeaderValue = 0;
    PIMAGE_NT_HEADERS pNtHeader = 0;

    // 从ReflectiveLoader函数的地址往回退，直到找到DLL的基址
    while (TRUE)
    {
        // 验证是否为DOS头
        if (((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_magic == IMAGE_DOS_SIGNATURE)
        {
            // 验证是否为NT头
            uiHeaderValue = ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew;
            if (uiHeaderValue >= sizeof(IMAGE_DOS_HEADER) && uiHeaderValue < 1024)
            {
                pNtHeader = (PIMAGE_NT_HEADERS)(uiHeaderValue + uiLibraryAddress);
                if (pNtHeader->Signature == IMAGE_NT_SIGNATURE)
                    break;
            }
        }
        uiLibraryAddress--;
    }

    if (!uiLibraryAddress)
        return FALSE;

    PIMAGE_DOS_HEADER pDOSheader = (PIMAGE_DOS_HEADER)uiLibraryAddress;
    /*---------------------第二步：获取所需要的Windows API---------------------------*/

    // 定义API指针类型
    typedef FARPROC(WINAPI* GETPROCADDR)(HMODULE hModule, LPCSTR  lpProcName);
    typedef HMODULE(WINAPI* LOADLIBRARYA)(LPCSTR lpLibFileName);
    typedef LPVOID(WINAPI* VIRTUALALLOC)(LPVOID lpAddress, SIZE_T dwSize, DWORD  flAllocationType, DWORD  flProtect);
    typedef BOOL(WINAPI* VIRTUALPROTECT)(LPVOID lpAddress, SIZE_T dwSize, DWORD  flNewProtect, PDWORD lpflOldProtect);
    typedef void (WINAPI* GETNATIVESYSTEMINFO)(LPSYSTEM_INFO lpSystemInfo);

    // 声明API指针变量
    GETPROCADDR pGetProcAddress = NULL;
    LOADLIBRARYA pLoadLibraryA = NULL;
    VIRTUALALLOC pVirtualAlloc = NULL;
    VIRTUALPROTECT pVirtualProtect = NULL;
    GETNATIVESYSTEMINFO pGetNativeSystemInfo = NULL;

    // 获取API的地址，将其存储在API指针变量中
    pGetProcAddress = (GETPROCADDR)GetApiAddressByHash(Kernel32_GetProcAddress);
    pLoadLibraryA = (LOADLIBRARYA)GetApiAddressByHash(Kernel32_LoadLibraryA);
    pVirtualAlloc = (VIRTUALALLOC)GetApiAddressByHash(Kernel32_VirtualAlloc);
    pVirtualProtect = (VIRTUALPROTECT)GetApiAddressByHash(Kernel32_VirtualProtect);
    pGetNativeSystemInfo = (GETNATIVESYSTEMINFO)GetApiAddressByHash(Kernel32_GetNativeSystemInfo);

    if (!pLoadLibraryA || !pGetProcAddress || !pVirtualAlloc || !pVirtualProtect || !pGetNativeSystemInfo)
    {
        return FALSE;
    }

    /*---------------------第三步：加载 PE 文件节到内存---------------------*/

    // 节表遍历与结束地址计算​
    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(pNtHeader);
    DWORD lastSectionEnd = 0;
    DWORD endOfSection;
    SYSTEM_INFO sysInfo;
    DWORD alignedImageSize;
    for (int i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++, sectionHeader++) {
        if (sectionHeader->SizeOfRawData == 0) {
            endOfSection = sectionHeader->VirtualAddress + pNtHeader->OptionalHeader.SectionAlignment;
        }
        else {
            endOfSection = sectionHeader->VirtualAddress + sectionHeader->SizeOfRawData;
        }

        if (endOfSection > lastSectionEnd) {
            lastSectionEnd = endOfSection;
        }
    }

    // 内存页对齐​
    pGetNativeSystemInfo(&sysInfo);
    alignedImageSize = (DWORD)AlignValueUp(pNtHeader->OptionalHeader.SizeOfImage, sysInfo.dwPageSize);
    if (alignedImageSize != AlignValueUp(lastSectionEnd, sysInfo.dwPageSize)) {
        return 0;
    }


    // 尝试按PE声明的ImageBase分配内存
    ULONG_PTR BaseAddress = (ULONG_PTR)pVirtualAlloc(
        (LPVOID)(pNtHeader->OptionalHeader.ImageBase),
        alignedImageSize,
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE
    );

    // 失败后由系统决定基址
    if (BaseAddress == 0) {
        BaseAddress = (ULONG_PTR)pVirtualAlloc(
            NULL,
            alignedImageSize,
            MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE
        );
    }


    // 复制PE头到目标内存
    for (int i = 0; i < pNtHeader->OptionalHeader.SizeOfHeaders; i++) {
        ((PBYTE)BaseAddress)[i] = ((PBYTE)uiLibraryAddress)[i];
    }

    // 新定位NT头指针
    pNtHeader = RVA(PIMAGE_NT_HEADERS, BaseAddress, ((PIMAGE_DOS_HEADER)BaseAddress)->e_lfanew);


    // 复制各节到内存
    sectionHeader = IMAGE_FIRST_SECTION(pNtHeader);

    for (int i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++, sectionHeader++) {
        for (int c = 0; c < sectionHeader->SizeOfRawData; c++) {
            ((PBYTE)(BaseAddress + sectionHeader->VirtualAddress))[c] = ((PBYTE)(uiLibraryAddress + sectionHeader->PointerToRawData))[c];
        }
    }


    /*---------------------第五步：修复重定位表----------------------*/

    ULONG_PTR baseOffset = BaseAddress - pNtHeader->OptionalHeader.ImageBase;
    PIMAGE_DATA_DIRECTORY dataDir = &pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    PIMAGE_BASE_RELOCATION relocation;
    PIMAGE_RELOC relocList;
    if (baseOffset && dataDir->Size) {

        PIMAGE_BASE_RELOCATION relocation = RVA(PIMAGE_BASE_RELOCATION, BaseAddress, dataDir->VirtualAddress);

        while (relocation->VirtualAddress) {
            relocList = (PIMAGE_RELOC)(relocation + 1);

            while ((PBYTE)relocList != (PBYTE)relocation + relocation->SizeOfBlock) {

                if (relocList->type == IMAGE_REL_BASED_DIR64)
                    *(PULONG_PTR)((PBYTE)BaseAddress + relocation->VirtualAddress + relocList->offset) += baseOffset;
                else if (relocList->type == IMAGE_REL_BASED_HIGHLOW)
                    *(PULONG_PTR)((PBYTE)BaseAddress + relocation->VirtualAddress + relocList->offset) += (DWORD)baseOffset;
                else if (relocList->type == IMAGE_REL_BASED_HIGH)
                    *(PULONG_PTR)((PBYTE)BaseAddress + relocation->VirtualAddress + relocList->offset) += HIWORD(baseOffset);
                else if (relocList->type == IMAGE_REL_BASED_LOW)
                    *(PULONG_PTR)((PBYTE)BaseAddress + relocation->VirtualAddress + relocList->offset) += LOWORD(baseOffset);

                relocList++;
            }
            relocation = (PIMAGE_BASE_RELOCATION)relocList;
        }
    }


    /*---------------------第六步：修复导入表---------------------*/
    PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)(pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + BaseAddress);
    //这个是IID的指针
    if (pImport != NULL)
    {
        while (pImport->Name != NULL)
        {
            char DLLname[100] = { 0 }; // 定义一个存储 DLL 名称的缓冲区
            char* uiLibraryAddressName = (char*)(pImport->Name + BaseAddress); // 获取 DLL 名称的地址

            // 手动将名称拷贝到 DLLname 缓冲区
            for (int i = 0; i < sizeof(DLLname) - 1; i++)
            {
                if (uiLibraryAddressName[i] == '\0') // 遇到字符串结束符时停止
                    break;
                DLLname[i] = uiLibraryAddressName[i]; // 拷贝字符
            }
            DLLname[sizeof(DLLname) - 1] = '\0'; // 确保缓冲区以 '\0' 结尾

            //通过名称找句柄
            HMODULE hProcess = pLoadLibraryA(DLLname);
            if (!hProcess)
            {
                return FALSE;
            }

            PIMAGE_THUNK_DATA64 pINT = (PIMAGE_THUNK_DATA64)(pImport->OriginalFirstThunk + BaseAddress);// 导入名称表
            PIMAGE_THUNK_DATA64 pIAT = (PIMAGE_THUNK_DATA64)(pImport->FirstThunk + BaseAddress); // 导入地址表
            while ((ULONG_PTR)(pINT->u1.AddressOfData) != NULL)
            {
                //根据IAT中存放信息，我们可以选择序号导入还是名称导入               
                if (pINT->u1.AddressOfData & IMAGE_ORDINAL_FLAG32)//判断如果是序号就是第一种处理方式
                {
                    //通过序号来获取地址
                    pIAT->u1.AddressOfData = (ULONG_PTR)(pGetProcAddress(hProcess, (LPCSTR)(pINT->u1.AddressOfData)));
                }
                else
                {
                    //通过函数名来获取地址
                    PIMAGE_IMPORT_BY_NAME pFucname = (PIMAGE_IMPORT_BY_NAME)(pINT->u1.AddressOfData + BaseAddress);
                    pIAT->u1.AddressOfData = (ULONG_PTR)(pGetProcAddress(hProcess, pFucname->Name));
                }
                pINT++;
                pIAT++;
            }
            pImport++;
        }
    }

    /*---------------------第七步：修改各节的内存保护属性--------------------*/
    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);
    DWORD executable, readable, writeable;
    DWORD dwProtect, dwOldProtect;
    for (DWORD i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++, pSectionHeader++) {

        if (pSectionHeader->SizeOfRawData) {

            // 获取当前节的保护属性
            executable = (pSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
            readable = (pSectionHeader->Characteristics & IMAGE_SCN_MEM_READ) != 0;
            writeable = (pSectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE) != 0;

            if (!executable && !readable && !writeable)
                dwProtect = PAGE_NOACCESS;                          // 不可访问
            else if (!executable && !readable && writeable)
                dwProtect = PAGE_WRITECOPY;                         // 写入时复制
            else if (!executable && readable && !writeable)
                dwProtect = PAGE_READONLY;                          // 只读
            else if (!executable && readable && writeable)
                dwProtect = PAGE_READWRITE;                         // 读写
            else if (executable && !readable && !writeable)
                dwProtect = PAGE_EXECUTE;                           // 仅执行
            else if (executable && !readable && writeable)
                dwProtect = PAGE_EXECUTE_WRITECOPY;                 // 可执行+写入时复制
            else if (executable && readable && !writeable)
                dwProtect = PAGE_EXECUTE_READ;                      // 可执行+只读
            else if (executable && readable && writeable)
                dwProtect = PAGE_EXECUTE_READWRITE;                 // 完全权限，即可读可写可执行

            // 处理非缓存属性
            if (pSectionHeader->Characteristics & IMAGE_SCN_MEM_NOT_CACHED) {
                dwProtect |= PAGE_NOCACHE;
            }

            // 修改当前节的内存保护属性
            pVirtualProtect(
                (LPVOID)(BaseAddress + pSectionHeader->VirtualAddress),
                pSectionHeader->SizeOfRawData,
                dwProtect, &dwOldProtect
            );
        }

    }

    /*---------------------第八步：执行TLS回调---------------------*/

    // 获取数据目录表中TLS项的地址
    dataDir = &pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    PIMAGE_TLS_DIRECTORY tlsDir;
    PIMAGE_TLS_CALLBACK* callback;
    if (dataDir->Size)
    {
        // 将TLS目录的RVA转换为内存地址
        tlsDir = RVA(PIMAGE_TLS_DIRECTORY, BaseAddress, dataDir->VirtualAddress);

        // 获取回调函数地址数组的起始位置
        callback = (PIMAGE_TLS_CALLBACK*)(tlsDir->AddressOfCallBacks);

        // 遍历回调函数数组
        for (; *callback; callback++) {

            // 调用回调函数，传递进程附加事件(DLL_PROCESS_ATTACH)
            (*callback)((LPVOID)BaseAddress, DLL_PROCESS_ATTACH, NULL);
        }
    }

    /*---------------------第九步：获取dllmain的地址，执行dllmain---------------------*/

    // 获取映射后的DLL的NT头
    PIMAGE_NT_HEADERS pNT = (PIMAGE_NT_HEADERS)(BaseAddress + pDOSheader->e_lfanew);

    typedef BOOL(WINAPI* DLLMAIN)(HINSTANCE, DWORD, LPVOID);
    // 获取DLL的入口点，一般为DllMain
    DLLMAIN dllentry = (DLLMAIN)((LPBYTE)BaseAddress + pNT->OptionalHeader.AddressOfEntryPoint);

    // 执行DllMain函数
    dllentry((HINSTANCE)BaseAddress,1,0);
    return TRUE;
}