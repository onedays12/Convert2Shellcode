#include <windows.h>

// 1. 声明 TLS 回调函数
VOID NTAPI TlsCallback(PVOID DllHandle, DWORD Reason, PVOID Reserved);

// 2. 使用链接器指令将 TLS 回调放入特定段
#ifdef _WIN64
    #pragma comment (linker, "/INCLUDE:_tls_used")  // 64 位需要
    #pragma comment (linker, "/INCLUDE:pTlsCallback")
#else
    #pragma comment (linker, "/INCLUDE:__tls_used") // 32 位需要
    #pragma comment (linker, "/INCLUDE:_pTlsCallback")
#endif

// 3. 创建 TLS 目录
#pragma data_seg(".CRT$XLB")
EXTERN_C PIMAGE_TLS_CALLBACK pTlsCallback = TlsCallback;
#pragma data_seg()

// 4. TLS 回调函数实现
VOID NTAPI TlsCallback(PVOID DllHandle, DWORD Reason, PVOID Reserved)
{
    char message[256];
    const char* reasonStr = "Unknown";
    
    switch (Reason)
    {
    case DLL_PROCESS_ATTACH:
        reasonStr = "PROCESS_ATTACH";
        break;
    case DLL_PROCESS_DETACH:
        reasonStr = "PROCESS_DETACH";
        break;
    case DLL_THREAD_ATTACH:
        reasonStr = "THREAD_ATTACH";
        return; // 线程附加不显示消息框
    case DLL_THREAD_DETACH:
        reasonStr = "THREAD_DETACH";
        return; // 线程分离不显示消息框
    }
    
    // 显示回调信息
    wsprintfA(message, "Hello Oneday!\n"
              "DLL Handle: 0x%p\n"
              "Reason: %s\n"
              "Reserved: 0x%p",
              DllHandle, reasonStr, Reserved);
    
    MessageBoxA(NULL, message, "TLS Callback Demo", MB_OK | MB_ICONINFORMATION);
}

// 5. 标准 DLL 入口点
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    char message[128];
    
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        wsprintfA(message, "Hello Oneday!\nhinstDLL: 0x%p", hinstDLL);
        MessageBoxA(NULL, message, "DllMain", MB_OK | MB_ICONINFORMATION);
        break;
        
    case DLL_PROCESS_DETACH:
        MessageBoxA(NULL, "Hello Oneday!", "DllMain", MB_OK | MB_ICONINFORMATION);
        break;
    }
    
    return TRUE;
}