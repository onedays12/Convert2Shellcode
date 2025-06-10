#include <windows.h>  // 必须包含Windows头文件以使用MessageBox

int main() {
    // 调用MessageBox函数
    int result = MessageBox(
        NULL,                   // 父窗口句柄（无父窗口设为NULL）
        L"Hello,Oneday!",   // 对话框正文内容
        L"操作确认",             // 对话框标题
        MB_YESNO | MB_ICONQUESTION  // 按钮组合+图标类型
    );

    // 根据用户点击的按钮处理逻辑
    if (result == IDYES) {
        MessageBox(NULL, L"您选择了【是】", L"结果提示", MB_OK | MB_ICONINFORMATION);
    }
    else if (result == IDNO) {
        MessageBox(NULL, L"您选择了【否】", L"结果提示", MB_OK | MB_ICONWARNING);
    }

    return 0;
}