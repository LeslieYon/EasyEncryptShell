#include <iostream>
#include "shell.h"

int main(int argc, char *argv[]) {
    //获取当前模块加载基地址
    HANDLE handle = GetModuleHandleA(argv[0]);

    //从当前模块中取出加密的原始程序
    void * srcImageBuffer = GetSrcPEImage(handle);

    //将原始程序手动加载并执行
    CreateChildThrd(srcImageBuffer);
    return 0;
}