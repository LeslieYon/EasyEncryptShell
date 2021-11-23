//
// Created by Mr.Yll on 2022/3/31.
//

#include <iostream>
#include "shell.h"

int main(int argc, char *argv[]) {
    //从硬盘中读取壳文件
    FILE* shell= OpenPEFile("loader.exe");
    void* filebuffer = ReadFileToFileBuffer(shell);

    //从壳中取出加密的原始程序
    void * srcImageBuffer = GetSrcPEImage(filebuffer);

    //将原始程序存盘
    void* srcFileBuffer = ImageBufferToFileBuffer(srcImageBuffer);
    SaveFileBufferToDisk(srcFileBuffer,"..\\unpacked.exe");
    return 0;
}