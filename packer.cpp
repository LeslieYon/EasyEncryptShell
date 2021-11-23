#include <iostream>
#include "PETools.h"

int main() {
    //读取并加载需要加壳的文件的信息
    FILE* srcFile = OpenPEFile("..\\SrcTest.exe");
    void* psrcFileBuffer = ReadFileToFileBuffer(srcFile);
    DWORD srcFileSize = GetPEFileSize(srcFile);
    fclose(srcFile);

    //加密原始可执行程序
    for (int i=0;i<srcFileSize;i++)
        ((unsigned char*)psrcFileBuffer)[i] ^= i;

    //读取壳文件
    FILE* shellFile = OpenPEFile("loader.exe");
    void* pshellFileBuffer = ReadFileToFileBuffer(shellFile);
    fclose(shellFile);

    //合并节，为新的数据附加腾出空间
    MergeSection(&pshellFileBuffer,BufferType::FileBuffer,"Shell");

    //将加密的原始文件数据附加到壳的尾部
    AddSection(&pshellFileBuffer,BufferType::FileBuffer,"Data",CodeSection,srcFileSize,psrcFileBuffer);

    //写入硬盘
    SaveFileBufferToDisk(pshellFileBuffer,"loader.exe");

    return 0;
}
