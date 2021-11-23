//
// Created by Mr.Yll on 2022/3/28.
//

#include "shell.h"

BOOL UnloadShell(HANDLE ProcHnd, void *BaseAddr) {
    typedef unsigned long (__stdcall *pfZwUnmapViewOfSection)(unsigned long, unsigned long);
    pfZwUnmapViewOfSection ZwUnmapViewOfSection = nullptr;
    BOOL res = FALSE;
    HMODULE m = LoadLibrary(TEXT("ntdll.dll"));
    if (m) {
        //ZwUnmapViewOfSection = (pfZwUnmapViewOfSection)GetProcAddress(m, "ZwUnmapViewOfSection");
        //此处为减少特征，使用自己实现的GetProcAddress函数
        void *ntdll_filebuffer = ImageBufferToFileBuffer(m);
        void *ZwUnmapViewOfSection_foa = GetFuncFOAWithName(ntdll_filebuffer, "ZwUnmapViewOfSection", m);
        void *ZwUnmapViewOfSection_rva = FOA2RVA(ZwUnmapViewOfSection_foa, ntdll_filebuffer, m);
        ZwUnmapViewOfSection = (pfZwUnmapViewOfSection) ZwUnmapViewOfSection_rva;
        if (ZwUnmapViewOfSection) {
            //printf("%08x\n",m);
            //printf("%08x\n",ZwUnmapViewOfSection);
            res = (ZwUnmapViewOfSection((unsigned long) ProcHnd, (unsigned long) BaseAddr) == 0);
        }
        FreeLibrary(m);
        free(ntdll_filebuffer);
    }
    return res;
}

void *GetSrcPEImage(const void *BaseAddr) {
    const DWORD IMAGE_SIZEOF_DOSHEADER = sizeof(IMAGE_DOS_HEADER);
    PointersToPEBuffer BufferInfo;
    GetBufferInfo(BaseAddr, BufferInfo, BufferType::FileBuffer);
    for (DWORD i = 0; i < BufferInfo.PPEHeader->NumberOfSections; i++) {
        char SectionName[8]{0};
        memcpy(SectionName, (BufferInfo.PSectionTable + i)->Name, 8);
        if (strcmp(SectionName, "Data") == 0) //寻找嵌入了加密数据的节
        {
            DWORD SectionSize = (BufferInfo.PSectionTable + i)->Misc.VirtualSize;
            void *PEimage = malloc(SectionSize);
            void *pSection = (char *) BaseAddr + (BufferInfo.PSectionTable + i)->VirtualAddress;
            printf("Read source enctypted image data from 0x%08x ...\n",pSection);fflush(stdout);
            memcpy(PEimage, pSection, SectionSize); //取出加密的PE文件
            for (int j = 0; j < SectionSize; j++) //解密
                ((unsigned char *) PEimage)[j] ^= j;
            void *ImageBuffer = FileBufferToImageBuffer(PEimage);
            free(PEimage);
            return ImageBuffer;
        }
    }
    Error("Can't find Src PE file section!");
    return nullptr;
}

DWORD WINAPI RUN(_In_ LPVOID lpParameter) {
    asm(".intel_syntax noprefix\n\t"
        "mov eax,[ebp+8]\n\t" //获得第一个参数（即需要转到的地址）
        "call eax\n\t" //执行跳转
        "pop ebp\n\t"
        "ret 4\n\t" //平衡堆栈
        ".att_syntax noprefix\n\t");
}

BOOL CreateChildThrd(void *ObjectPEImage) {
    PointersToPEBuffer BufferInfo;
    GetBufferInfo(ObjectPEImage, BufferInfo, BufferType::ImageBuffer, true);
    void* ImageLoadAddr = VirtualAlloc( (LPVOID)BufferInfo.POptionHeader->ImageBase,BufferInfo.PEBufferSize,MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!ImageLoadAddr) {
        if (!BufferInfo.pRelocationTable){ //如果在默认基址处分配内存失败，且没有重定位表，则加载失败
            Error("Can't Load Src PE file on default offset!");
            return false;
        }
        ImageLoadAddr = VirtualAlloc(nullptr, BufferInfo.PEBufferSize, MEM_RESERVE | MEM_COMMIT,PAGE_EXECUTE_READWRITE);
        printf("Alloc new space at 0x%08x ...\n",ImageLoadAddr);fflush(stdout);
        if (!RebuildRelocationTable(ObjectPEImage, BufferType::ImageBuffer, ImageLoadAddr)) //重定位PE文件
        {
            Error("Can't rebulid Src PE relocation!");
            return false;
        }
        if (!BuildImportTable(ObjectPEImage,BufferType::ImageBuffer))
        {
            Error("Can't build image import table!");
            return false;
        }
        if (!memcpy( ImageLoadAddr, ObjectPEImage, BufferInfo.PEBufferSize)) {
            Error("Can't write Src PE image to new space!");
            return false;
        }
        void* ObjectOEP = (void*)((DWORD) ImageLoadAddr + BufferInfo.POptionHeader->AddressOfEntryPoint);
        HANDLE hSrcPE = CreateThread(NULL, 0, RUN,ObjectOEP,0, NULL);
        printf("Create and run Src PE image as new thread %d ...\n", GetThreadId(hSrcPE));fflush(stdout);
        WaitForSingleObject(hSrcPE,INFINITE);
        DWORD dwExitCode = 0;
        GetExitCodeThread(hSrcPE,&dwExitCode);
        printf("Src PE image has exited with code 0x%08x ...\n", dwExitCode);fflush(stdout);
        CloseHandle(hSrcPE);
    }
    return true;
}

/*BOOL CreateChildProc(void *ObjectPEImage) {
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    memset(&pi, 0, sizeof(pi));
    wprintf(GetCommandLine());
    //以挂起方式运行进程
    BOOL res = CreateProcess(TEXT("shell_packed.exe"),
                             NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL,
                             &si, &pi);
    if (res) {
        //获取主线程的信息
        CONTEXT Ctx;
        Ctx.ContextFlags = CONTEXT_FULL;
        GetThreadContext(pi.hThread, &Ctx);
        void *ChildProcessBaseAddr = nullptr;
        //读取主程序加载位置
        ReadProcessMemory(pi.hProcess, (void *) (Ctx.Ebx + 8), &ChildProcessBaseAddr, sizeof(unsigned long), nullptr);
        PointersToPEBuffer BufferInfo;
        GetBufferInfo(ObjectPEImage, BufferInfo, BufferType::ImageBuffer, true);
        //卸载子进程中的壳文件
        if (!UnloadShell(pi.hProcess, ChildProcessBaseAddr))
            return false;
        //在子进程中为原始PE文件分配空间
        //尝试在默认基址处分配空间
        //void* ImageLoadAddr = VirtualAllocEx(pi.hProcess, (LPVOID)BufferInfo.POptionHeader->ImageBase,BufferInfo.PEBufferSize,MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        void *ImageLoadAddr = nullptr; //强制在非默认地址分配内存//
        if (!ImageLoadAddr) {
            if (!BufferInfo.pRelocationTable) //如果在默认基址处分配内存失败，且没有重定位表，则加载失败
            {
                TerminateProcess(pi.hProcess, -1);
                Error("Can't Load Src PE file on default offset!");
                return false;
            }
            //尝试在其它位置分配内存空间
            //BufferInfo.PNTHeader->OptionalHeader.DllCharacteristics = 0x8100;
            ImageLoadAddr = VirtualAllocEx(pi.hProcess, nullptr, BufferInfo.PEBufferSize, MEM_RESERVE | MEM_COMMIT,
                                           PAGE_EXECUTE_READWRITE|PAGE_NOCACHE);
            if (!RebuildRelocationTable(ObjectPEImage, BufferType::ImageBuffer, ImageLoadAddr)) //重定位PE文件
            {
                TerminateProcess(pi.hProcess, -1);
                Error("Can't rebulid Src PE relocation!");
                return false;
            }
            //SaveFileBufferToDisk(ImageBufferToFileBuffer(ObjectPEImage),"new.exe");
        }
        //向子进程写入解密的原始PE文件
        if (!WriteProcessMemory(pi.hProcess, ImageLoadAddr, ObjectPEImage, BufferInfo.PEBufferSize, nullptr)) {
            Error("Can't write Src PE file to new process!");
            TerminateProcess(pi.hProcess, -1);
            return false;
        }
        Ctx.Eax = (DWORD) ImageLoadAddr + BufferInfo.POptionHeader->AddressOfEntryPoint; //修正EIP为新镜像的OEP
        WriteProcessMemory(pi.hProcess,(LPVOID)(Ctx.Ebx+8),&ImageLoadAddr,sizeof(DWORD), nullptr);
        SetThreadContext(pi.hThread, &Ctx); //更新子进程执行上下文
        ResumeThread(pi.hThread); //恢复子进程
        CloseHandle(pi.hThread);
        WaitForSingleObject(pi.hProcess,INFINITE);
        DWORD dwExitCode;
        GetExitCodeProcess(pi.hProcess,&dwExitCode);
        printf("\nExit Code:%x\n",dwExitCode);
    } else {
        Error("Can't create child process!");
        return false;
    }
    return true;
}*/