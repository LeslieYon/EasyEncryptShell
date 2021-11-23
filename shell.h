//
// Created by Mr.Yll on 2022/3/28.
//

#ifndef SHELL_SHELL_H
#define SHELL_SHELL_H

#include "PETools.h"

BOOL UnloadShell(HANDLE ProcHnd, void* BaseAddr);
void* GetSrcPEImage(const void* BaseAddr);
BOOL CreateChildThrd(void* ObjectPEImage);
#endif //SHELL_SHELL_H
