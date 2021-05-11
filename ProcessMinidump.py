import os
import re
import sys
import psutil
import win32api
import win32con
import win32file
import win32security
from ctypes import windll

#####################
pid = 0  # pid为0时根据关键词(search_key)查找pid
search_key = ""  # 查找关键词


#####################


def get_pid():
    for this_pid in psutil.pids():
        p = psutil.Process(this_pid)
        if search_key in p.name():
            print("找到%spid: %d" % (search_key, this_pid))
            return this_pid
    print("%s未运行!!!" % search_key)
    sys.exit(-1)


def AdjustPrivilege(pri):
    flags = win32security.TOKEN_ADJUST_PRIVILEGES | win32security.TOKEN_QUERY
    token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), flags)
    pri_id = win32security.LookupPrivilegeValue(None, pri)
    newPrivileges = [(pri_id, win32security.SE_PRIVILEGE_ENABLED)]
    win32security.AdjustTokenPrivileges(token, 0, newPrivileges)


class MINIDUMP_TYPES_CLASS(object):
    """
    MINIDUMP types
    """

    MiniDumpNormal = 0x00000000
    MiniDumpWithDataSegs = 0x00000001
    MiniDumpWithFullMemory = 0x00000002
    MiniDumpWithHandleData = 0x00000004
    MiniDumpFilterMemory = 0x00000008
    MiniDumpScanMemory = 0x00000010
    MiniDumpWithUnloadedModules = 0x00000020
    MiniDumpWithIndirectlyReferencedMemory = 0x00000040
    MiniDumpFilterModulePaths = 0x00000080
    MiniDumpWithProcessThreadData = 0x00000100
    MiniDumpWithPrivateReadWriteMemory = 0x00000200
    MiniDumpWithoutOptionalData = 0x00000400
    MiniDumpWithFullMemoryInfo = 0x00000800
    MiniDumpWithThreadInfo = 0x00001000
    MiniDumpWithCodeSegs = 0x00002000


def DumpProcess(ProcessID):
    AdjustPrivilege("seDebugPrivilege")

    pHandle = win32api.OpenProcess(win32con.PROCESS_QUERY_INFORMATION | win32con.PROCESS_VM_READ, 0, ProcessID)

    fHandle = win32file.CreateFile("%s.tmp" % ProcessID,
                                   win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                                   win32file.FILE_SHARE_READ | win32file.FILE_SHARE_WRITE,
                                   None,
                                   win32file.CREATE_ALWAYS,
                                   win32file.FILE_ATTRIBUTE_NORMAL,
                                   None)

    windll.dbghelp.MiniDumpWriteDump(pHandle.handle,
                                     ProcessID,
                                     fHandle.handle,
                                     MINIDUMP_TYPES_CLASS.MiniDumpWithFullMemory,
                                     None,
                                     None,
                                     None)

    win32api.CloseHandle(pHandle)
    win32api.CloseHandle(fHandle)
    print("Minidump生成完成")


if __name__ == '__main__':
    if len(sys.argv) == 2:
        pid = int(sys.argv[1])
    if pid == 0:
        if search_key != "":
            pid = get_pid()
        else:
            print("pid和搜索关键词均未指定")
            sys.exit(-1)
    DumpProcess(pid)
