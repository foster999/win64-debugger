from ctypes import *

# Map Microsoft types to ctypes
BYTE = c_ubyte
WORD = c_ushort
DWORD = c_ulong
DWORD64 = c_ulonglong
LPBYTE = POINTER(c_ubyte)
LPTSTR = POINTER(c_char)
HANDLE = c_void_p
PVOID = c_void_p
UINT_PTR = c_ulong


# Constants
DEBUG_PROCESS =  0x00000001
CREATE_NEW_CONSOLE = 0x00000010
PROCESS_ALL_ACCESS = 0x001F0FFF
INFINITE = 0xFFFFFFFF
DBG_CONTINUE = 0x00010002


# Thread constants
THREAD_ALL_ACCESS = 0x001F03FF
TH32CS_SNAPTHREAD = 0x00000004


# Context constants
CONTEXT_FULL = 0x00010007
CONTEXT_DEBUG_REGISTERS = 0x00010010


# Debug event constants
EXCEPTION_DEBUG_EVENT = 0x1
CREATE_THREAD_DEBUG_EVENT = 0x2
CREATE_PROCESS_DEBUG_EVENT = 0x3
EXIT_THREAD_DEBUG_EVENT = 0x4
EXIT_PROCESS_DEBUG_EVENT = 0x5
LOAD_DLL_DEBUG_EVENT = 0x6
UNLOAD_DLL_DEBUG_EVENT = 0x7
OUTPUT_DEBUG_STRING_EVENT = 0x8
RIP_EVENT = 0x9


# Debug exception constants
EXCEPTION_ACCESS_VIOLATION = 0xC0000005
EXCEPTION_BREAKPOINT = 0x80000003
EXCEPTION_GUARD_PAGE = 0x80000001
EXCEPTION_SINGLE_STEP = 0x80000004


class STARTUPINFO(Structure):
    __fields_ = [
        ("cb", DWORD),
        ("lpReserved", LPTSTR),
        ("lpDesktop", LPTSTR),
        ("lpTitle", LPTSTR),
        ("dwX", DWORD),
        ("dwY", DWORD),
        ("dwXSize", DWORD),
        ("dwYSize", DWORD),
        ("dwXCountChars", DWORD),
        ("dwYCountChars", DWORD),
        ("dwFillAttribute",DWORD),
        ("dwFlags", DWORD),
        ("wShowWindow", WORD),
        ("cbReserved2", WORD),
        ("lpReserved2", LPBYTE),
        ("hStdInput", HANDLE),
        ("hStdOutput", HANDLE),
        ("hStdError", HANDLE),
        ]


class PROCESS_INFORMATION(Structure):
    _fields_ = [
        ("hProcess", HANDLE),
        ("hThread", HANDLE),
        ("dwProcessId", DWORD),
        ("dwThreadId", DWORD),
        ]


class EXCEPTION_RECORD(Structure):
    pass

EXCEPTION_RECORD._fields_ = [
        ("ExceptionCode",        DWORD),
        ("ExceptionFlags",       DWORD),
        ("ExceptionRecord",      POINTER(EXCEPTION_RECORD)),  # WTF
        ("ExceptionAddress",     PVOID),
        ("NumberParameters",     DWORD),
        ("ExceptionInformation", UINT_PTR * 15),
        ]


class _EXCEPTION_RECORD(Structure):
    _fields_ = [
        ("ExceptionCode",        DWORD),
        ("ExceptionFlags",       DWORD),
        ("ExceptionRecord",      POINTER(EXCEPTION_RECORD)),
        ("ExceptionAddress",     PVOID),
        ("NumberParameters",     DWORD),
        ("ExceptionInformation", UINT_PTR * 15),
        ]


# Exceptions
class EXCEPTION_DEBUG_INFO(Structure):
    _fields_ = [
        ("ExceptionRecord",    EXCEPTION_RECORD),
        ("dwFirstChance",      DWORD),
        ]


class DEBUG_EVENT_UNION(Union):
    _fields_ = [
        ("Exception", EXCEPTION_DEBUG_INFO),
#        ("CreateThread",      CREATE_THREAD_DEBUG_INFO),
#        ("CreateProcessInfo", CREATE_PROCESS_DEBUG_INFO),
#        ("ExitThread",        EXIT_THREAD_DEBUG_INFO),
#        ("ExitProcess",       EXIT_PROCESS_DEBUG_INFO),
#        ("LoadDll",           LOAD_DLL_DEBUG_INFO),
#        ("UnloadDll",         UNLOAD_DLL_DEBUG_INFO),
#        ("DebugString",       OUTPUT_DEBUG_STRING_INFO),
#        ("RipInfo",           RIP_INFO),
        ]   


class DEBUG_EVENT(Structure):
    _fields_ = [
        ("dwDebugEventCode", DWORD),
        ("dwProcessId",  DWORD),
        ("dwThreadId", DWORD),
        ("u", DEBUG_EVENT_UNION),
        ]


class THREADENTRY32(Structure):
    """
    Holds information about a thread.
    Useful for enumerating all threads, to find those owned by
    a particular process.
    """
    _fields_ = [
        ("dwSize",             DWORD),
        ("cntUsage",           DWORD),
        ("th32ThreadID",       DWORD),
        ("th32OwnerProcessID", DWORD),
        ("tpBasePri",          DWORD),
        ("tpDeltaPri",         DWORD),
        ("dwFlags",            DWORD),
    ]


class FLOATING_SAVE_AREA(Structure):
    """
    Use by CONTEXT.
    """
    _fields_ = [
        ("ControlWord", DWORD),
        ("StatusWord", DWORD),
        ("TagWord", DWORD),
        ("ErrorOffset", DWORD),
        ("ErrorSelector", DWORD),
        ("DataOffset", DWORD),
        ("DataSelector", DWORD),
        ("RegisterArea", BYTE * 80),
        ("Cr0NpxState", DWORD),
]


class CONTEXT(Structure):
    """
    Context for 32-bit process thread.
    Holds register values from a Wow64GetThreadContext() call.
    WoW64 subsystems are capable of running 32-bit applications.
    """
    _fields_ = [
        ("ContextFlags", DWORD),
        ("Dr0", DWORD),
        ("Dr1", DWORD),
        ("Dr2", DWORD),
        ("Dr3", DWORD),
        ("Dr6", DWORD),
        ("Dr7", DWORD),
        ("FloatSave", FLOATING_SAVE_AREA),
        ("SegGs", DWORD),
        ("SegFs", DWORD),
        ("SegEs", DWORD),
        ("SegDs", DWORD),
        ("Edi", DWORD),
        ("Esi", DWORD),
        ("Ebx", DWORD),
        ("Edx", DWORD),
        ("Ecx", DWORD),
        ("Eax", DWORD),
        ("Ebp", DWORD),
        ("Eip", DWORD),
        ("SegCs", DWORD),
        ("EFlags", DWORD),
        ("Esp", DWORD),
        ("SegSs", DWORD),
        ("ExtendedRegisters", BYTE * 512),
]


class M128A(Structure):
    _fields_ = [
            ("Low", DWORD64),
            ("High", DWORD64)
            ]


class XMM_SAVE_AREA32(Structure):
    _pack_ = 1 
    _fields_ = [  
                ('ControlWord', WORD), 
                ('StatusWord', WORD), 
                ('TagWord', BYTE), 
                ('Reserved1', BYTE), 
                ('ErrorOpcode', WORD), 
                ('ErrorOffset', DWORD), 
                ('ErrorSelector', WORD), 
                ('Reserved2', WORD), 
                ('DataOffset', DWORD), 
                ('DataSelector', WORD), 
                ('Reserved3', WORD), 
                ('MxCsr', DWORD), 
                ('MxCsr_Mask', DWORD), 
                ('FloatRegisters', M128A * 8), 
                ('XmmRegisters', M128A * 16), 
                ('Reserved4', BYTE * 96)
                ] 


class DUMMYSTRUCTNAME(Structure):
    _fields_=[
              ("Header", M128A * 2),
              ("Legacy", M128A * 8),
              ("Xmm0", M128A),
              ("Xmm1", M128A),
              ("Xmm2", M128A),
              ("Xmm3", M128A),
              ("Xmm4", M128A),
              ("Xmm5", M128A),
              ("Xmm6", M128A),
              ("Xmm7", M128A),
              ("Xmm8", M128A),
              ("Xmm9", M128A),
              ("Xmm10", M128A),
              ("Xmm11", M128A),
              ("Xmm12", M128A),
              ("Xmm13", M128A),
              ("Xmm14", M128A),
              ("Xmm15", M128A)
              ]


class DUMMYUNIONNAME(Union):
    _fields_=[
              ("FltSave", XMM_SAVE_AREA32),
              ("DummyStruct", DUMMYSTRUCTNAME)
              ]


class CONTEXT64(Structure):
    """
    Context for 64-bit process thread.
    Holds register values from a GetThreadContext() call.
    """
    _pack_ = 16
    _fields_ = [
        ("P1Home", DWORD64),
        ("P2Home", DWORD64),
        ("P3Home", DWORD64),
        ("P4Home", DWORD64),
        ("P5Home", DWORD64),
        ("P6Home", DWORD64),

        ("ContextFlags", DWORD),
        ("MxCsr", DWORD),

        ("SegCs", WORD),
        ("SegDs", WORD),
        ("SegEs", WORD),
        ("SegFs", WORD),
        ("SegGs", WORD),
        ("SegSs", WORD),
        ("EFlags", DWORD),

        ("Dr0", DWORD64),
        ("Dr1", DWORD64),
        ("Dr2", DWORD64),
        ("Dr3", DWORD64),
        ("Dr6", DWORD64),
        ("Dr7", DWORD64),

        ("Rax", DWORD64),
        ("Rcx", DWORD64),
        ("Rdx", DWORD64),
        ("Rbx", DWORD64),
        ("Rsp", DWORD64),
        ("Rbp", DWORD64),
        ("Rsi", DWORD64),
        ("Rdi", DWORD64),
        ("R8", DWORD64),
        ("R9", DWORD64),
        ("R10", DWORD64),
        ("R11", DWORD64),
        ("R12", DWORD64),
        ("R13", DWORD64),
        ("R14", DWORD64),
        ("R15", DWORD64),
        ("Rip", DWORD64),

        ("DebugControl", DWORD64),
        ("LastBranchToRip", DWORD64),
        ("LastBranchFromRip", DWORD64),
        ("LastExceptionToRip", DWORD64),
        ("LastExceptionFromRip", DWORD64),

        ("DUMMYUNIONNAME", DUMMYUNIONNAME),

        ("VectorRegister", M128A * 26),
        ("VectorControl", DWORD64)
    ]
