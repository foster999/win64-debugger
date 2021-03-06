from ctypes import *
from ctypes.wintypes import *
from win64_debugger.structs import *
import traceback
import sys

kernel32 = WinDLL('kernel32', use_last_error=True)

# Define prototype param and return types
kernel32.DebugActiveProcess.argtypes = [DWORD]
kernel32.DebugActiveProcess.restype = BOOL

kernel32.WaitForDebugEvent.argtypes = [POINTER(DEBUG_EVENT), DWORD]
kernel32.WaitForDebugEvent.restype = BOOL

kernel32.ContinueDebugEvent.argtypes = [DWORD, DWORD, DWORD]
kernel32.ContinueDebugEvent.restype = BOOL


kernel32.GetThreadContext.argtypes = [HANDLE, POINTER(CONTEXT64)]
kernel32.GetThreadContext.restype = BOOL

kernel32.SetThreadContext.argtypes = [HANDLE, POINTER(CONTEXT64)]
kernel32.SetThreadContext.restype = BOOL


kernel32.OpenProcess.argtypes = [DWORD, BOOL, DWORD64]
kernel32.OpenProcess.restype = HANDLE

kernel32.OpenThread.argtypes = [DWORD, BOOL, DWORD64]
kernel32.OpenThread.restype = HANDLE

kernel32.CloseHandle.argtypes = [HANDLE]
kernel32.CloseHandle.restype = BOOL


kernel32.GetModuleHandleW.argtypes = [LPCWSTR]
kernel32.GetModuleHandleW.restype = HMODULE

kernel32.GetProcAddress.argtypes = [HMODULE, LPCSTR]
kernel32.GetProcAddress.restype = c_void_p


kernel32.ReadProcessMemory.argtypes = [HANDLE, LPCVOID, LPVOID, c_size_t, POINTER(c_size_t)]
kernel32.ReadProcessMemory.restype = BOOL

kernel32.WriteProcessMemory.argtypes = [HANDLE, LPVOID, LPCVOID, c_size_t, POINTER(c_size_t)]
kernel32.WriteProcessMemory.restype = BOOL

kernel32.GetSystemInfo.argtypes = [POINTER(SYSTEM_INFO)]
kernel32.GetSystemInfo.restype = BOOL

kernel32.VirtualQueryEx.argtypes = [HANDLE, LPCVOID, POINTER(MEMORY_BASIC_INFORMATION), SIZE_T]
kernel32.VirtualQueryEx.restype = BOOL

kernel32.VirtualProtectEx.argtypes = [HANDLE, LPVOID, SIZE_T, DWORD, POINTER(DWORD)]
kernel32.VirtualProtectEx.restype = BOOL


class Debugger():
    def __init__(self):
        self.process_handle = None
        self.pid = None
        self.debugger_active = False
        self.debugger_attached = False
        self.thread_handle = None
        self.context = None
        self.exception = None
        self.exception_address = None
        self.soft_breakpoints = {}
        self.first_breakpoint = True
        self.hardware_breakpoints = {}

        # Get default system page size
        system_info = SYSTEM_INFO()
        kernel32.GetSystemInfo(byref(system_info))
        self.page_size = system_info.dwPageSize
        
        self.guarded_pages = {}
        self.memory_breakpoints = {}

    def __enter__(self):
        return self
    
    def __exit__(self):
        self.run()
        if self.debugger_attached:
            self.detach()
    

    def load(self, command):
        """
        Launch the specified executable, with debugging access for the
        process.
        """
        executable = command[0]
        creation_flags = DEBUG_PROCESS

        startupinfo = STARTUPINFO()
        process_information = PROCESS_INFORMATION()

        startupinfo.dwFlags = 0x00000001
        startupinfo.wShowWindow = 0x00000000

        startupinfo.cb = sizeof(startupinfo)

        # Python 3 requires CreateProcessW, for UNICODE str
        if kernel32.CreateProcessW(
            executable,
            " ".join(command),
            None,
            None,
            None,
            creation_flags,
            None,
            None,
            byref(startupinfo),
            byref(process_information)
            ):
            print("[*] Successfully launched the process")
            print(f"[*] PID: {process_information.dwProcessId}")
        else:
            print(f"[*] Process could not be launched")
            print(f"[*] Error: 0x{get_last_error():016x}")

        self.process_handle = self.open_process(
            process_information.dwProcessId
            )


    def open_process(self, pid):
        """
        Get a process handle for a given process id (`pid`).
        """
        process_handle = kernel32.OpenProcess(
            PROCESS_ALL_ACCESS,
            False,
            pid
            )
        return process_handle


    def attach(self, pid):
        """
        Attach to active process by process id (`pid`).
        
        Retrieve process handle and acquire debugging access.
        """
        self.process_handle = self.open_process(pid)

        if kernel32.DebugActiveProcess(pid):
            self.debugger_active = True
            self.pid = int(pid)
            self.debugger_attached = True
            print(f"[*] Attached to process: {pid}")
        else:
            raise SystemExit("[*] Failed to attach debugger to process")
    

    def run(self):
        """
        Debug loop - one event at a time.
        """
        self.print_event_code_descriptions()
        while self.debugger_active == True:
            self.get_debug_event()
                

    def get_debug_event(self):
        """
        Gets next debug event and handle event types.
        Deactivates debugger when process is exited.
        """
        debug_event = DEBUG_EVENT()
        continue_status = DBG_CONTINUE

        if kernel32.WaitForDebugEvent(byref(debug_event), INFINITE):
            # Store thread info
            self.thread_handle = self.open_thread(debug_event.dwThreadId)
            self.context = self.get_thread_context(thread_handle = self.thread_handle)
            
            print(
                f"[*] Event code: 0x{debug_event.dwDebugEventCode}"
                f"     Thread ID: 0x{debug_event.dwThreadId:08x}"
                )

            event_code = debug_event.dwDebugEventCode
            if event_code == EXCEPTION_DEBUG_EVENT:
                exception_record = debug_event.u.Exception.ExceptionRecord
                self.exception = exception_record.ExceptionCode
                self.exception_address = exception_record.ExceptionAddress
            
                if self.exception == EXCEPTION_ACCESS_VIOLATION:
                    print("[**] Access violation detected")
                    self.dump_registers()
                    self.debugger_active = False  # Process doesn't seem to recover from this
                elif self.exception == EXCEPTION_BREAKPOINT:
                    print("[**] Hit user defined soft breakpoint")
                    continue_status = self.exception_handler_breakpoint()
                elif self.exception == EXCEPTION_GUARD_PAGE:
                    print("[**] Hit memory breakpoint - guard page access detected")
                    # System removes guard status for us
                elif self.exception == EXCEPTION_SINGLE_STEP:
                    print("[**] Hit hardware breakpoint - single stepping")
                    self.exception_handler_single_step()
                    
            elif event_code == EXIT_PROCESS_DEBUG_EVENT:
                print("[*] Process exited")
                self.debugger_active = False
        
            kernel32.ContinueDebugEvent(
                debug_event.dwProcessId,
                debug_event.dwThreadId,
                continue_status
            )
        

    def exception_handler_breakpoint(self):
        """
        Handle soft breakpoints.
        """
        if self.exception_address in self.soft_breakpoints:
            # Put this back where it belongs
            self.write_process_memory(
                self.exception_address,
                self.soft_breakpoints[self.exception_address]
                )
            
            # Reset thread context instruction pointer
            self.context = self.get_thread_context(
                thread_handle = self.thread_handle
                )
            self.context.Rip -= 1

            kernel32.SetThreadContext(self.thread_handle, byref(self.context))

        else:
            if self.first_breakpoint:
                print("[**] Hit Windows driven breakpoint")
            else:
                print("[**] Hit non-user-defined breakpoint")

        print(f"[**] Exception address: 0x{self.exception_address:016x}")
        return DBG_CONTINUE


    def detach(self):
        """
        Take process out of debug mode.
        """
        if kernel32.DebugActiveProcessStop(self.pid):
            self.debugger_attached = False
            print("[*] Exiting debugger")
            return True
        else:
            print("[*] There was an error detaching debugger")
            return False


    def open_thread(self, thread_id):
        """
        Get a thread handle for a given `thread_id`.
        """
        thread_handle = kernel32.OpenThread(
            THREAD_ALL_ACCESS,
            False,
            thread_id
        )
        if thread_handle is not None:
            return thread_handle
        
        print("[*] Could not obtain valid thread handle")
        return False

    
    def enumerate_threads(self):
        """
        Creat a list of thread IDs for children of the proccess that the
        debugger is attached to.
        """
        snapshot = kernel32.CreateToolhelp32Snapshot(
            TH32CS_SNAPTHREAD,
            self.pid
        )
        if snapshot is not None:
            thread_entry = THREADENTRY32()
            thread_entry.dwSize = sizeof(thread_entry)  # Size must be set
            success = kernel32.Thread32First(
                snapshot,
                byref(thread_entry)
            )
        
            thread_list = []
            while success:
                if thread_entry.th32OwnerProcessID == self.pid:
                    thread_list.append(thread_entry.th32ThreadID)
                success = kernel32.Thread32Next(
                    snapshot,
                    byref(thread_entry)
                    )
            # Prevent leaks
            kernel32.CloseHandle(snapshot)
            return thread_list

        print("[*] Could not enumerate threads")
        return False


    def get_thread_context(self, thread_id = None, thread_handle = None):
        """
        Get context object for specified thread ID or context.
        Context contains register info.
        """
        context = CONTEXT64()
        context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS

        if thread_handle is None:
            if thread_id is None:
                print(f"[*] Must provide thread ID or handle to get context")
                return False
            thread_handle = self.open_thread(thread_id)

        if kernel32.GetThreadContext(thread_handle, byref(context)):
            return context
        
        print(f"[*] Could not get context for thread")
        return False


    def read_process_memory(self, address, length):
        """
        Read `length` bytes from the specified memory `address`.
        """
        read_buffer = create_string_buffer(length)
        read_byte_count = c_size_t(0)

        if not kernel32.ReadProcessMemory(
            self.process_handle,
            address,
            read_buffer,
            length,
            byref(read_byte_count)
        ):
            return False
        else:
            return read_buffer.raw


    def write_process_memory(self, address, data):
        """
        Write `data` to the specified memory `address`.
        """
        write_byte_count = c_size_t(0)
        length = len(data)
        c_data = c_char_p(data[write_byte_count.value:])

        if not kernel32.WriteProcessMemory(
            self.process_handle,
            address,
            c_data,
            length,
            byref(write_byte_count)
        ):
            return False
        else:
            return True

        
    def set_soft_breakpoint(self, address):
        """
        Set a soft breakpoint at the specified memory `address`.

        Replaces a byte with INT3 (halt in operation code), to set a soft
        breakpoint. Stores the original byte in `self.soft_breakpoints`, to be
        reinserted when the breakpoint is hit.
        """
        if address not in self.soft_breakpoints:
            original_byte = self.read_process_memory(address, 1)
            # Replace with INT3
            if self.write_process_memory(address, b"\xCC"):
                self.soft_breakpoints[address] = original_byte
                print(f"[*] Soft breakpoint set at 0x{address:016x}")
                return True
            
            print("[*] Could not set breakpoint")
            return False


    def set_hardware_breakpoint(self, address, length, condition):
        """
        Set a hardware breakpoint in all active threads.

        See https://www.oreilly.com/library/view/mastering-assembly-programming/9781787287488/663ff39a-7ec3-4d2b-b6bd-43cdb6b0ca71.xhtml
        for bit layout of Dr7 register.

        Parameters
        ----------
        address
            location of breakpoint in memory
        length
            length of data item to be monitored. 1, 2 or 4 bytes.
        condition
            when breakpoint should be triggered. HW_ACCESS, HW_EXCECUTE or HW_WRITE.
        """
        if length in (1, 2, 4):
            # 0 indicates 1 byte length
            length -= 1
        else:
            return False

        if condition not in (HW_ACCESS, HW_EXECUTE, HW_WRITE):
            return False

        available = (set(range(4)) - set(self.hardware_breakpoints.keys()))

        if len(available) < 1:
            return False
        else:
            slot = available.pop()

        # Set debug control register flag in every thread
        for thread_id in self.enumerate_threads():
            context = self.get_thread_context(thread_id=thread_id)

            # Enable local breakpoint for available register
            context.Dr7 |= 1 << (slot * 2)
            # Enable exact data breakpoint match (if supported)
            context.Dr7 |= 1 << 8

            # Save breakpoint address in available register
            hardware_breakpoint_address_registers = {
                0: context.Dr0,
                1: context.Dr1,
                2: context.Dr2,
                3: context.Dr3,
            }
            hardware_breakpoint_address_registers[slot] = address

            # Set condition/type of breakpoint
            context.Dr7 |= condition << ((slot * 4) + 16)

            # Set length (size in bytes)
            context.Dr7 |= length << ((slot * 4) + 18)

            thread_handle = self.open_thread(thread_id)
            kernel32.SetThreadContext(thread_handle, byref(context))

        self.hardware_breakpoints[slot] = (address, length, condition)
        print(f"[**] Hardware breakpoint set at 0x{address:016x}")

        return True


    def set_memory_breakpoint(self, address, size):
        mbi = MEMORY_BASIC_INFORMATION()
        if kernel32.VirtualQueryEx(
            self.process_handle,
            address,
            byref(mbi),
            sizeof(mbi)
        ) < sizeof(mbi):  # Must be full size
            return False
        
        current_page = c_ulong(0)
        while current_page <= address + size:
            self.guarded_pages.append(current_page)  # So we can identify those we've created

            old_protection = c_ulong(0)

            if not kernel32.VirtualProtectEx(
                self.process_handle,
                current_page,
                size,
                mbi.Protect | PAGE_GUARD,
                byref(old_protection)
            ):
                return False
            
            # Increment by default system page size
            current_page += self.page_size

        self.memory_breakpoints[address] = (address, size, mbi)

        return True


    def exception_handler_single_step(self):
        """
        Determine if single step occured in reaction to a hardware breakpoint
        and grab the hit breakpoint.

        Should check for BS flag in Dr6, but Windows doesn't propagate this
        down correctly...
        """
        if self.context.Dr6 & 0x1 and self.hardware_breakpoints.has_key(0):
            slot = 0
        elif self.context.Dr6 & 0x2 and self.hardware_breakpoints.has_key(1):
            slot = 1
        elif self.context.Dr6 & 0x4 and self.hardware_breakpoints.has_key(2):
            slot = 2
        elif self.context.Dr6 & 0x8 and self.hardware_breakpoints.has_key(3):
            slot = 3
        else:
            continue_status = DBG_EXCEPTION_NOT_HANDLED

        if self.delete_hardware_breakpoint(slot):
            continue_status = DBG_CONTINUE
        
        print("[*] Hardware breakpoint removed.")
        return continue_status


    def delete_hardware_breakpoint(self, slot):
        """
        Disable a hardware breakpoint in all active threads.

        Reverse of adding a hardware breakpoint.
        """
        for thread_id in self.enumerate_threads():
            context = self.get_thread_context(thread_id=thread_id)
            # Remove breakpoint
            context.Dr7 &= ~(1 << (slot * 2))
            context.Dr7 &= ~(1 << 8)
        
            hardware_breakpoint_address_registers = {
                0: context.Dr0,
                1: context.Dr1,
                2: context.Dr2,
                3: context.Dr3,
            }
            hardware_breakpoint_address_registers[slot] = 0x00000000

            # Remove condition/type flag
            context.Dr7 &= ~(3 << ((available * 4) + 16))

            # Remove length flag
            context.Dr7 &= ~(3 << ((available * 4) + 18))

            thread_handle = self.open_thread(thread_id)
            kernel32.SetThreadContext(thread_handle, byref(context))

        del self.hardware_breakpoints[slot]
        
        return True


    @staticmethod
    def resolve_function_address(dll, function):
        """
        Get the address of a function in the specified dynamic linked library
        (dll - i.e. module).

        Parameters
        ----------
        dll
            name of dll file that function is located in
        function
            name of function
        """
        module_handle = kernel32.GetModuleHandleW(dll)

        function_address = kernel32.GetProcAddress(
            module_handle,
            bytes(function, "utf-8")  # Method requires byte str
            )
        # Don't need to worry about closing module "handle"
        return hex(function_address)


    def dump_registers(self):
        """
        Dump 64-bit register contents for each thread that belongs to the
        process.
        """
        thread_list = self.enumerate_threads()

        registers = {
            "RIP": "Rip",
            "RSP": "Rsp",
            "RBP": "Rbp",
            "RAX": "Rax",
            "RBX": "Rbx",
            "RCX": "Rcx",
            "RDX": "Rdx"
        }

        if thread_list:
            for thread_id in thread_list:
                thread_context = self.get_thread_context(thread_id)
                if thread_context:
                    print(f"[*] Dumping registers for thread ID: 0x{thread_id:016x}")
                    for key, value in registers.items():
                        print(f"[**] {key}: 0x{getattr(thread_context, value):016x}")
                    print(f"[*] END DUMP")


    def print_event_code_descriptions(self):
        print(
            """[*] Event codes:
    0x1 - EXCEPTION_DEBUG_EVENT
    0x2 - CREATE_THREAD_DEBUG_EVENT
    0x3 - CREATE_PROCESS_DEBUG_EVENT
    0x4 - EXIT_THREAD_DEBUG_EVENT
    0x5 - EXIT_PROCESS_DEBUG_EVENT
    0x6 - LOAD_DLL_DEBUG_EVENT
    0x7 - UNLOAD_DLL_DEBUG_EVENT
    0x8 - OUTPUT_DEBUG_STRING_EVENT
    0x9 - RIP_EVENT
"""
        )
        