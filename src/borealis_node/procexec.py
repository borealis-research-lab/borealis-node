"""Bounded, isolated execution of one agent process.

Windows: the process is created SUSPENDED, assigned to a Job Object with
KILL_ON_JOB_CLOSE (breakaway not allowed), and only then resumed via the primary thread
handle returned by CreateProcessW. If assignment or resume fails, the still-suspended
process is terminated before running any code (fail closed). Closing the job kills the
agent and every descendant. Only the stdin (NUL), stdout and stderr handles are inherited.

POSIX: the agent runs in a new session/process group, killed as a group on timeout.
Limitation (documented): a child that deliberately leaves the group can survive.

No shell is ever used; arguments are passed as a list.
"""

from __future__ import annotations

import os
import subprocess
import sys
import threading
import time
from dataclasses import dataclass

STDOUT_LIMIT = 10 * 1024 * 1024
STDERR_LIMIT = 64 * 1024

# Test hook: set to True to make Job Object assignment fail (verifies fail-closed behaviour).
FAIL_JOB_ASSIGNMENT = False


@dataclass
class Result:
    exit_code: int | None
    stdout: bytes
    stderr: bytes
    timed_out: bool = False
    killed: bool = False
    output_too_large: bool = False
    launch_error: str | None = None
    started: float = 0.0
    finished: float = 0.0


class _Collector:
    """Reads a stream on a background thread, keeping at most `limit` bytes."""

    def __init__(self, read, limit: int, on_overflow) -> None:
        self.read, self.limit, self.on_overflow = read, limit, on_overflow
        self.data = bytearray()
        self.overflow = False
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def _run(self) -> None:
        while True:
            try:
                chunk = self.read(65536)
            except OSError:
                return
            if not chunk:
                return
            room = self.limit - len(self.data)
            if len(chunk) > room:
                self.data.extend(chunk[:max(room, 0)])
                if not self.overflow:
                    self.overflow = True
                    self.on_overflow()
            else:
                self.data.extend(chunk)


def run(executable: str, args: list[str], timeout: float, cwd: str | None = None) -> Result:
    if os.name == "nt":
        return _run_windows(executable, args, timeout, cwd)
    return _run_posix(executable, args, timeout, cwd)


# =========================================================================================
# POSIX
# =========================================================================================


def _run_posix(executable: str, args: list[str], timeout: float, cwd: str | None) -> Result:
    import signal

    started = time.time()
    try:
        proc = subprocess.Popen([executable, *args], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, cwd=cwd, shell=False, start_new_session=True,
                                close_fds=True)
    except OSError:
        return Result(None, b"", b"", launch_error="spawn-failed", started=started, finished=time.time())
    state = {"killed": False}

    def kill_group() -> None:
        state["killed"] = True
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except OSError:
            pass

    out = _Collector(proc.stdout.read, STDOUT_LIMIT, kill_group)
    err = _Collector(proc.stderr.read, STDERR_LIMIT, lambda: None)
    timed_out = False
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        kill_group()
        proc.wait()
    kill_group_after = state["killed"]
    try:  # reap any group members still running after the agent exited
        os.killpg(proc.pid, signal.SIGKILL)
    except OSError:
        pass
    out.thread.join(5)
    err.thread.join(5)
    return Result(None if (timed_out or kill_group_after) else proc.returncode, bytes(out.data), bytes(err.data),
                  timed_out=timed_out, killed=timed_out or kill_group_after, output_too_large=out.overflow,
                  started=started, finished=time.time())


# =========================================================================================
# Windows
# =========================================================================================


def _run_windows(executable: str, args: list[str], timeout: float, cwd: str | None) -> Result:
    import ctypes
    import msvcrt
    from ctypes import wintypes

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    HANDLE, DWORD, BOOL = wintypes.HANDLE, wintypes.DWORD, wintypes.BOOL

    class SECURITY_ATTRIBUTES(ctypes.Structure):
        _fields_ = [("nLength", DWORD), ("lpSecurityDescriptor", ctypes.c_void_p), ("bInheritHandle", BOOL)]

    class STARTUPINFOW(ctypes.Structure):
        _fields_ = [("cb", DWORD), ("lpReserved", wintypes.LPWSTR), ("lpDesktop", wintypes.LPWSTR),
                    ("lpTitle", wintypes.LPWSTR), ("dwX", DWORD), ("dwY", DWORD), ("dwXSize", DWORD),
                    ("dwYSize", DWORD), ("dwXCountChars", DWORD), ("dwYCountChars", DWORD),
                    ("dwFillAttribute", DWORD), ("dwFlags", DWORD), ("wShowWindow", wintypes.WORD),
                    ("cbReserved2", wintypes.WORD), ("lpReserved2", ctypes.c_void_p), ("hStdInput", HANDLE),
                    ("hStdOutput", HANDLE), ("hStdError", HANDLE)]

    class STARTUPINFOEXW(ctypes.Structure):
        _fields_ = [("StartupInfo", STARTUPINFOW), ("lpAttributeList", ctypes.c_void_p)]

    class PROCESS_INFORMATION(ctypes.Structure):
        _fields_ = [("hProcess", HANDLE), ("hThread", HANDLE), ("dwProcessId", DWORD), ("dwThreadId", DWORD)]

    class IO_COUNTERS(ctypes.Structure):
        _fields_ = [(n, ctypes.c_ulonglong) for n in ("r", "w", "o", "rb", "wb", "ob")]

    class BASIC_LIMIT(ctypes.Structure):
        _fields_ = [("PerProcessUserTimeLimit", ctypes.c_longlong), ("PerJobUserTimeLimit", ctypes.c_longlong),
                    ("LimitFlags", DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                    ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", DWORD),
                    ("Affinity", ctypes.c_size_t), ("PriorityClass", DWORD), ("SchedulingClass", DWORD)]

    class EXTENDED_LIMIT(ctypes.Structure):
        _fields_ = [("BasicLimitInformation", BASIC_LIMIT), ("IoInfo", IO_COUNTERS),
                    ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
                    ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t)]

    def fn(name, restype, *argtypes):
        f = getattr(k32, name)
        f.restype, f.argtypes = restype, list(argtypes)
        return f

    CreatePipe = fn("CreatePipe", BOOL, ctypes.POINTER(HANDLE), ctypes.POINTER(HANDLE),
                    ctypes.POINTER(SECURITY_ATTRIBUTES), DWORD)
    SetHandleInformation = fn("SetHandleInformation", BOOL, HANDLE, DWORD, DWORD)
    CreateFileW = fn("CreateFileW", HANDLE, wintypes.LPCWSTR, DWORD, DWORD, ctypes.POINTER(SECURITY_ATTRIBUTES),
                     DWORD, DWORD, HANDLE)
    InitAttrList = fn("InitializeProcThreadAttributeList", BOOL, ctypes.c_void_p, DWORD, DWORD,
                      ctypes.POINTER(ctypes.c_size_t))
    UpdateAttr = fn("UpdateProcThreadAttribute", BOOL, ctypes.c_void_p, DWORD, ctypes.c_size_t, ctypes.c_void_p,
                    ctypes.c_size_t, ctypes.c_void_p, ctypes.c_void_p)
    DeleteAttrList = fn("DeleteProcThreadAttributeList", None, ctypes.c_void_p)
    CreateProcessW = fn("CreateProcessW", BOOL, wintypes.LPCWSTR, wintypes.LPWSTR, ctypes.c_void_p, ctypes.c_void_p,
                        BOOL, DWORD, ctypes.c_void_p, wintypes.LPCWSTR, ctypes.POINTER(STARTUPINFOEXW),
                        ctypes.POINTER(PROCESS_INFORMATION))
    CreateJobObjectW = fn("CreateJobObjectW", HANDLE, ctypes.c_void_p, wintypes.LPCWSTR)
    SetInfoJob = fn("SetInformationJobObject", BOOL, HANDLE, ctypes.c_int, ctypes.c_void_p, DWORD)
    AssignProcessToJobObject = fn("AssignProcessToJobObject", BOOL, HANDLE, HANDLE)
    ResumeThread = fn("ResumeThread", DWORD, HANDLE)
    TerminateProcess = fn("TerminateProcess", BOOL, HANDLE, ctypes.c_uint)
    TerminateJobObject = fn("TerminateJobObject", BOOL, HANDLE, ctypes.c_uint)
    WaitForSingleObject = fn("WaitForSingleObject", DWORD, HANDLE, DWORD)
    GetExitCodeProcess = fn("GetExitCodeProcess", BOOL, HANDLE, ctypes.POINTER(DWORD))
    CloseHandle = fn("CloseHandle", BOOL, HANDLE)

    started = time.time()
    inherit = SECURITY_ATTRIBUTES(ctypes.sizeof(SECURITY_ATTRIBUTES), None, True)
    handles_to_close: list = []

    def pipe():
        r, w = HANDLE(), HANDLE()
        if not CreatePipe(ctypes.byref(r), ctypes.byref(w), ctypes.byref(inherit), 0):
            raise OSError("CreatePipe failed")
        SetHandleInformation(r, 1, 0)  # read end stays in this process only
        return r, w

    try:
        out_r, out_w = pipe()
        err_r, err_w = pipe()
    except OSError:
        return Result(None, b"", b"", launch_error="spawn-failed", started=started, finished=time.time())
    nul = CreateFileW("NUL", 0x80000000, 3, ctypes.byref(inherit), 3, 0, None)

    def fail(code: str) -> Result:
        CloseHandle(out_r)  # read ends are only handed to readers on success
        CloseHandle(err_r)
        return Result(None, b"", b"", launch_error=code, started=started, finished=time.time())

    handles_to_close += [out_w, err_w, nul]

    # Only these three handles may be inherited by the agent.
    inheritable = (HANDLE * 3)(nul, out_w, err_w)
    size = ctypes.c_size_t(0)
    InitAttrList(None, 1, 0, ctypes.byref(size))
    attr_buf = ctypes.create_string_buffer(size.value)
    si = STARTUPINFOEXW()
    si.StartupInfo.cb = ctypes.sizeof(STARTUPINFOEXW)
    si.StartupInfo.dwFlags = 0x100  # STARTF_USESTDHANDLES
    si.StartupInfo.hStdInput, si.StartupInfo.hStdOutput, si.StartupInfo.hStdError = nul, out_w, err_w
    pi = PROCESS_INFORMATION()
    job = None
    try:
        if not InitAttrList(attr_buf, 1, 0, ctypes.byref(size)) or not UpdateAttr(
                attr_buf, 0, 0x00020002, inheritable, ctypes.sizeof(inheritable), None, None):
            return fail("spawn-failed")
        si.lpAttributeList = ctypes.cast(attr_buf, ctypes.c_void_p)
        cmdline = ctypes.create_unicode_buffer(subprocess.list2cmdline([executable, *args]))
        flags = 0x00000004 | 0x00000200 | 0x08000000 | 0x00080000  # SUSPENDED, NEW_PROCESS_GROUP, NO_WINDOW, EXT_STARTUPINFO
        if not CreateProcessW(executable, cmdline, None, None, True, flags, None, cwd, ctypes.byref(si), ctypes.byref(pi)):
            return fail("spawn-failed")
        handles_to_close += [pi.hThread]

        # --- isolation: job assignment before the process runs any code -----------------
        job = CreateJobObjectW(None, None)
        limits = EXTENDED_LIMIT()
        limits.BasicLimitInformation.LimitFlags = 0x2000  # KILL_ON_JOB_CLOSE (no BREAKAWAY_OK)
        isolated = bool(job) and SetInfoJob(job, 9, ctypes.byref(limits), ctypes.sizeof(limits)) \
            and not FAIL_JOB_ASSIGNMENT and AssignProcessToJobObject(job, pi.hProcess)
        if not isolated or ResumeThread(pi.hThread) == 0xFFFFFFFF:
            TerminateProcess(pi.hProcess, 1)  # never ran: still suspended (or contained by the job)
            WaitForSingleObject(pi.hProcess, 5000)
            CloseHandle(pi.hProcess)
            if job:
                CloseHandle(job)
            return fail("isolation-failed")
    finally:
        DeleteAttrList(attr_buf) if si.lpAttributeList else None
        for h in handles_to_close:  # parent no longer needs the child's ends
            CloseHandle(h)

    state = {"killed": False}

    def kill_tree() -> None:
        state["killed"] = True
        TerminateJobObject(job, 1)

    out_fd = msvcrt.open_osfhandle(out_r.value, os.O_RDONLY)
    err_fd = msvcrt.open_osfhandle(err_r.value, os.O_RDONLY)
    out = _Collector(lambda n: os.read(out_fd, n), STDOUT_LIMIT, kill_tree)
    err = _Collector(lambda n: os.read(err_fd, n), STDERR_LIMIT, lambda: None)
    timed_out = WaitForSingleObject(pi.hProcess, int(timeout * 1000)) == 0x102  # WAIT_TIMEOUT
    if timed_out:
        kill_tree()
        WaitForSingleObject(pi.hProcess, 10000)
    code = DWORD()
    GetExitCodeProcess(pi.hProcess, ctypes.byref(code))
    CloseHandle(job)  # KILL_ON_JOB_CLOSE: any descendants still running are terminated
    out.thread.join(5)
    err.thread.join(5)
    os.close(out_fd)
    os.close(err_fd)
    CloseHandle(pi.hProcess)
    killed = state["killed"]
    return Result(None if killed else code.value, bytes(out.data), bytes(err.data), timed_out=timed_out,
                  killed=killed, output_too_large=out.overflow, started=started, finished=time.time())
