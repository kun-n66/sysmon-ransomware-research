"""Windows named-pipe client. Python standard library only; no pywin32 needed."""
import ctypes
from ctypes import wintypes
import os
import time


class PipeDisconnected(OSError):
    pass


class WindowsPipe:
    def __init__(self, name, connect_timeout=60):
        if os.name != "nt":
            raise OSError("Live collection requires Windows; tests/storage also run elsewhere.")
        prefix = "\\\\.\\pipe\\"
        if not name.startswith(prefix) or not name[len(prefix):] or "\\" in name[len(prefix):]:
            raise ValueError(r"Use a LOCAL pipe such as \\.\pipe\sysmon-log (not an SMB/remote pipe).")
        self.api = ctypes.WinDLL("kernel32", use_last_error=True)
        pointer = ctypes.c_void_p

        class OVERLAPPED(ctypes.Structure):
            _fields_ = [("Internal", ctypes.c_size_t), ("InternalHigh", ctypes.c_size_t),
                        ("Offset", wintypes.DWORD), ("OffsetHigh", wintypes.DWORD),
                        ("hEvent", wintypes.HANDLE)]

        self.overlapped_type = OVERLAPPED
        signatures = {
            "CreateFileW": ([wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, pointer,
                             wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE], wintypes.HANDLE),
            "CreateEventW": ([pointer, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR], wintypes.HANDLE),
            "ReadFile": ([wintypes.HANDLE, pointer, wintypes.DWORD, pointer, pointer], wintypes.BOOL),
            "WriteFile": ([wintypes.HANDLE, pointer, wintypes.DWORD, pointer, pointer], wintypes.BOOL),
            "WaitForSingleObject": ([wintypes.HANDLE, wintypes.DWORD], wintypes.DWORD),
            "GetOverlappedResult": ([wintypes.HANDLE, pointer, pointer, wintypes.BOOL], wintypes.BOOL),
            "CancelIoEx": ([wintypes.HANDLE, pointer], wintypes.BOOL),
            "CloseHandle": ([wintypes.HANDLE], wintypes.BOOL),
        }
        for function, (arguments, result) in signatures.items():
            getattr(self.api, function).argtypes = arguments
            getattr(self.api, function).restype = result
        self.handle = None
        deadline = time.monotonic() + connect_timeout
        while True:
            handle = self.api.CreateFileW(name, 0xC0000000, 0, None, 3, 0x40000000, None)
            if handle != ctypes.c_void_p(-1).value:
                self.handle = handle
                break
            error = ctypes.get_last_error()
            if error not in (2, 231):
                raise ctypes.WinError(error)
            if time.monotonic() >= deadline:
                raise TimeoutError("Pipe unavailable: check VM power and serial pipe server settings.")
            time.sleep(0.05)

    def _io(self, payload, timeout, writing):
        api = self.api
        buffer = ctypes.create_string_buffer(payload) if writing else ctypes.create_string_buffer(payload)
        size = len(payload) if writing else payload
        overlap = self.overlapped_type()
        overlap.hEvent = api.CreateEventW(None, True, False, None)
        if not overlap.hEvent:
            raise ctypes.WinError(ctypes.get_last_error())
        count = wintypes.DWORD()
        timed_out = False
        try:
            function = api.WriteFile if writing else api.ReadFile
            ok = function(self.handle, buffer, size, None, ctypes.byref(overlap))
            error = 0 if ok else ctypes.get_last_error()
            if not ok and error != 997:  # ERROR_IO_PENDING
                if error in (109, 232, 233):
                    raise PipeDisconnected("VMware pipe disconnected.")
                raise ctypes.WinError(error)
            if not ok:
                wait = api.WaitForSingleObject(overlap.hEvent, max(1, int(timeout * 1000)))
                if wait == 258:  # WAIT_TIMEOUT; finish cancellation before releasing buffers.
                    timed_out = True
                    api.CancelIoEx(self.handle, ctypes.byref(overlap))
                elif wait != 0:
                    api.CancelIoEx(self.handle, ctypes.byref(overlap))
                    api.GetOverlappedResult(self.handle, ctypes.byref(overlap), ctypes.byref(count), True)
                    raise OSError("WaitForSingleObject failed.")
            ok = api.GetOverlappedResult(self.handle, ctypes.byref(overlap), ctypes.byref(count), True)
            if not ok:
                error = ctypes.get_last_error()
                if timed_out and error == 995:
                    if writing:
                        raise TimeoutError("Timed out writing collector command.")
                    return b""
                if error in (109, 232, 233):
                    raise PipeDisconnected("VMware pipe disconnected.")
                raise ctypes.WinError(error)
            if not writing and count.value == 0:
                raise PipeDisconnected("VMware closed the pipe.")
            return count.value if writing else buffer.raw[:count.value]
        finally:
            api.CloseHandle(overlap.hEvent)

    def read(self, size=65536, timeout=0.1):
        return self._io(size, timeout, False)

    def write(self, data, timeout=5):
        offset = 0
        deadline = time.monotonic() + timeout
        while offset < len(data):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Timed out writing collector command.")
            count = self._io(data[offset:], remaining, True)
            if not count:
                raise PipeDisconnected("Zero-length pipe write.")
            offset += count

    def close(self):
        if self.handle is not None:
            self.api.CloseHandle(self.handle)
            self.handle = None
