import time
import threading
import ctypes

def secure_zero_bytes(data: bytearray):
    length = len(data)
    ptr = (ctypes.c_char * length).from_buffer(data)
    for i in range(length):
        ptr[i] = 0

class KeyStorage:
    def __init__(self, timeout: int = 3600):
        self._key = None
        self._last_access = None
        self._timeout = timeout
        self._active = True
        self._lock = threading.Lock()


    def store_key(self, key:bytes):

        with self._lock:
            self._key = bytearray(key)
            self._last_access = time.time()


    def get_key(self):
        with self._lock:

            if not self._active:
                return None

            if self._key is None:
                return None

            if time.time() - self._last_access > self._timeout:
                self.clear_key()
                return None

            self._last_access = time.time()
            return bytes(self._key)


    def clear_key(self):
        with self._lock:

            if self._key is not None:
                secure_zero_bytes(self._key)

                self._key = None
                self._last_access = None


    def set_active(self, active:bool):
        with self._lock:

            self._active = active
            if not active:
                self.clear_key()
