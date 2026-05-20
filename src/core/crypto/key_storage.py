import time
from src.core.crypto.placeholder import secure_zero_bytes


cached_key = None
last_access = None

TIMEOUT = 3600


def store_key(key:bytes):
    global last_access, cached_key

    cached_key = bytearray(key)
    last_access = time.time()


def get_key():
    global last_access, cached_key

    if cached_key is None:
        return None

    if time.time() - last_access > TIMEOUT:
        clear_key()
        return None

    last_access = time.time()
    return bytes(cached_key)


def clear_key():
    global last_access, cached_key

    if cached_key is not None:
        secure_zero_bytes(cached_key)

        cached_key = None
        last_access = None
