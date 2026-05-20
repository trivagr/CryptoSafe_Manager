import time
from src.core.crypto import key_derivation
from src.core.key_manager import KeyManager


failed_attempts = 0
last_login_time = None
is_authenticated = False

key_manager = KeyManager()


def authenticate(password, stored_hash, salt):
    global failed_attempts, last_login_time, is_authenticated

    if not key_derivation.password_verify(password, stored_hash):
        handle_failed_attempt()
        return False

    encryption_key = key_derivation.key_derive(password, salt)

    key_manager.unlock_key(encryption_key)

    failed_attempts = 0
    is_authenticated = True
    last_login_time = time.time()

    print("UserLoggedIn")
    return True


def logout():
    global is_authenticated, failed_attempts

    key_manager.lock_key()

    is_authenticated = False
    failed_attempts = 0

    print("UserLoggedOut")


def handle_failed_attempt():
    global failed_attempts

    failed_attempts += 1

    if failed_attempts <= 2:
        delay = 1
    elif failed_attempts <= 4:
        delay = 5
    else:
        delay = 30

    time.sleep(delay)


def update_activity():
    global last_login_time

    last_login_time = time.time()