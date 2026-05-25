import time
from src.core.key_manager import KeyManager


user_logged_in = None

failed_attempts = 0
last_login_time = None
is_authenticated = False

key_manager = KeyManager()


def authenticate(password, stored_hash, salt):
    global failed_attempts, last_login_time, is_authenticated

    if not key_manager.unlock(password, stored_hash, salt):
        handle_failed_attempt()
        return False

    failed_attempts = 0
    is_authenticated = True
    last_login_time = time.time()

    if user_logged_in:
        user_logged_in()
    return True


def logout():
    global is_authenticated, failed_attempts, last_login_time

    key_manager.lock()

    is_authenticated = False
    failed_attempts = 0
    last_login_time = None


def shutdown():
    global is_authenticated, failed_attempts, last_login_time
    key_manager.lock()

    is_authenticated = False
    failed_attempts = 0
    last_login_time = None


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