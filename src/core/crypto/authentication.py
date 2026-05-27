import time

user_logged_in = None

failed_attempts = 0
last_login_time = None
is_authenticated = False


def authenticate(key_manager, password, stored_hash, salt):
    global failed_attempts
    global last_login_time
    global is_authenticated

    try:

        success = key_manager.unlock(
            password,
            stored_hash,
            salt
        )

        if not success:

            handle_failed_attempt()

            return False

    except:

        handle_failed_attempt()

        return False

    failed_attempts = 0

    is_authenticated = True

    last_login_time = time.time()

    if user_logged_in:
        user_logged_in()

    return True


def logout(key_manager):

    global is_authenticated
    global failed_attempts
    global last_login_time

    key_manager.lock()

    is_authenticated = False

    failed_attempts = 0

    last_login_time = None


def shutdown(key_manager):

    global is_authenticated
    global failed_attempts
    global last_login_time

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

def session_expired(timeout_seconds):

    global last_login_time

    if last_login_time is None:
        return False

    return (time.time() - last_login_time) > timeout_seconds