import win32clipboard
import win32con

from abc import ABC, abstractmethod


class ClipboardAdapter(ABC):

    @abstractmethod
    def set_text(self, text: str):
        pass

    @abstractmethod
    def get_text(self):
        pass

    @abstractmethod
    def clear(self):
        pass


class WindowsClipboardAdapter(ClipboardAdapter):

    def set_text(self, text: str):

        win32clipboard.OpenClipboard()

        try:

            win32clipboard.EmptyClipboard()

            win32clipboard.SetClipboardData(
                win32con.CF_UNICODETEXT,
                text
            )

        finally:

            win32clipboard.CloseClipboard()

    def get_text(self):

        win32clipboard.OpenClipboard()

        try:

            if win32clipboard.IsClipboardFormatAvailable(
                win32con.CF_UNICODETEXT
            ):
                return win32clipboard.GetClipboardData(
                    win32con.CF_UNICODETEXT
                )

            return ""

        finally:

            win32clipboard.CloseClipboard()

    def clear(self):

        win32clipboard.OpenClipboard()

        try:

            win32clipboard.EmptyClipboard()

        finally:

            win32clipboard.CloseClipboard()