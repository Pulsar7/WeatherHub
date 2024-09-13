import os
import sys
import pytz
from datetime import datetime
from colorama import init, Fore, Style
from rich.console import Console
#
from .constants import *


init(autoreset=True)


class Logger:

    """Simple not-thread-safe CLI-logger."""

    def __init__(self, label:str, timezone:str="UTC") -> None:
        self._label:str|None = None
        self._timezone:str|None = None

        #
        self.label = label
        self.timezone = timezone
        self._current_progress:bool = False

    @property
    def label(self) -> str:
        """Get label of current logger."""
        return self._label

    @label.setter
    def label(self, new_label:str) -> None:
        if not isinstance(new_label, str):
            raise TypeError("The label has to be a string.")
        if len(new_label) == 0:
            raise ValueError("The label can't be empty.")
        self._label = new_label

    @property
    def timezone(self) -> str:
        """Get used timezone as a string."""
        return self._timezone

    @timezone.setter
    def timezone(self, new_timezone:str) -> None:
        if not isinstance(new_timezone, str):
            raise TypeError("The timezone has to be a string.")
        if len(new_timezone) == 0:
            raise ValueError("The timezone can't be empty.")
        self._timezone = new_timezone

    @property
    def string_repr(self) -> str:
        """Get current-logger string-representation."""
        return Fore.LIGHTBLACK_EX+"["+Fore.LIGHTBLUE_EX+self.get_current_time()+Fore.LIGHTBLACK_EX+"] "+Fore.LIGHTBLACK_EX+"("+Fore.WHITE+self.label+Fore.LIGHTBLACK_EX+")"+Style.RESET_ALL

    def get_current_time(self) -> str:
        n = datetime.now(pytz.timezone(self.timezone))
        return f"{n.hour}:{n.minute}:{n.second}"


    def info(self, text:str, progress:bool=False) -> None:
        """Printout info-text to CLI."""

        if self._current_progress:
            self.ok()

        if len(text) == 0:
            return

        text = f"{Fore.LIGHTYELLOW_EX}INFO{Style.RESET_ALL}:{Fore.WHITE} {text}"

        if progress:
            sys.stdout.write(f"\r{self.string_repr} {text}...")
            sys.stdout.flush()
            self._current_progress = True
            return

        print(f"{self.string_repr} {text}")

    def ok(self, text:str="O.K.") -> None:
        print(Fore.LIGHTGREEN_EX+text+Style.RESET_ALL)
        self._current_progress = False

    def warning(self, text:str) -> None:
        if self._current_progress:
            self.failed()

        print(f"{self.string_repr} {Fore.YELLOW}WARNING{Fore.RESET}: {Fore.LIGHTYELLOW_EX}{text}{Style.RESET_ALL}")

    def error(self, text:str) -> None:
        if self._current_progress:
            self.failed()

        print(f"{self.string_repr} {Fore.RED}ERROR{Fore.RESET}: {Fore.LIGHTRED_EX}{text}{Style.RESET_ALL}")

    def failed(self, text:str="ERROR") -> None:
        print(Fore.LIGHTRED_EX+text+Style.RESET_ALL)
        self._current_progress = False
