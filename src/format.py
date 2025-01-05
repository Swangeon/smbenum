from colorama import Fore


def print_header(message: str) -> None:
    print(Fore.MAGENTA +
          ("=" * 30) +
          Fore.GREEN +
          " " +
          message +
          " " +
          Fore.MAGENTA +
          ("=" * 30) +
          Fore.RESET)


def print_warning(message: str) -> None:
    print(f"{Fore.YELLOW}[~]{Fore.RESET} {message}")


def print_info(message: str) -> None:
    print(f"{Fore.GREEN}[+]{Fore.RESET} {message}")


def print_error(message: str) -> None:
    print(f"{Fore.RED}[-]{Fore.RESET} {message}")
