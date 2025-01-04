"""
Author: Sean Brady
Description: Program to enumerate an smb server for information that could be useful.
"""

from argparse import ArgumentParser, Namespace
from colorama import Fore
from impacket.smbconnection import SMBConnection
from impacket.dcerpc.v5.srvs import SHARE_INFO_1
from prettytable import PrettyTable


DEFAULT_SMB_USERNAMES: list[str] = [
    "administrator",
    "guest",
    "krbtgt",
    "domain",
    "admins",
    "root",
    "bin",
    ""
]
SMB_SHARE_TYPES: dict[int, str] = {
    0: "DISK",
    1: "PRINTER",
    2: "DEVICE",
    3: "IPC",
    1073741824: "TEMP",
    2147483651: "SPECIAL",
    4294967295: "UNKNOWN"
}


class SMBConn():
    def __init__(self,
                 ip: str,
                 port: int = 445,
                 user: str = '',
                 passwd: str = ''):
        """
        Constructor for the SMBConn class.

        Args:
            ip (str): IP address of the SMB server.
            port (int, optional): Port to connect to the server. Defaults to 445.
            user (str, optional): Username to login with. Defaults to ''.
            passwd (str, optional): Password to login with. Defaults to ''.
        """
        self.ip = ip
        self.port = port
        self.user = user
        self.passwd = passwd
        self.connect()

    def __del__(self) -> None:
        """
        Disconnects the SMB session before the object is deleted.
        """
        try:
            self.session.close()
        except Exception as e:
            print(f"[-] Error encountered during disconnection: {e}")

    def connect(self) -> None:
        """
        Connects to the SMB server and logs in to create a session.
        """
        try:
            self.session = SMBConnection(
                remoteName=self.ip,
                remoteHost=self.ip,
                sess_port=self.port
            )
            if self.user or self.passwd:
                self.session.login(user=self.user, password=self.passwd)
            else:
                self.login()
        except Exception as e:
            print(f"[-] Error encountered during connection: {e}")

    def login(self) -> None:
        """
        Login to the SMB server using default usernames.
        """
        print(Fore.MAGENTA + ("=" * 30) + Fore.RESET + Fore.GREEN + " Logging into System " + Fore.RESET + Fore.MAGENTA + ("=" * 30) + Fore.RESET)
        for username in DEFAULT_SMB_USERNAMES:
            print(f"{Fore.YELLOW}[~]{Fore.RESET} Using {username}|''")
            self.session.login(user=username, password=self.passwd)
            if self.session.getCredentials():
                print(f"{Fore.GREEN}[+]{Fore.RESET} Got session with {username}")
                self.user = username
                break

    def get_shares(self) -> list[list[str]]:
        """
        Enumerate and retrieve data about all shares on the server.

        Returns:
            list[list[str]]: List of lists containing share name, share type, and share remark.
        """
        raw_share_data: list[SHARE_INFO_1] = self.session.listShares()
        share_data: list[list[str]] = []
        for share in raw_share_data:
            share_name: str = share["shi1_netname"][:-1]
            share_type: str = SMB_SHARE_TYPES[int(share["shi1_type"])]
            if share["shi1_remark"]:
                share_remark: str = share["shi1_remark"][:-1]
            else:
                share_remark: str = ''
            share_data.append([share_name, share_type, share_remark])
        return share_data

    def get_machine_info(self) -> list[str, int]:
        """
        Retrieve machine information from the server.

        Returns:
            list[str, int]: List containing server OS, build, major, minor, max read size, and max write size.
        """
        server_info: list = []
        server_os: str = self.session.getServerOS()
        server_build: str = self.session.getServerOSBuild()
        server_build_major: str = self.session.getServerOSMajor()
        server_build_minor: str = self.session.getServerOSMinor()
        io_capabilities: str = self.session.getIOCapabilities()
        max_read_size: str = io_capabilities["MaxReadSize"]
        max_write_size: str = io_capabilities["MaxWriteSize"]
        server_info.append(server_os)
        server_info.append(server_build)
        server_info.append(server_build_major)
        server_info.append(server_build_minor)
        server_info.append(max_read_size)
        server_info.append(max_write_size)
        return server_info


    def output_basic_info(self) -> None:
        """
        Output basic information for starting the application.
        """
        print(Fore.MAGENTA + ("=" * 30) + Fore.GREEN + " Target Information " + Fore.MAGENTA + ("=" * 30) + Fore.RESET)
        print(f"Target ........... {self.ip}")
        print(f"Port ............. {self.port}")
        print(f"Username ......... {self.user}")
        print(f"Password ......... {self.passwd}")

    def output_shares(self) -> None:
        """
        Outputs share information in a much more user friendly way.
        """
        shares: list[list[str]] = self.get_shares()
        print(Fore.MAGENTA + ("=" * 30) + Fore.GREEN + " SMB Share Information " + Fore.MAGENTA + ("=" * 30) + Fore.RESET)
        table = PrettyTable(["Name", "Type", "Remarks"])
        table.add_rows(shares)
        print(table)

    def output_machine_info(self) -> None:
        """
        Outputs machine information in a much more user friendly way.
        """
        machine_info: list[str, int] = self.get_machine_info()
        print(Fore.MAGENTA + ("=" * 30) + Fore.GREEN + " Machine Information " + Fore.MAGENTA + ("=" * 30) + Fore.RESET)
        print(f"OS ............... {machine_info[0]}")
        print(f"Build ............ {machine_info[1]}")
        print(f"Major/Minor ...... {machine_info[2]}.{machine_info[3]}")
        print(f"Max Read Size .... {machine_info[4]} Bytes")
        print(f"Max Write Size ... {machine_info[5]} Bytes")


def parse_args() -> Namespace:
    """
    Parse command line arguments.

    Returns:
        Namespace: Command line arguments.
    """
    parser = ArgumentParser()
    parser.add_argument("-i", "--ip", type=str, required=True)
    parser.add_argument("-n", "--port", type=int, default=445)
    parser.add_argument("-u", "--user", type=str, default='')
    parser.add_argument("-p", "--passwd", type=str, default='')
    return parser.parse_args()


def main() -> None:
    """
    Main entry point for the application.
    """
    args = parse_args()
    smbconn = SMBConn(ip=args.ip, port=args.port, user=args.user, passwd=args.passwd)
    smbconn.output_basic_info()
    smbconn.output_machine_info()
    smbconn.output_shares()


if __name__ == "__main__":
    main()
