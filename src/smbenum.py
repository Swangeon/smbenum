"""
Author: Sean Brady
Description: Program to enumerate an smb server for information that could be useful.
"""

from impacket.smbconnection import SMBConnection, SessionError
from impacket.dcerpc.v5.srvs import SHARE_INFO_1
from prettytable import PrettyTable

import format


STATUS_LOGON_FAILURE: int = 0xc000006d
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
        self.shares: list[list[str]] = None
        self.machine_info: list[str, int] = None
        self.session = self.connect()
        if not self.session:
            raise Exception("Failed to connect to SMB server")

    def __del__(self) -> None:
        """
        Disconnects the SMB session before the object is deleted.
        """
        if self.session:
            try:
                self.session.close()
            except Exception as e:
                format.print_error(f"Error encountered during disconnection: {e}")

    def connect(self) -> SMBConnection:
        """
        Connects to the SMB server and logs in to create a session.
        """
        try:
            return SMBConnection(
                remoteName=self.ip,
                remoteHost=self.ip,
                sess_port=self.port,
                timeout=30
            )
        except Exception as e:
            format.print_error(f"Error encountered during connection: {e}")

    def login(self) -> bool:
        """
        Login to the SMB server using default usernames.

        Returns:
            bool: True if login was successful, False otherwise.
        """
        format.print_header("Logging into System")
        if self.user:
            return self._specific_login()
        else:
            return self._brute_force()

    def _specific_login(self) -> bool:
        """
        Login to the SMB server using the user specified username and password.

        Returns:
            bool: Returns True if login was successful, False otherwise.
        """
        try:
            format.print_warning(f"Using {self.user} | {self.passwd}")
            self.session.login(user=self.user, password=self.passwd)
            format.print_info(f"Logged in with Credentials: {self.user} | {self.passwd}")
            return True
        except SessionError as e:
            if e.getErrorCode() == STATUS_LOGON_FAILURE:
                format.print_error(f"Invalid Login for {self.user} | {self.passwd}")
        except Exception as e:
            format.print_error(f"Error encountered during login: {e}")
        return False

    def _brute_force(self) -> bool:
        """
        Login to the SMB server using default usernames and blank password.

        Returns:
            bool: Returns True if login was successful, False otherwise.
        """
        for username in DEFAULT_SMB_USERNAMES:
            try:
                format.print_warning(f"Using {username} | ''")
                self.session.login(user=username, password=self.passwd)
                if self.session.getCredentials():
                    format.print_info(f"Logged in with Credentials: {username} | {self.passwd}")
                    self.user = username
                    return True
            except SessionError as e:
                if e.getErrorCode() == STATUS_LOGON_FAILURE:
                    format.print_error(f"Invalid Login for {username} | {self.passwd}")
            except Exception as e:
                format.print_error(f"Error encountered during login: {e}")
        return False

    def enumerate(self) -> None:
        """
        Enumerate the server for information and output it to the user.
        """
        self._output_basic_info()
        self._output_machine_info()
        self._output_shares()

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
            list[str, int]: List containing server OS, build, major, minor,
                            max read size, and max write size.
        """
        server_info: list = []
        io_capabilities: dict = self.session.getIOCapabilities()
        server_info.append(self.session.getServerOS())
        server_info.append(self.session.getServerOSBuild())
        server_info.append(self.session.getServerOSMajor())
        server_info.append(self.session.getServerOSMinor())
        server_info.append(io_capabilities["MaxReadSize"])
        server_info.append(io_capabilities["MaxWriteSize"])
        return server_info

    def _output_basic_info(self) -> None:
        """
        Output basic information for starting the application.
        """
        format.print_header("Target Information")
        print(f"Target ........... {self.ip}")
        print(f"Port ............. {self.port}")
        print(f"Username ......... {self.user}")
        print(f"Password ......... {self.passwd}")

    def _output_machine_info(self) -> None:
        """
        Outputs machine information in a much more user friendly way.
        """
        format.print_header("Machine Information")
        format.print_info("Retrieving machine information...")
        self.machine_info = self.get_machine_info()
        print(f"OS ............... {self.machine_info[0]}")
        print(f"Build ............ {self.machine_info[1]}")
        print(f"Major/Minor ...... {self.machine_info[2]}.{self.machine_info[3]}")
        print(f"Max Read Size .... {self.machine_info[4]} Bytes")
        print(f"Max Write Size ... {self.machine_info[5]} Bytes")

    def _output_shares(self) -> None:
        """
        Outputs share information in a much more user friendly way.
        """
        format.print_header("SMB Share Information")
        format.print_info("Retrieving share information...")
        self.shares = self.get_shares()
        table = PrettyTable(["Name", "Type", "Remarks"])
        table.add_rows(self.shares)
        print(table)
