from argparse import ArgumentParser, Namespace
from smbenum import SMBConn


def parse_args() -> Namespace:
    """
    Parse command line arguments.

    Returns:
        Namespace: Command line arguments.
    """
    parser = ArgumentParser(
        prog="smbenum",
        description="Program to enumerate an smb server for information that could be useful.",
        epilog="Author: Sean Brady",
        usage="python main.py -i 192.168.1.1",
    )
    parser.add_argument("-i", "--ip", type=str, required=True, help="Target IP Address")
    parser.add_argument("-n", "--port", type=int, default=445, help="SMB Server Port #")
    parser.add_argument("-u", "--user", type=str, default='', help="SMB Username")
    parser.add_argument("-p", "--passwd", type=str, default='', help="SMB Password")
    return parser.parse_args()


def main() -> None:
    """
    Main entry point for the application.
    """
    args = parse_args()
    smbconn = SMBConn(ip=args.ip, port=args.port, user=args.user, passwd=args.passwd)
    smbconn.login()
    smbconn.enumerate()


if __name__ == "__main__":
    main()
