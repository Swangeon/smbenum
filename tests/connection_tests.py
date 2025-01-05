import unittest
import os
import sys
import warnings

from smbenum import SMBConn


class ConnectionTests(unittest.TestCase):
    def setUp(self):
        """
        Setup the test class.
        """
        warnings.filterwarnings("ignore", category=ResourceWarning)
        self._stdout = sys.stdout
        sys.stdout = open(os.devnull, 'w')

    def test_valid_connection(self):
        """
        Test that when their is a valid connection with a server that the connection
        process succeeds.
        """
        self.assertIsNotNone(SMBConn(ip="127.0.0.1"))

    def test_non_smb_server(self):
        """
        Test that when their is a non smb server that the connection process fails.
        """
        with self.assertRaises(Exception):
            SMBConn(ip="127.0.0.1", port=80)

    def test_invalid_ip(self):
        """
        Test that when their is a invalid ip that the connection process fails.
        """
        with self.assertRaises(Exception):
            SMBConn(ip="0.1.1.1")

    def test_invalid_port(self):
        """
        Test that when their is a invalid port that the connection process fails.
        """
        with self.assertRaises(Exception):
            SMBConn(ip="127.0.0.1", port=0)

    def tearDown(self):
        """
        Tear down the test class.
        """
        sys.stdout.close()
        sys.stdout = self._stdout


if __name__ == "__main__":
    unittest.main()
