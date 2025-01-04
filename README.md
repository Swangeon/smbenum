# SMBEnum

[![GNU GPL3 License](https://img.shields.io/badge/License-GNU_GPL3-brightgreen)](https://www.gnu.org/licenses/gpl-3.0.en.html)
[![Release](https://img.shields.io/badge/Release-v0.1.0-blue)](https://github.com/Swangeon/smbenum/releases/tag/v0.1.0)

## Description

This tool is for enumerating basic information about an SMB Server.

## Installation

1. Install all necessary modules: `pip install -r requirements.txt`
2. Run via python: `python smbenum.py -i 192.168.1.1`

## Usage

`-i`/`--ip`     | **REQUIRED** | IP Address of the SMB Server.

`-n`/`--port`   | **OPTIONAL** | Port that the SMB Server runs on.

`-u`/`--user`   | **OPTIONAL** | Username to login to the SMB Server.

`-p`/`--passwd` | **OPTIONAL** | Password to login to the SMB Server.

## TODOs

- Add a basic testing suite.
- Refactor the code.
- Add ability to login via Kerboros if it is the only way to login to the SMB Server.
- Add enumeration of files within each share of the SMB Server.
- Add more information to the README like a GIF, Contributions Section, etc.
