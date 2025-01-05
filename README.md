# SMBEnum

[![Release](https://img.shields.io/badge/Release-v0.1.0-blue)](https://github.com/Swangeon/smbenum/releases/tag/v0.1.0)
[![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/Swangeon/smbenum/smb_testing.yml?label=SMB%20Testing)](https://github.com/Swangeon/smbenum/actions/workflows/smb_testing.yml)
[![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/Swangeon/smbenum/codeql.yml?label=CodeQL%20Security%20Testing)](https://github.com/Swangeon/smbenum/actions/workflows/codeql.yml)
[![GNU GPL3 License](https://img.shields.io/badge/License-GNU_GPL3-darkorange)](https://www.gnu.org/licenses/gpl-3.0.en.html)


## Description

This tool is for enumerating basic information about an SMB Server.

## Installation

1. Install all necessary modules: `pip install -e .`
2. Run via python: `python src/main.py -i 127.0.0.1`

## Usage

| Option          | Necessity    | Description                          | Example                                         |
|-----------------|--------------|--------------------------------------|-------------------------------------------------|
| `-i`/`--ip`     | **REQUIRED** | IP Address of the SMB Server.        | `python src/main.py -i 127.0.0.1`               |
| `-n`/`--port`   | **OPTIONAL** | Port that the SMB Server runs on.    | `python src/main.py -i 127.0.0.1 -n 139`        |
| `-u`/`--user`   | **OPTIONAL** | Username to login to the SMB Server. | `python src/main.py -i 127.0.0.1 -u admin`      |
| `-p`/`--passwd` | **OPTIONAL** | Password to login to the SMB Server. | `python src/main.py -i 127.0.0.1 -p p@ssW0Rd!!` |

## TODOs

- Extend a basic testing suite.
- Refactor the code.
- Add ability to specify a username and password list to brute force logins.
- Add ability to login via Kerboros if it is the only way to login to the SMB Server.
- Add enumeration of files within each share of the SMB Server.
- Add more information to the README like a GIF, Contributions Section, etc.
