# LazarusWakeUp

A Python-Based Tool for Reconnaissance and State Management of AD Principals.

<p align="center">
  <img width="400" height="300" src="/Pictures/logo.png"><br /><br />
  <!-- <img alt="GitHub License" src="https://img.shields.io/github/license/nickvourd/LazarusWakeUp?style=social&logo=GitHub&logoColor=purple">
  <img alt="GitHub Repo stars" src="https://img.shields.io/github/stars/nickvourd/LazarusWakeUp?logoColor=yellow"><br />
  <img alt="GitHub forks" src="https://img.shields.io/github/forks/nickvourd/LazarusWakeUp?logoColor=red">
  <img alt="GitHub watchers" src="https://img.shields.io/github/watchers/nickvourd/LazarusWakeUp?logoColor=blue">
  <img alt="GitHub contributors" src="https://img.shields.io/github/contributors/nickvourd/LazarusWakeUp?style=social&logo=GitHub&logoColor=green"> -->
</p>

## Description

LazarusWakeUp is a Python-based tool for enumerating and managing disabled Active Directory principals. Based on this research.

![Static Badge](https://img.shields.io/badge/Python-3.x-green?style=flat&logoSize=auto)
![Static Badge](https://img.shields.io/badge/Poetry-blue?style=flat&logoSize=auto)
![Static Badge](https://img.shields.io/badge/Version-1.0%20-red)

> If you find any bugs, don’t hesitate to [report them](https://github.com/nickvourd/LazarusWakeUp/issues). Your feedback is valuable in improving the quality of this project!

## Disclaimer

The authors and contributors of this project are not liable for any illegal use of the tool. It is intended for educational purposes only. Users are responsible for ensuring lawful usage.

## Table of Contents

- [LazarusWakeUp](#lazaruswakeup)
  - [Description](#description)
  - [Disclaimer](#disclaimer)
  - [Table of Contents](#table-of-contents)
  - [Acknowledgement](#acknowledgement)
  - [Installation](#installation)
  - [Usage](#usage)
  - [References](#references)

## Acknowledgement

Special thanks to my brother [@kavasilo](https://x.com/kavasilo), who provided invaluable assistance during the development proceess of this tool.

LazarusWakeUp was created with :heart: by [@nickvourd](https://x.com/nickvourd).

## Installation

⚠️ Please ensure that Poetry is installed on your system.

1) Clone the repository by executing the following command:

```
git clone https://github.com/nickvourd/LazarusWakeUp.git
```

2) Once the repository is cloned, navigate into the LazarusWakeUp directory:

```
cd LazarusWakeUp
```

3) Install dependencies with Poetry:

```
poetry install
```

4) Verify installation:

```
poetry run lazarus-wakeup --help
```

## Usage

```
LazarusWakeUp - Find, enable/disable, and analyze disabled AD principals

options:
  -h, --help            show this help message and exit
  -a, --action {enable,disable,find,find-all}
                        Action to operate on disabled accounts
  --use-ldaps           Use LDAPS instead of LDAP
  --use-schannel        Use LDAP Schannel (TLS) for certificate-based authentication
  -v, --verbose         verbosity level (-v for verbose, -vv for debug)
  --force               Skip confirmation prompts (for batch operations)
  --port PORT           Custom LDAP port (default: 389 or 636 for LDAPS)

authentication & connection:
  --dc-ip ip address    IP Address of the domain controller or KDC (Key Distribution Center) for Kerberos. If omitted it will use the domain part (FQDN) specified in the identity
                        parameter
  -d, --domain DOMAIN   (FQDN) domain to authenticate to
  -u, --user USER       user to authenticate with
  -crt, --certfile CERTFILE
                        Path to the user certificate (PEM format) for Schannel authentication
  -key, --keyfile KEYFILE
                        Path to the user private key (PEM format) for Schannel authentication
  -td, --target-domain TARGET_DOMAIN
                        Target domain (if different than the domain of the authenticating user)
  --no-pass             don't ask for password (useful for -k)
  -p, --password PASSWORD
                        password to authenticate with
  -H, --hashes [LMHASH:]NTHASH
                        NT/LM hashes, format is LMhash:NThash
  --aes-key hex key     AES key to use for Kerberos Authentication (128 or 256 bits)
  -k, --kerberos        Use Kerberos authentication. Grabs credentials from .ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the
                        ones specified in the command line

arguments when setting -action to find, enable or disable:
  -t, --target TARGET_SAMNAME
                        Target account (required for find, enable, disable)
  -tl, --target-list TARGET_SAMNAME_LIST
                        Path to a file with target accounts names (one per line)

Examples:
  # Find all disabled users and computers (with relationship analysis)
  lazarus-wakeup -d CORP.LOCAL -u administrator -p Password123 -a find-all

  # Find specific disabled user
  lazarus-wakeup -d CORP.LOCAL -u admin -p Pass123 -a find -t jdoe

  # Find multiple specific disabled users from file
  lazarus-wakeup -d CORP.LOCAL -u admin -p Pass123 -a find -tl disabled_users.txt

  # Enable a disabled user
  lazarus-wakeup -d CORP.LOCAL -u admin -p Pass123 -a enable -t jdoe

  # Enable multiple users from file
  lazarus-wakeup -d CORP.LOCAL -u admin -p Pass123 -a enable -tl targets.txt --force

  # Disable a user
  lazarus-wakeup -d CORP.LOCAL -u admin -p Pass123 -a disable -t jdoe

  # Use NTLM hash
  lazarus-wakeup -d CORP.LOCAL -u admin -H :a87f3a337d73085c45f9416be5787d86 -a find-all

  # Use Kerberos
  lazarus-wakeup -d CORP.LOCAL -u admin -p Pass123 -k -a find-all

  # Use LDAPS
  lazarus-wakeup -d CORP.LOCAL -u admin -p Pass123 --use-ldaps -a find-all

Note: 
  - Guest and krbtgt accounts are automatically excluded from all operations
  - find requires -t or -tl to specify targets
  - find-all searches all disabled objects without requiring targets
  - Both find and find-all automatically analyze inbound relationships
```

## References

- [DACL by The Hacker Recipes](https://www.thehacker.recipes/ad/movement/dacl/)
- [An ACE Up the Sleeve by SpecterOps](https://specterops.io/wp-content/uploads/sites/3/2022/06/an_ace_up_the_sleeve.pdf)

