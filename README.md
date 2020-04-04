![Logo of Centos](./centos.png)

# Bootstrap / Harden CentOS &middot; [![GitHub license](https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)](./LICENSE)

A bootstrapping / hardening CentOS bash script. It is meant to be used on new systems.

The motivation for this script is to easily serve up web servers / microservices.

## Features

- Automatic yum updates
- Idle users will be disconnected after 15 minutes
- Secure SSH Daemon
  - Set SSH to a random number
  - Creates an `admin` user - Only they can login
- Two-Factor Authentication (2FA)
- Creates a swap file
- Synchronizes a specified time zone
- Password policies
  - Passwords will expire every 180 days
  - Passwords may only be changed once a day
- Block common network attacks
  - Syn Floods
  - Fragmented Packets
  - Malformed XMAS Packets
  - Drop NULL packets
  - Limit pings to 3 per second and bursts of 25
  - Discourage Port Scanning
- Connection tracking
- Install Docker (optional)
- Install Go (optional)
- Install Gitlab Runner (optional)
- Register Gitlab Runner (optional)
- Install DDoS Defalate - https://github.com/jgmdev/ddos-deflate
- Install CHKROOTKIT - http://www.chkrootkit.org
- Install Root Kit Hunter (rkhunter) - http://rkhunter.sourceforge.net
- Install Linux Socket Monitor (LSM) - Runs in the background and watches for changes in sockets

## Getting Started

As root user, execute

```bash
 source <(curl -s https://raw.githubusercontent.com/nikitabuyevich/bootstrap-centos/master/bootstrap-centos.sh)
```

### Prerequisites

- [CentOS](https://www.centos.org/) - Linux distribution that is a consistent, manageable platform that suits a wide variety of deployments

### Configuration

By default, the only TCP ports which are exposed are `HTTP` / `HTTPS` / `SSH`. Modify the `TCP_PORTS` variable if you wish to add more.

Update this script as it fits your needs. For example, this script includes an optional Gitlab Runner install. Feel free to remove it if you have no use for it.

## Built With

- [Bash](https://www.gnu.org/software/bash/) - Unix shell and command language

## Authors

- **Nikita Buyevich** - [nikitabuyevich.com](https://nikitabuyevich.com/)

## License

This project is licensed under the MIT License - see the [LICENSE](./LICENSE) file for details.

## Acknowledgments

Forked and modified from https://www.limestonenetworks.com/support/knowledge-center/11/83/hardening_centos.html
