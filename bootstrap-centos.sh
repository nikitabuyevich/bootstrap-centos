#!/bin/bash
# Created by Nikita Buyevich
# Last updated on March 31st, 2020
# Forked from https://www.limestonenetworks.com/support/knowledge-center/11/83/hardening_centos.html

echo "-------------- Bootstrapping your CentOS --------------"
echo "It is recommended that you only run this on a new system."
echo "---------------------------------------------------------"
cd /root

# --- GLOBAL VARIABLES ---
# Open HTTP / HTTPS
TCP_PORTS=( 80 443 )

# --- ENVIRONMENT VARIABLES ---
/bin/cat << EOM > /etc/environment
# Enable keystrokes for non-linux machines
export TERM="xterm-256color"
EOM



echo "--- Create Admin User ---"
echo "-------------------------"
useradd -m admin
passwd admin
# Give admin sudo access
gpasswd -a admin wheel



echo "--- Bootstrap Setup ---"
echo "-----------------------"
# Set alert email address
read -p "Enter an email address to be notified about alerts: " ALERT_EMAIL
# Set SSH port
read -p "Enter a new SSH port (or press enter for random): " SSH_PORT
# Randomize SSH port if it wasn't provided
if [[ "$SSH_PORT" == "" ]]
then SSH_PORT=$((RANDOM%5000+2000))
fi
# Add ssh port to tcp ports to accept
TCP_PORTS+=( $SSH_PORT )
echo "--------------------------------------- Create a Swap File ----------------------------------------"
echo "Advice about the best size for a swap space varies significantly depending on the source consulted."
echo "Generally, an amount equal to or double the amount of RAM on your system is a good starting point."
echo "---------------------------------------------------------------------------------------------------"
read -p "Enter a swap file size (e.g., 4G): " SWAP_FILE_SIZE
read -p "Enter a time zone (e.g., Europe/Berlin): " TIME_ZONE
read -p "Install Docker [y/n]: " INSTALL_DOCKER
read -p "Install Gitlab Runner [y/n]: " INSTALL_GITLAB_RUNNER
case "$INSTALL_GITLAB_RUNNER" in
      y|Y ) read -p "Register Gitlab Runner [y/n]: " REGISTER_GITLAB_RUNNER;;
esac

# Install EPEL repo
yum install -y epel-release


case "$INSTALL_GITLAB_RUNNER" in
      y|Y ) echo "Installing Gitlab Runner...";
            # Install Gitlab Runner
            curl -L https://packages.gitlab.com/install/repositories/runner/gitlab-runner/script.rpm.sh | bash
            yum install -y gitlab-runner
            # Let gitlab-runner run Docker
            usermod -aG docker gitlab-runner
            break;;
esac



case "$REGISTER_GITLAB_RUNNER" in
      y|Y ) echo "Registering Gitlab Runner...";
            # Register Gitlab Runner
            # See # See https://docs.gitlab.com/runner/register/index.html
            gitlab-runner register
            break;;
esac



echo "--- Enable 2FA ---"
echo "---------------------"
# Install 2FA
yum install -y google-authenticator
# Setup 2FA as admin user
sudo -u admin -H sh -c "google-authenticator"

# Update PAM file to include google-authenticator
/bin/cat << EOM > /etc/pam.d/sshd
#%PAM-1.0
auth       required     pam_sepermit.so
# auth       substack     password-auth
auth       include      postlogin
# Used with polkit to reauthorize users in remote sessions
-auth      optional     pam_reauthorize.so prepare
account    required     pam_nologin.so
account    include      password-auth
password   include      password-auth
# pam_selinux.so close should be the first session rule
session    required     pam_selinux.so close
session    required     pam_loginuid.so
# pam_selinux.so open should only be followed by sessions to be executed in the user context
session    required     pam_selinux.so open env_params
session    required     pam_namespace.so
session    optional     pam_keyinit.so force revoke
session    include      password-auth
session    include      postlogin
# Used with polkit to reauthorize users in remote sessions
-session   optional     pam_reauthorize.so prepare
auth required pam_google_authenticator.so
EOM
echo "----------------------------------------------------"
echo "----------------------------------------------------"



echo "--- Scheduling Auto Updates ---"
echo "-------------------------------"
# Turn on cron-based auto-updates
yum install -y yum-cron
for d in crond yum yum-cron; do
    /sbin/chkconfig $d on
    /sbin/service $d start
done



echo "--- Installing Useful Packages ---"
echo "----------------------------------"
# Installing useful packages
yum install -y wget unzip



echo "--- Insure All Packages Are Up To Date  ---"
echo "-------------------------------------------"
yum update -y



echo "--- Creating Swap File ---"
echo "--------------------------"
# Create swapfile
fallocate -l $SWAP_FILE_SIZE /swapfile
# Restrict access to it
chmod 600 /swapfile
# Format file for swap
mkswap /swapfile
# Use the swapfile
swapon /swapfile
# Automatically use swapfile on reboot
sh -c 'echo "/swapfile none swap sw 0 0" >> /etc/fstab'



echo "--- Setting Time Zone ---"
echo "---------------------"
# Set time zone
timedatectl set-timezone $TIME_ZONE
# Install ntp
yum install -y ntp
# Start ntp
systemctl enable ntpd
systemctl start ntpd



echo "--- Install git and git lfs ---"
echo "-------------------------------"
# Remove old git packages
yum remove -y git*
# Install git
yum install -y  https://centos7.iuscommunity.org/ius-release.rpm
yum install -y  git2u-all
# Install git lfs
curl -s https://packagecloud.io/install/repositories/github/git-lfs/script.rpm.sh | bash
yum install -y git-lfs
git lfs install



case "$INSTALL_DOCKER" in
      y|Y ) echo "Installing Docker...";
            # Install Docker
            curl -fsSL https://get.docker.com/ | sh
            # Run Docker
            systemctl enable docker
            systemctl start docker
            # Let admin run Docker
            usermod -aG docker admin
            # Install docker-compose
            curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
            chmod +x /usr/local/bin/docker-compose
            break;;
esac



echo "---                     Setting Password Policies                        ---"
echo "--- Per recommendations from http://wiki.centos.org/HowTos/OS_Protection ---"
echo "----------------------------------------------------------------------------"
echo "Passwords will expire every 180 days"
perl -npe 's/PASS_MAX_DAYS\s+99999/PASS_MAX_DAYS 180/' -i /etc/login.defs
echo "Passwords may only be changed once a day"
perl -npe 's/PASS_MIN_DAYS\s+0/PASS_MIN_DAYS 1/g' -i /etc/login.defs



echo "---            Setting Additional OS Policies/Securities                 ---"
echo "--- Per recommendations from http://wiki.centos.org/HowTos/OS_Protection ---"
echo "----------------------------------------------------------------------------"
# Now that we've restricted the login options for the server,
# lets kick off all the idle folks. To do this,
# we're going to use a bash variable in /etc/profile.
# There are some reasonably trivial ways around this of course,
# but it's all about layering the security.
echo "Idle users will be removed after 15 minutes"
echo "readonly TMOUT=900" >> /etc/profile.d/os-security.sh
echo "readonly HISTFILE" >> /etc/profile.d/os-security.sh
chmod +x /etc/profile.d/os-security.sh

# In some cases, administrators may want the root user
# or other trusted users to be able to run cronjobs
# or timed scripts with at. In order to lock these down,
# you will need to create a cron.deny and at.deny file inside /etc
# with the names of all blocked users. An easy way to do this is
# to parse /etc/passwd. The script below will do this for you.
echo "Locking down Cron"
touch /etc/cron.allow
chmod 600 /etc/cron.allow
awk -F: '{print $1}' /etc/passwd | grep -v root > /etc/cron.deny
echo "Locking down AT"
touch /etc/at.allow
chmod 600 /etc/at.allow
awk -F: '{print $1}' /etc/passwd | grep -v root > /etc/at.deny



echo "--- Install and Clear IPTables Firewall  ---"
echo "--------------------------------------------"
yum install -y iptables
chkconfig iptables on
/sbin/service iptables start
/sbin/iptables -F
/sbin/iptables -X
iptables-save


echo "--- Running Firewall Configurations ---"
echo "---------------------------------------"

# By default reject all traffic
/sbin/iptables -P INPUT DROP
/sbin/iptables -P OUTPUT DROP
/sbin/iptables -P FORWARD DROP

# Allow localhost
/sbin/iptables -A INPUT -i lo -j ACCEPT
/sbin/iptables -A OUTPUT -o lo -j ACCEPT

# Allow output for new, related and established connections
/sbin/iptables -A OUTPUT -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT

# Open TCP Ports
for port in ${TCP_PORTS[@]}
    do
        echo "Opening TCP Port $port"
        /sbin/iptables -A INPUT -p tcp -m tcp --dport $port -j ACCEPT
    done

# Enable ntp
iptables -A OUTPUT -p udp --dport 123 -j ACCEPT
iptables -A INPUT -p udp --sport 123 -j ACCEPT


echo "--- Blocking Common Attacks ---"
echo "-------------------------------"

echo "Forcing SYN packets check"
/sbin/iptables -A INPUT -p tcp ! --syn -m state --state NEW -j DROP

echo "Forcing Fragments packets check"
/sbin/iptables -A INPUT -f -j DROP

echo "Dropping malformed XMAS packets"
/sbin/iptables -A INPUT -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP

echo "Drop all NULL packets"
/sbin/iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP

echo "Limiting pings to 1 per second"
/sbin/iptables -N PACKET
/sbin/iptables -A DEFAULT_RULES -p icmp -m limit --limit 3/sec --limit-burst 25 -j ACCEPT

echo "Setup Connection Tracking"
/sbin/iptables -N STATE_TRACK
/sbin/iptables -A STATE_TRACK -m state --state RELATED,ESTABLISHED -j ACCEPT
/sbin/iptables -A STATE_TRACK -m state --state INVALID -j DROP

echo "Discouraging Port Scanning"
/sbin/iptables -N PORTSCAN
/sbin/iptables -A PORTSCAN -p tcp --tcp-flags ACK,FIN FIN -j DROP
/sbin/iptables -A PORTSCAN -p tcp --tcp-flags ACK,PSH PSH -j DROP
/sbin/iptables -A PORTSCAN -p tcp --tcp-flags ACK,URG URG -j DROP
/sbin/iptables -A PORTSCAN -p tcp --tcp-flags FIN,RST FIN,RST -j DROP
/sbin/iptables -A PORTSCAN -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
/sbin/iptables -A PORTSCAN -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
/sbin/iptables -A PORTSCAN -p tcp --tcp-flags ALL ALL -j DROP
/sbin/iptables -A PORTSCAN -p tcp --tcp-flags ALL NONE -j DROP
/sbin/iptables -A PORTSCAN -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP
/sbin/iptables -A PORTSCAN -p tcp --tcp-flags ALL SYN,FIN,PSH,URG -j DROP
/sbin/iptables -A PORTSCAN -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP


echo "Setting Final Configurations"
/sbin/iptables -N COMMON
/sbin/iptables -A COMMON -j STATE_TRACK
/sbin/iptables -A COMMON -j PORTSCAN
/sbin/iptables -A COMMON -j PACKET

/sbin/iptables -A INPUT -j COMMON
/sbin/iptables -A OUTPUT -j COMMON
/sbin/iptables -A FORWARD -j COMMON
/sbin/iptables -A FORWARD -j PACKET

echo "Saving IPTables"
iptables-save



echo "--- Installing DDoS Deflate ---"
echo "-------------------------------"
wget https://github.com/jgmdev/ddos-deflate/archive/master.zip -O ddos.zip
unzip ddos.zip
rm -rf ddos.zip
yes | sh ddos-deflate-master/install.sh
rm -rf ddos-deflate-master



echo "--- Installing CHKROOTKIT  ---"
echo "------------------------------"
wget -O /usr/local/src/chkrootkit.tar.gz ftp://ftp.pangeia.com.br/pub/seg/pac/chkrootkit.tar.gz
tar -C /usr/local/src/ -zxvf /usr/local/src/chkrootkit.tar.gz
mkdir /usr/local/chkrootkit
mv -f /usr/local/src/chkrootkit*/* /usr/local/chkrootkit
cd /usr/local/chkrootkit
make sense
cd /root

/bin/cat << EOM > /etc/cron.daily/chkrootkit.sh
#!/bin/sh
(
/usr/local/chkrootkit/chkrootkit
) | /bin/mail -s 'CHROOTKIT Daily Run' $ALERT_EMAIL
EOM
chmod 700 /etc/cron.daily/chkrootkit.sh



echo "--- Installing Root Kit Hunter ---"
echo "----------------------------------"
wget -O /usr/local/src/rkhunter.tar.gz "https://sourceforge.net/projects/rkhunter/files/latest/download"
tar -C /usr/local/src/ -zxvf /usr/local/src/rkhunter.tar.gz
cd /usr/local/src/rkhunter*
./installer.sh --layout default --install
/usr/local/bin/rkhunter --update
/usr/local/bin/rkhunter --propupd
rm -Rf /usr/local/src/rkhunter*
/bin/cat << EOM > /etc/cron.daily/rkhunter.sh
#!/bin/sh
(
/usr/local/bin/rkhunter --versioncheck
/usr/local/bin/rkhunter --update
/usr/local/bin/rkhunter --cronjob --report-warnings-only
) | /bin/mail -s 'rkhunter Daily Run' $ALERT_EMAIL
EOM
chmod 700 /etc/cron.daily/rkhunter.sh



echo "--- Installing LSM (Linux Socket Monitor) ---"
echo "---------------------------------------------"
wget -O /usr/local/src/lsm-current.tar.gz http://www.rfxn.com/downloads/lsm-current.tar.gz
tar -C /usr/local/src/ -zxvf /usr/local/src/lsm-current.tar.gz
cd /usr/local/src/lsm-0.*
sh install.sh
cd /root
rm -Rf /usr/local/src/lsm-*
sed -i 's/root/'$ALERT_EMAIL/ /usr/local/lsm/conf.lsm
/usr/local/sbin/lsm -g


echo "--- Making changes to /etc/sysctl.conf ---"
echo "------------------------------------------"
echo 'net.ipv4.tcp_syncookies = 1' >> /etc/sysctl.conf
echo 'net.ipv4.tcp_synack_retries = 2' >> /etc/sysctl.conf
echo 'net.ipv4.conf.all.rp_filter = 1' >> /etc/sysctl.conf
echo 'net.ipv4.conf.default.rp_filter = 1' >> /etc/sysctl.conf
echo 'net.ipv4.conf.all.accept_redirects = 0' >> /etc/sysctl.conf
echo 'net.ipv4.conf.all.secure_redirects = 0' >> /etc/sysctl.conf
echo 'net.ipv4.conf.all.accept_source_route = 0' >> /etc/sysctl.conf
echo 'net.ipv4.conf.all.send_redirects = 0' >> /etc/sysctl.conf
echo 'net.ipv4.conf.default.send_redirects = 0' >> /etc/sysctl.conf

/sbin/sysctl net.ipv4.tcp_syncookies=1
/sbin/sysctl net.ipv4.tcp_synack_retries=2
/sbin/sysctl net.ipv4.conf.all.rp_filter=1
/sbin/sysctl net.ipv4.conf.default.rp_filter=1
/sbin/sysctl net.ipv4.conf.all.accept_redirects=0
/sbin/sysctl net.ipv4.conf.all.secure_redirects=0
/sbin/sysctl net.ipv4.conf.all.accept_source_route=0
/sbin/sysctl net.ipv4.conf.all.send_redirects=0
/sbin/sysctl net.ipv4.conf.default.send_redirects=0



echo "--- Modify SELinux to allow sshd to listen to new SSH port ---"
echo "--------------------------------------------------------------"
# Install semanage
yum install -y policycoreutils-python
# Allow SSH port
semanage port -a -t ssh_port_t -p tcp $SSH_PORT



echo "--- Copy root's SSH authorized keys to new user ---"
echo "-----------------------------------------------------"
mkdir /home/admin/.ssh
chmod 700 /home/admin/.ssh
cp /root/.ssh/authorized_keys /home/admin/.ssh/authorized_keys
chmod 600 /home/admin/.ssh/authorized_keys
chown -R admin:admin /home/admin/.ssh



echo "--- Securing the SSH Daemon ---"
echo "-------------------------------"
echo "Backing up previous SSHd configurations"
mv /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
/bin/cat << EOM > /etc/ssh/sshd_config
## Random SSH port
Port $SSH_PORT

## Sets listening address on server. default=0.0.0.0
#ListenAddress 192.168.0.1

## Enforcing SSH Protocol 2 only
Protocol 2

## Disable direct root login, with no you need to login with admin user, then "su -" you into root
PermitRootLogin no

# Authentication
LoginGraceTime 1m

# Disable password login
PermitEmptyPasswords no
PasswordAuthentication no

# Enable 2FA
ChallengeResponseAuthentication yes
UsePAM yes
AuthenticationMethods publickey,password publickey,keyboard-interactive

##
UsePrivilegeSeparation yes

##
AllowTcpForwarding yes

## Disables X11Forwarding
X11Forwarding no

## Checks users on their home directority and rhosts, that they arent world-writable
StrictModes yes

## The option IgnoreRhosts specifies whether rhosts or shosts files should not be used in authentication
IgnoreRhosts yes

##
HostbasedAuthentication no

## RhostsAuthentication specifies whether sshd can try to use rhosts based authentication.
RhostsRSAAuthentication no

## Enable / Disable sftp server
Subsystem      sftp    /usr/libexec/openssh/sftp-server

## Add users that are allowed to log in
AllowUsers admin
EOM



echo "--- Install VIM ---"
echo "-------------------"
# Installing latest vim
yum -y install vim-X11 vim-common vim-enhanced vim-minimal
# Create .vimrc file for admin user
/bin/cat << EOM > /home/admin/.vimrc
set history=700

colo delek
syntax on

set showmode

set autoindent
set smartindent
set backspace=eol,start,indent

set expandtab
set tabstop=4
set shiftwidth=4
set ruler

set number
set ignorecase
set smartcase
set hlsearch
set backup
set backupdir=~/vim/tmp/
set nowrap
set laststatus=2
set cmdheight=2
EOM
# Copy vim settings to root as well
cp  /home/admin/.vimrc /root/.vimrc



echo "--- Install htop ---"
echo "--------------------"
# Installing latest vim
yum -y install htop
# Create necessary htop folders for admin user
mkdir /home/admin/.config
mkdir /home/admin/.config/htop
# Overwrite htoprc file for admin user
# Custom options:
#     Use Tree View
#     Hide kernel threads
#     Hide userland threads
/bin/cat << EOM > /home/admin/.config/htop/htoprc
# Beware! This file is rewritten by htop when settings are changed in the interface.
# The parser is also very primitive, and not human-friendly.
fields=0 48 17 18 38 39 40 2 46 47 49 1
sort_key=46
sort_direction=1
hide_threads=0
hide_kernel_threads=1
hide_userland_threads=1
shadow_other_users=1
show_thread_names=1
highlight_base_name=1
highlight_megabytes=1
highlight_threads=1
tree_view=1
header_margin=1
detailed_cpu_time=1
cpu_count_from_zero=0
update_process_names=1
color_scheme=0
delay=15
left_meters=LeftCPUs Memory Swap
left_meter_modes=1 1 1
right_meters=RightCPUs Tasks LoadAverage Uptime
right_meter_modes=1 2 2 2
EOM



echo "******************************************"
echo "     YOUR SERVER IS NOW BOOTSTRAPPED"
echo "------------------------------------------"
echo "SSH User: admin"
echo "SSH Port: $SSH_PORT"
echo "Alert Email: $ALERT_EMAIL"
echo "******************************************************************"
echo ""
echo "You must now reconnect to this server using the information above."
echo "Changing the SSH port has caused this connection to freeze."
echo "BEFORE CLOSING THIS WINDOW please note your information above."
echo "------------------------------------------------------------------"
/sbin/service sshd restart
