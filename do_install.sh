#!/bin/bash

clear

# As fist the network so we can continue
echo -e "\n\nBasic Network Configuration:"

echo -n "  DHCP [Y/n]"
read DHCP
if [ "${DHCP}" == "n" -o "${DHCP}" == "N" ]; then
	IPv4=''
	while [ -z "${IPv4}" ]; do
		echo -n "  IPv4 Address: "
		read IPv4
	done

	echo -n "  Netmask (DDN not /CIDR) [255.255.255.0]: "
	read NMASK
	if [ -z "${NMASK}" ]; then
		NMASK="255.255.255.0"
	fi

	IPGW=''
	while [ -z "${IPGW}" ]; do
		echo -n "  IPv4 Gateway: "
		read IPGW
	done

	DNS1=''
	while [ -z "${DNS1}" ]; do
		echo -n "  DNS-Server 1: "
		read DNS1
	done
	echo -n "  DNS-Server 2 (optional): "
	read DNS2

	sed -i 's/inet dhcp/inet static/' /etc/network/interfaces
	echo -e "\taddress ${IPv4}" >> /etc/network/interfaces
	echo -e "\tnetmast ${NMASK}" >> /etc/network/interfaces
	echo -e "\tgateway ${IPGW}" >> /etc/network/interfaces

	echo "nameserver ${DNS1}" > /etc/resolv.conf
	if [ ! -z "${DNS2}" ]; then
		echo "nameserver ${DNS2}" >> /etc/resolv.conf
	fi

	systemctl enable networking
	systemctl restart networking

	IPIFACE=`cat /etc/network/interfaces | grep "inet static" | awk '{print $2}'`
	ifup ${IPIFACE}
fi

# The main part starts here...
NGINX_CERT_PATH="/etc/nginx/certs"

apt install dialog

TITLE="ReverseProxy Setup: TITLE"

dialog --backtitle "${TITLE//TITLE/Warmup}" \
  --title "Starting setup" \
  --yesno "This Script is installing and hardening a NGINX Reverse-Proxy.\nTo do so, the base linux is cleand up and hardnend as well.\n\nShall we continue?" \
  10 50
if [ $? == 1 ]; then
	echo -e "\nNothing done except installed dialog...\n\nsee you soon...\n"
	exit 1
fi

HOSTNAME=""
INTERNAL=""
DOMAIN=""
EXCHANGE=""
OWA=""
SYSLOG=""
SYSPORT=""

function install_and_cleanup() {
	apt remove task-ssh-server telnet usbutils xauth reportbug
	apt autoremove
	apt install sudo nginx-light ufw openssh-server openssh-client
}

function enable_services() {
	echo "${HOSTNAME}" > /etc/hostname
	cat >/etc/hosts <<EOL
127.0.0.1	localhost
127.0.0.1	${HOSTNAME}
::1		localhost  ip6-localhost  ip6-loopback
::1		${HOSTNAME}
fe02::1		ip6-allnodes
fe02::2		ip6-allrouters
EOL

	cat >/etc/cron.d/upgrade <<EOL
# Hold the system up to date around 2:00 AM
2 0 * * 0 root ( apt-get -y update && apt-get -y -d upgrade ) > /dev/null
EOL

	if [ ! -z "${SYSLOG}" ]; then
		echo -e "\n# Remote syslog server\n*.* @@${SYSLOG}:${SYSPORT:-514}" >> /etc/rsyslog.conf
	else
		echo -e "\n# Remote syslog server\n#*.* @@1.2.3.4:514" >> /etc/rsyslog.conf
	fi

	ufw allow 'Nginx Full'
	ufw allow from ${INTERNAL} to any port 22 proto tcp comment 'SSH from internal only'
	ufw limit 22/tcp
	ufw enable

	systemctl enable ufw
	systemctl enable ssh
	systemctl enable nginx
}

FIFO=/tmp/`tr -dc A-Za-z0-9 </dev/urandom | head -c 8`
function read_base_data() {
	dialog \
		--backtitle "${TITLE//TITLE/Configuration}" \
		--title "Configuration" \
		--form "Please enter all values" 20 65 0 \
		"Hostname   (of the Proxy)" 1 1 "" 1 30 28 0 \
		"Internal-Net  (A.B.C.D/M)" 2 1 "" 2 30 28 0 \
		"Domain    (External FQDN)" 3 1 "" 3 30 28 0 \
		"Server/IP      (Internal)" 4 1 "" 4 30 28 0 \
		"Redirect-Path  (URI-Path)" 5 1 "" 5 30 28 0 \
		"Syslog-Server   (Host/IP)" 6 1 "" 6 30 28 0 \
		"Syslog-Port (default 514)" 7 1 "" 7 30 28 0 \
		--output-fd 1 &>${FIFO}
	if [ $? == 1 ]; then
		echo -e "\nAborted...\n\n"
		exit 1
	fi

	RESULT=(`cat ${FIFO}`)
	rm ${FIFO}
	HOSTNAME=${RESULT[0]}
	INTERNAL=${RESULT[1]}
	DOMAIN=${RESULT[2]}
	EXCHANGE=${RESULT[3]}
	OWA=${RESULT[4]}
	SYSLOG=${RESULT[5]}
	SYSPORT=${RESULT[6]}
}

function clean_nginx_installation() {
	rm /etc/nginx/modules-enabled/*
	rm /etc/nginx/sites-enabled/*
	ln -s /etc/nginx/sites-available/default /etc/nginx/sites-enabled/default

	sed -i 's/ssl_protocols.*/ssl_protocols TLSv1.2 TLSv1.3 ; # Dropping SSLv3, ref POODLE, TLSv1.0 and TLSv1.1/' /etc/nginx/nginx.conf
	sed -i 's/ssl_protocols.*/ssl_protocols TLSv1.2 TLSv1.3 ; # Dropping SSLv3, ref POODLE, TLSv1.0 and TLSv1.1/' /etc/nginx/nginx.conf

	sed -i 's/# ssl_prefer_server_ciphers.*/ssl_prefer_server_ciphers on;/' /etc/nginx/nginx.conf
	sed -i 's/ssl_prefer_server_ciphers.*/ssl_prefer_server_ciphers on;/' /etc/nginx/nginx.conf
	#ssl_ciphers EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH;

	sed -i 's/# server_tokens.*/server_tokens off;/' /etc/nginx/nginx.conf
	sed -i 's/server_tokens.*/server_tokens off;/' /etc/nginx/nginx.conf

	sed -i 's/# gzip on;/gzip off;/' /etc/nginx/nginx.conf
	sed -i 's/gzip on;/gzip off;/' /etc/nginx/nginx.conf

	cat >/etc/nginx/conf.d/99-buffer-policy.conf <<EOL
client_body_buffer_size 1k;
client_header_buffer_size 1k;
client_max_body_size 1k;
large_client_header_buffers 2 1k;
EOL
	chmod 0644 /etc/nginx/conf.d/99-buffer-policy.conf
	cat >/etc/nginx/conf.d/99-xss.conf <<EOL
add_header X-XSS-Protection "1; mode=block";
add_header X-Frame-Options "SAMEORIGIN";
add_header Strict-Transport-Security "max-age=31536000; includeSubdomains; preload";
add_header Content-Security-Policy "default-src 'self' http: https: data: blob: 'unsafe-inline'" always;
if (\$http_user_agent ~* LWP::Simple|BBBike|wget|curl) {
  return 403;
}

location / {
  limit_except GET HEAD POST { deny all; }
}
EOL
	chmod 0644 /etc/nginx/conf.d/99-xss.conf
}

function harden_system() {
	cat >/etc/sysctl.d/99-harden.conf <<EOL
# Turn on exec-shield
kernel.exec-shield=1
kernel.randomize_va_space=1

# Enable IP Spoofing protection
net.ipv4.conf.all.rp_filter=1

# Disable IP Source Routing
net.ipv4.conf.all.accept_source_route=0

# Ignore broadcast requests
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.icmp_ignore_bogus_error_messages=1

# Make sure spoofed packets get logged
net.ipv4.conf.al.log_martians=1
EOL
	chmod 0644 /etc/sysctl.d/99-harden.conf
	systemctl daemon-reload

	cat >/etc/motd <<EOL
Welcome to the specially hardened Proxy ${HOSTNAME}

Update the SSL-Certificate:
---------------------------
1. Upload these files via scp:
 * ${DOMAIN}.crt
 * ${DOMAIN}.key

2. Change the ownershp and permission of them:
\$ sudo chown root.root ${DOMAIN}.*
\$ sudo chmod 0600 ${DOMAIN}.*

3. Copy them into ${NGINX_CERT_PATH}
\$ sudo mv ${DOMAIN}.* ${HGINX_CERT_PATH}/


Upgrade the system from time to time:
-------------------------------------
\$ apt update
\$ apt upgrade
\$ apt full-upgrade
\$ apt autoremove

Have fun...
EOL
}

function configure_sshd() {
	sed -i 's/^X11Forwarding.*/X11Forwarding no/' /etc/ssh/sshd_config
	sed -i 's/^AllowAgentForwarding.*/AllowAgentForwarding no/' /etc/ssh/sshd_config
	sed -i 's/^AllowTcpForwarding.*/AllowTcpForwarding no/' /etc/ssh/sshd_config
	sed -i 's/^PrintMotd.*/PrintMotd yes/' /etc/ssh/sshd_config

	cat >/etc/ssh/sshd_config.d/99-z_hardening.conf <<EOL
# Using https://infosec.mozilla.org/guidelines/openssh with default parameters set too
Port 22
Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key

Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
KexAlgorithms curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256

SyslogFacility AUTH
LogLevel INFO
Banner none

LoginGraceTime 120
PermitRootLogin no
PermitEmptyPasswords no
PasswordAuthentication yes

PubkeyAuthentication yes
IgnoreRhosts yes

X11Forwarding no
PrintMotd no
PrintLastLog yes
TCPKeepAlive no
EOL
	chmod 0644 /etc/ssh/sshd_config.d/99-z_hardening.conf
}

function configure_nginx_proxy() {
	cat >/etc/nginx/sites-available/default <<EOL
server {
	listen 80 default_server;
	listen [::]:80 default_server;
	server_name ${DOMAIN};

	rewrite ^ https://\$server_name\$request_uri? permanent;
}
server {
	listen 443 ssl default_server;
	listen [::]:443 ssl default_server;
	server_name ${DOMAIN};

	gzip off;
	ssl_certificate ${NGINX_CERT_PATH}/${DOMAIN}.crt;
	ssl_certificate_key ${NGINX_CERT_PATH}/${DOMAIN}.key;
	ssl_session_timeout 5m;

	location / {
		proxy_http_version 1.1;
		proxy_read_timeout 360;
		proxy_cache_bypass \$http_upgrade;
		proxy_set_header Upgrade \$http_upgrade;
		proxy_set_header Connection keep-alive;
		proxy_set_header Host \$host;
		proxy_set_header X-Real-IP \$remote_addr;
		proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
		proxy_set_header X-Forwarded-Proto \$scheme;

		proxy_pass https://${EXCHANGE}/${OWA};
	}
}
EOL
	mkdir -p ${NGINX_CERT_PATH}
	chmod -R 0600 ${NGINX_CERT_PATH}
}

function __password_change__() {
	dialog --clear
	dialog --backtitle "${TITLE//TITLE/Securing Users}" \
	  --title "New Password for '${1}'?" \
	  --yes-label "Change Password" \
	  --yesno "Did you choose a secure Password for '${1}' during the installation or shall we change it?" \
	  10 50
	if [ $? == 0 ]; then
		echo -e "\n\nChange password for: ${1}"
		passwd ${1}
	fi
}

function passwords() {
	__password_change__ root

	__USERNAME=(`cat /etc/passwd | grep ':1000:' | awk -F':' '{ printf "%s\n%s", $1, $6 }'`)
	USERNAME="${__USERNAME[0]}"
	USERHOME="${__USERNAME[1]}"
	if [ ! -z "${USERNAME}" ]; then
		__password_change__ ${USERNAME}
		usermod -a -G sudo ${USERNAME}
	else
		echo "Did not find any user with an ID=1000. This is normally the User added during the installation. Please add this user manually and add it to the 'sudo'-group."
		read __none
	fi
}

install_and_cleanup
read_base_data
harden_system
configure_sshd
clean_nginx_installation
configure_nginx_proxy
enable_services
passwords

dialog --backtitle "${TITLE//TITLE/Finished}" \
  --title "Finished" \
  --msgbox "The System is configured with your given values and hardened as much as possible.\n\nThere is some basic network blocking and regulation, a firewall blocking all except HTTP and HTTPS and finally an NGINX reverse Proxy redirection from HTTP to HTTPS and only with the most secure TLS-Versions and ciphers enabled.\n\nBe sure there is ${DOMAIN}.key and ${DOMAIN}.crt in place under ${NGINX_CERT_PATH}" \
  18 50

clear

exit 0
