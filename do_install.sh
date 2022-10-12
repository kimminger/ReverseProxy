#!/bin/bash

clear

# As fist the network so we can continue
echo -e "\n\nBasic Network Configuration:"

echo -n "  DHCP (or no change) [Y/n]"
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
  --yesno "This Script is installing and hardening a NGINX Reverse-Proxy.\nTo do so, the base linux is cleaned up and hardnend as well.\n\nShall we continue?" \
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

USER1000=(`cat /etc/passwd | grep ':1000:' | awk -F':' '{ printf "%s\n%s", $1 }'`)
if [ -z "${USER1000}" ]; then
	echo "There should be a user with UID 1000 being created during setup."
	echo "Please create a user with UID 1000 and restart this script."
	exit 1
fi

function install_and_cleanup() {
	apt remove task-ssh-server telnet usbutils xauth reportbug
	apt install sudo nginx-light libnginx-mod-http-headers-more-filter ufw openssh-server openssh-client wget
	apt autoremove
	/sbin/usermod -a -G sudo ${USER1000}
}

function enable_services() {
	echo "${HOSTNAME}" > /etc/hostname
	cat >/etc/hosts <<EOL
127.0.0.1	localhost
127.0.0.1	${HOSTNAME}
127.0.0.1	${DOMAIN}
::1		localhost  ip6-localhost  ip6-loopback
::1		${HOSTNAME}
::1		${DOMAIN}
fe02::1		ip6-allnodes
fe02::2		ip6-allrouters
EOL

	cat >/etc/cron.daily/upgrade <<EOL
#!/bin/bash
# Hold the system up to date
apt-get -y update > /dev/null
apt-get -y -d upgrade > /dev/null
EOL
	chmod 0755 /etc/cron.daily/upgrade
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
		"Hostname    (of the Proxy)" 1 1 "" 1 30 28 0 \
		"Allow SSH from (A.B.C.D/M)" 2 1 "" 2 30 28 0 \
		"Domain     (External FQDN)" 3 1 "" 3 30 28 0 \
		"Exchange-Server (Internal)" 4 1 "" 4 30 28 0 \
		"Syslog-Server    (Host/IP)" 5 1 "" 5 30 28 0 \
		"Syslog-Port  (default 514)" 6 1 "" 6 30 28 0 \
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
	SYSLOG=${RESULT[4]}
	SYSPORT=${RESULT[5]}
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
client_max_body_size 0;
large_client_header_buffers 4 16k;
EOL
	chmod 0644 /etc/nginx/conf.d/99-buffer-policy.conf
	cat >/etc/nginx/conf.d/99-xss.conf <<EOL
#add_header X-XSS-Protection "1; mode=block";
#add_header X-Frame-Options "SAMEORIGIN";
#add_header Strict-Transport-Security "max-age=31536000; includeSubdomains; preload";
#add_header Content-Security-Policy "default-src 'self' http: https: data: blob: 'unsafe-inline'" always;
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
 * ${DOMAIN}.pfx
 * (or alternatively ${DOMAIN}.pem and ${DOMAIN}.key)
# pscp ${DOMAIN}.* reverse@A.B.C.D:/home/${USER1000}/

2. Install as user reverse:
\$ cd /home/${USER1000}
\$ ./install_cert.sh


Upgrade the system manually from time to time:
-------------------------------------
\$ apt update
\$ apt upgrade
\$ apt full-upgrade
\$ apt autoremove

Have fun...
EOL
}

function prepare_cert_copy() {
	cat >/home/${USER1000}/install_cert.sh <<EOL
#!/bin/bash
DOMAIN="${DOMAIN}"

PFX=\`ls -a *.pfx | head -1\`
if [ ! -z "\${PFX}" ]; then
  echo "Found the following:"
  echo "     pfx: \${PFX}"
  echo "If this in not the correct one, press ctrl+c and upload the correct one."
  read _TMP

  openssl pkcs12 -in \${PFX} -nokeys -out \${DOMAIN}.pem
  if [ "$?" != "0" ]; then exit 1; fi
  openssl pkcs12 -in \${PFX} -nocerts -out \${DOMAIN}.key -nodes
  if [ "$?" != "0" ]; then exit 1; fi
fi

PEM=\`ls -a *.pem | head -1\`
KEY=\`ls -a *.key | head -1\`

echo "Found the following:"
echo "     pem: \${PEM}"
echo "     key: \${KEY}"
echo "If these are NOT the correct files, press CTRL+c and remove all pem and key files which are irrelevant."
read _TMP

chmod 0600 \${DOMAIN}.*
sudo chown root.root \${DOMAIN}.*
sudo mv \${DOMAIN}.* ${NGINX_CERT_PATH}/
sudo systemctl restart nginx
EOL
	chown reverse /home/${USER1000}/install_cert.sh
	chmod 0700 /home/${USER1000}/install_cert.sh
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
	#server_name ${DOMAIN};

        location = /+ { rewrite ^ https://\$server_name\$request_uri? permanent; }
        location /nginx_status { stub_status; allow 127.0.0.1; deny all; }
}
server {
	listen 443 ssl default_server;
	listen [::]:443 ssl default_server;
	#server_name ${DOMAIN};

	gzip off;
	ssl_certificate ${NGINX_CERT_PATH}/${DOMAIN}.pem;
	ssl_certificate_key ${NGINX_CERT_PATH}/${DOMAIN}.key;
	ssl_session_timeout 5m;

	proxy_http_version 1.1;
	proxy_read_timeout 360;

	proxy_cache_bypass \$http_upgrade;
	proxy_set_header Upgrade \$http_upgrade;

	more_set_input_headers "Authorization: \$http_authorization";
	more_set_headers -s 401 'WWW-Authenticate: Basic realm="\$host"';

	proxy_set_header Connection keep-alive;
	proxy_set_header Host \$host;
	proxy_set_header X-Real-IP \$remote_addr;
	proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
	proxy_set_header X-Forwarded-Proto \$scheme;

	location / { rewrite ^ https://\$host/owa permanent; }

        # CVE-2022-41040, CVE-2022-41082
        location ~* autodiscover.*powershell { return 403; }

	# Outlook Webaccess
	location /owa { proxy_pass https://${EXCHANGE}/owa; }
	location /OWA { proxy_pass https://${EXCHANGE}/owa; }

	# ExchangeWebServices for Office-365 Hybrid integrations
	location /ews { proxy_pass https://${EXCHANGE}/EWS; }
	location /EWS { proxy_pass https://${EXCHANGE}/EWS; }

	# MAPI for Outlook sync and Mobile-Apps
	location /mapi { proxy_pass https://${EXCHANGE}/mapi; }
	location /MAPI { proxy_pass https://${EXCHANGE}/mapi; }

	# Autodiscover configuration
	location /autodiscover { proxy_pass https://${EXCHANGE}/autodiscover; }
	location /Autodiscover { proxy_pass https://${EXCHANGE}/Autodiscover; }

	# ActiveSync for some Mobile-Apps
	location /Microsoft-Server-ActiveSync { proxy_pass https://${EXCHANGE}/Microsoft-Server-ActiveSync; }
	location /rpc/rpcproxy.dll { proxy_pass https://${EXCHANGE}/rpc/rpcproxy.dll; }

	# 2FA from DUO or any other
        location /duo { proxy_pass https://${EXCHANGE}/duo; }
}
EOL

	rm /etc/nginx/modules-enabled/*
	ln -s /usr/share/nginx/modules-available/mod-http-headers-more-filter.conf /etc/nginx/modules-enabled/50-mod-http-headers-more-filter.conf

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
prepare_cert_copy
enable_services
passwords

dialog --backtitle "${TITLE//TITLE/Finished}" \
  --title "Finished" \
  --msgbox "The System is configured with your given values and hardened as much as possible.\n\nThere is some basic network blocking and regulation, a firewall blocking all except HTTP and HTTPS and finally an NGINX reverse Proxy redirection from HTTP to HTTPS and only with the most secure TLS-Versions and ciphers enabled.\n\nBe sure there is ${DOMAIN}.key and ${DOMAIN}.crt in place under ${NGINX_CERT_PATH}" \
  18 50

clear

exit 0
