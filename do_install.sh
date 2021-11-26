#!/bin/bash

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
DOMAIN=""
EXCHANGE=""
OWA=""

function install_and_cleanup() {
	apt remove openssh-server task-ssh-server openssh-client telnet usbutils xauth reportbug
	apt autoremove
	apt install nftables nginx-light ufw
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
	mkdir /root/certs

	systemctl enable nftables
	systemctl enable nginx
	ufw allow 'Nginx HTTPS'
	systemctl enable ufw
}

FIFO=/tmp/`tr -dc A-Za-z0-9 </dev/urandom | head -c 8`
function read_base_data() {
	dialog \
		--backtitle "${TITLE//TITLE/Configuration}" \
		--title "Configuration" \
		--form "Please enter all values" 20 65 0 \
		"Hostname  (of the Proxy)" 1 1 "" 1 30 28 0 \
		"Domain   (External FQDN)" 2 1 "" 2 30 28 0 \
		"Exchange (Internal FQND)" 3 1 "" 3 30 28 0 \
		"OWA-Path on the Exchange" 4 1 "" 4 30 28 0 \
		--output-fd 1 &>${FIFO}
	if [ $? == 1 ]; then
		echo -e "\nAborted...\n\n"
		exit 1
	fi

	RESULT=(`cat ${FIFO}`)
	rm ${FIFO}
	HOSTNAME=${RESULT[0]}
	DOMAIN=${RESULT[1]}
	EXCHANGE=${RESULT[2]}
	OWA=${RESULT[3]}
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
}

function configure_nginx_proxy() {
	cat >/etc/nginx/sites-available/default <<EOL
server {
	listen 80 default_server;
	listen[::]:80 default_server;
	server_name ${DOMAIN};
	rewrite ^ https://\$server_name\$request_uri? permanent;
}
server {
	listen 443 ssl default_server;
	listen [::]:443 ssl default_server;

	gzip off;
	ssl on;
	ssl_certificate /root/certs/${DOMAIN}.crt;
	ssl_certificate_key /root/certs/${DOMAIN}.key;
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
}

install_and_cleanup
read_base_data
harden_system
clean_nginx_installation
configure_nginx_proxy
enable_services

dialog --backtitle "${TITLE//TITLE/Finished}" \
  --title "Finished" \
  --msgbox "The System is configured with your given values and hardened as much as possible.\n\nThere is some basic network blocking and regulation, a firewall blocking all except HTTP and HTTPS and finally an NGINX reverse Proxy redirection from HTTP to HTTPS and only with the most secure TLS-Versions and ciphers enabled.\n\nBe sure there is ${DOMAIN}.key and ${DOMAIN}.crt in place under /root/certs/" \
  18 50

clear

exit 0
