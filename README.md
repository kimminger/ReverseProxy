# ReverseProxy

Easily harden a debian minimalistic installation and configure a nginx to redirect all traffic to an internal webserver.

* Download (64-bit PC netinst iso)[https://www.debian.org/distrib/]
* Install in a new VM _(**Do not install anything**, just the base system, no X-Server, no SSH-Server. Uncheck everything except the base system and tools.)_
* Copy the script do_install.sh to /root/
* Run the script
* Restart the VM

For this to work with Exchange, you have to enable **Basic-Authentication** on all the Exchange URL's.
In particular for OWA, EWS, MAPI and Autodiscover. In this setup we support OutlookWebAccess (OWA) but also Teams in Office365 and Outlook-Clients and ActiveSync clients as well. If you not need one of them, you should disable them in the nginx proxy configuration.

## Hardend Linux

Some basic regulations on the network configuration, remote syslog and a simple firewall is configured. Beside this, SSH is only allowed from the internal network and the system is being udated automatically every night.

## Hardend Openssh

Only the most recommended Ciphers, MACs and KexAlgorithms are allowed. Also some other basic best practices are configured.

## Hardend Nginx

The nginx configuration is changed and extended to be as save as possible. There is no information propagation and no modules loaded.

The main traffic on HTTP is redirected to HTTPS and only the most recommended ciphers are allowed.

### Most important settings

Generally we turn off the server tokens and gzip (due to SSL) and disable all insecure SSL-Protocols.
For Exchange we have to allow unlimitted client body size (this is unsecure but needed) `[client_max_body_size 0]` and also we have to allow big header values `[large_client_header_buffers 4 32k]`.
```
server_tokens off;
gzip off;

ssl_protocols TLSv1.2 TLSv1.3 ; # Dropping SSLv3, ref POODLE, TLSv1.0 and TLSv1.1
ssl_prefer_server_ciphers on;

client_body_buffer_size 1k;
client_header_buffer_size 1k;

client_max_body_size 0;
large_client_header_buffers 4 32k;
```

For the virtual host we use a default SSL-Configuration and HTTP -> HTTPS Redirection.
To passthrough the client authenticatione to Exchange, we have to enforce Basic-Authentication in case we receive a `401 Unauthorized` from Exchange.
Also we disable caching and passthrough some client values as headers.
Finally we have to redirect any combination of URLs (upper and lowercase) to the internal Exchange server.

```
server {
	listen 80 default_server;
	listen [::]:80 default_server;
	server_name DOMAIN.TLD;

	rewrite ^ https://$server_name$request_uri? permanent;
}

server {
	listen 443 ssl default_server;
	listen [::]:443 ssl default_server;
	server_name DOMAIN.TLD;

	ssl_certificate /etc/nginx/certs/DOMAIN.TLD.pem;
	ssl_certificate_key /etc/nginx/certs/DOMAIN.TLD.key;
	ssl_session_timeout 5m;

	proxy_http_version 1.1;
	proxy_read_timeout 360;

	proxy_cache_bypass $http_upgrade;
	proxy_set_header Upgrade $http_upgrade;

	more_set_input_headers "Authorization: $http_authorization";
	more_set_headers -s 401 'WWW-Authenticate: Basic realm="DOMAIN.TLD"';

	proxy_set_header Connection keep-alive;
	proxy_set_header Host $host;
	proxy_set_header X-Real-IP $remote_addr;
	proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
	proxy_set_header X-Forwarded-Proto $scheme;

	location / { rewrite ^ https://$server_name/owa permanent; }

	# Outloo WebAccess
	location /owa { proxy_pass https://INT.EXCH.IP.ADDR/owa; }
	location /OWA { proxy_pass https://INT.EXCH.IP.ADDR/owa; }

	# Office365 integration (Exchange Webservice)
	location /ews { proxy_pass https://INT.EXCH.IP.ADDR/EWS; }
	location /EWS { proxy_pass https://INT.EXCH.IP.ADDR/EWS; }

	# Outlook clients and others (Microsoft API)
	location /mapi { proxy_pass https://INT.EXCH.IP.ADDR/mapi; }
	location /MAPI { proxy_pass https://INT.EXCH.IP.ADDR/mapi; }
	location /rpc/rpcproxy.dll { proxy_pass https://INT.EXCH.IP.ADDR/rpc/rpcproxy.dll; }

	# Autoconfiguration for Outlook and others
	location /Autodiscover { proxy_pass https://INT.EXCH.IP.ADDR/Autodiscover; }
	location /autodiscover { proxy_pass https://INT.EXCH.IP.ADDR/autodiscover; }

	# ActiveSync Clients - mostly mobile apps
	location /Microsoft-Server-ActiveSync { proxy_pass https://INT.EXCH.IP.ADDR/Microsoft-Server-ActiveSync; }
}
```
