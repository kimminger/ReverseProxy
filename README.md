# ReverseProxy

Easily harden a debian minimalistic installation and configure a nginx to redirect all traffic to an internal webserver.

* Download (64-bit PC netinst iso)[https://www.debian.org/distrib/]
* Install in a new VM _(**Do not install anything**, just the base system, no X-Server, no SSH-Server. Uncheck everything except the base system and tools.)_
* Copy the script do_install.sh to /root/
* Run the script
* Restart the VM


## Hardend Nginx

The nginx configuration is changed and extended to be as save as possible. There is no information propagation and no modules loaded.

The main traffic on HTTP is redirected to HTTPS and only the most recommended ciphers are allowed.

## Hardend Openssh

Only the most recommended Ciphers, MACs and KexAlgorithms are allowed. Also some other basic best practices are configured.

## Hardend Linux

Some basic regulations on the network configuration, remote syslog and a simple firewall is configured. Beside this, SSH is only allowed from the internal network and the system is being udated automatically every night.

