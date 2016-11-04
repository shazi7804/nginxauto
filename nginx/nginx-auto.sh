#!/bin/bash
#
# Program: Nginx install
# Author: scott
# Github: https://github.com/shazi7804
trap 'stop' SIGUSR1 SIGINT SIGHUP SIGQUIT SIGTERM SIGSTOP

Config="auto.conf"
WorkPath="/usr/local/src"

stop() {
	exit 0
}

welcome(){
	echo ""
	echo "Welcome to the nginx automatic installation"
	echo ""
	echo "Nginx installation is starting"
	echo ""
	echo "Nginx version: $NginxVer"
	if [[ "1" == $OpenSSL ]]; then
		echo "SSL: OpenSSL $OpenSSLVer"
	elif [[ "1" == $LibreSSL ]]; then
		echo "SSL: LibreSSL $LibreSSLVer"
	else
		echo "SSL: OpenSSL `openssl version | awk -F" " '{print $2}'`"
	fi

	if [[ "1" == $Headers ]]; then
		echo "Headers: $HeadersVer"
	fi

	if [[ "1" == $PageSpeed ]]; then
		echo "PageSpeed: $NPSVer"
	fi

	echo ""
}

helpmsg() {
	echo ""
	echo "Usage: $0 [option] [values]"
	echo ""
	echo "option:"
	echo ""
	echo "	install		Install nginx service"
	echo "	uninstall	Uninstall nginx service"
	echo "	-c		config file source"
	echo ""
}

WorkingStatus() {
	local rest green red status message
	rest='\033[0m'
	green='\033[033;32m'
	red='\033[033;31m'
	
	status=$1
	shift
	message=$@

	if [[ "OK" == $status ]]; then
		echo -ne "$message  [${green}OK${rest}]\r"
		echo -ne "\n"
	elif [[ "Fail" == $status ]]; then
		echo -ne "$message  [${green}Fail${rest}]"
		exit 1
	elif [[ "Process" == $status ]]; then
		echo -ne "$message  [..]\r"
	fi
}

Dependencies(){
	local dep
	WorkingStatus Process "Verify dependencies"
	dep="wget git tar git autoconf gcc gcc-c++ make zlib-devel pcre-devel openssl-devel libxml2 libxslt-devel gd-devel geoipupdate perl-devel perl-ExtUtils-Embed"
	if rpm -q $dep &>/dev/null; then
		WorkingStatus OK "Verify dependencies"
	else
		yum install -y $dep &>/dev/null
		if [ $? -eq 0 ]; then
			WorkingStatus OK "Verify dependencies"
		else
			WorkingStatus Fail "Verify dependencies"
		fi
	fi
}

NginxInstall() {
	WorkingStatus Process "Downloading nginx"
	wget -q http://nginx.org/download/nginx-${NginxVer}.tar.gz -P ${WorkPath} -c
	tar zxf ${WorkPath}/nginx-${NginxVer}.tar.gz -C ${WorkPath}/
	if [ $? -eq 0 ]; then
		WorkingStatus OK "Downloading nginx"
	else
		WorkingStatus Fail "Downloading nginx"
	fi

	# Get nginx config
	if [[ ! -e /etc/nginx/nginx.conf ]]; then
		WorkingStatus Process "Downloading nginx.conf"
		mkdir -p /etc/nginx
		if [[ ! -e ./conf/nginx.conf ]]; then
			wget -q https://raw.githubusercontent.com/shazi7804/auto-install/master/nginx/conf/nginx.conf -P /etc/nginx/ -c
		else
			cp ./conf/{nginx,expire}.conf ./conf/user-agent.rules /etc/nginx/
		fi
		if [[ $? -eq 0 ]]; then
			WorkingStatus OK "Downloading nginx.conf"
		else
			WorkingStatus Fail "Downloading nginx.conf"
		fi
	fi

	# Configuration
	WorkingStatus Process "Configuring nginx"
	cd ${WorkPath}/nginx-${NginxVer}
	./configure ${NginxConfiguration} ${NginxModules} &>/dev/null
	if [[ $? -eq 0 ]]; then
		WorkingStatus OK "Configuring nginx"
	else
		WorkingStatus Fail "Configuring nginx"
	fi

	# Compile
	WorkingStatus Process "Compiling nginx"
	make -j $(nproc) &>/dev/null
	if [[ $? -eq 0 ]]; then
		WorkingStatus OK "Compiling nginx"
	else
		WorkingStatus Fail "Compiling nginx"
	fi

	# Install
	WorkingStatus Process "Installing nginx"
	make install &>/dev/null
	if [[ $? -eq 0 ]]; then
		WorkingStatus OK "Installing nginx"
	else
		WorkingStatus Fail "Installing nginx"
	fi

	# remove debugging symbols
	strip -s /usr/sbin/nginx

	# Logrotate
	if [[ ! -e /etc/logrotate.d/nginx ]]; then
		cp ${Root}/conf/nginx.logrotate /etc/logrotate.d/nginx
		if [[ $? -ne 0 ]]; then
			wget -q https://raw.githubusercontent.com/shazi7804/auto-install/master/nginx/conf/nginx.logrotate -P /etc/logrotate.d -c
		fi
	fi

	# boot service
	if [[ ! -e /etc/init.d/nginx ]]; then
		cp ${Root}/conf/nginx.service /etc/init.d/nginx
		if [[ $? -ne 0 ]]; then
			wget -q https://raw.githubusercontent.com/shazi7804/auto-install/master/nginx/conf/nginx.service -P /etc/init.d -c
		fi
	fi
	if [[ ! -x /etc/init.d/nginx ]]; then
		chmod +x /etc/init.d/nginx
	fi

	# default create cache directory
	if [[ ! -d /var/cache/nginx ]]; then
		mkdir -p /var/cache/nginx
	fi

	if ! id nginx &> /dev/null ; then
		adduser nginx -M	
	fi

	# init default file
	find /etc/nginx -type f -iname "*.default" -delete &> /dev/null

	if [[ -d /etc/nginx/html ]]; then
		rm -r /etc/nginx/html
	fi

	if [[ ! -d /etc/nginx/conf.d ]]; then
		mkdir /etc/nginx/conf.d
	fi
	
	if ! ls -A /etc/nginx/conf.d &>/dev/null; then
		cd $Root
		cp conf/server.conf /etc/nginx/conf.d/0.conf	
	fi

	# Restart service
	WorkingStatus Process "Restart service"
	service nginx restart &>/dev/null
	if [[ $? -eq 0 ]]; then
		WorkingStatus OK "Restart service"
		echo ""
		echo "Installation successful !! You can enjoy the service."
		echo ""
	else
		WorkingStatus Fail "Restart service"
	fi
}


AddModules() {
	# PageSpeed
	if [[ "1" == $PageSpeed ]]; then
		WorkingStatus Process "Downloading ngx_pagespeed"
		# Upgrade gcc+ 4.8
		if ! rpm -q devtoolset-2-gcc-c++ devtoolset-2-binutils &>/dev/null; then
			rpm --import http://ftp.scientificlinux.org/linux/scientific/5x/x86_64/RPM-GPG-KEYs/RPM-GPG-KEY-cern
			wget -q -O /etc/yum.repos.d/slc6-devtoolset.repo http://linuxsoft.cern.ch/cern/devtoolset/slc6-devtoolset.repo -c
			yum install -y devtoolset-2-gcc-c++ devtoolset-2-binutils >&/dev/null			
		fi
		
		wget -q https://github.com/pagespeed/ngx_pagespeed/archive/release-${NPSVer}-beta.zip -P ${WorkPath} -c
		wait
		unzip -q -o ${WorkPath}/release-${NPSVer}-beta.zip -d ${WorkPath}
		wait
		wget -q https://dl.google.com/dl/page-speed/psol/${NPSVer}.tar.gz -P ${WorkPath}/ngx_pagespeed-release-${NPSVer}-beta -c
		wait
		tar -xzf ${WorkPath}/ngx_pagespeed-release-${NPSVer}-beta/${NPSVer}.tar.gz -C ${WorkPath}/ngx_pagespeed-release-${NPSVer}-beta
		if [[ $? -eq 0 ]]; then
			WorkingStatus OK "Downloading ngx_pagespeed"
		else
			WorkingStatus Fail "Downloading ngx_pagespeed"
		fi
		NginxModules=$(echo $NginxModules; echo "--add-module=${WorkPath}/ngx_pagespeed-release-${NPSVer}-beta --with-cc=/opt/rh/devtoolset-2/root/usr/bin/gcc")
	fi

	# Brotli
	if [[ "1" == $Brotli ]]; then
		WorkingStatus Process "Downloading libbrotli"
		if ! rpm -q libtool autoconf automake &>/dev/null; then
			yum install -y libtool autoconf automake &>/dev/null
		fi
		cd ${WorkPath}
		git clone https://github.com/bagder/libbrotli &>/dev/null
		if [[ $? -eq 0 ]]; then
			WorkingStatus OK "Downloading libbrotli"
		else
			WorkingStatus Fail "Downloading libbrotli"
		fi

		cd libbrotli
		WorkingStatus Process "Configuring libbrotli"
		./autogen.sh &>/dev/null
		./configure &>/dev/null
		if [[ $? -eq 0 ]]; then
			WorkingStatus OK "Configuring libbrotli"
		else
			WorkingStatus Fail "Configuring libbrotli"
		fi

		WorkingStatus Process "Compiling libbrotli"
		make -j $(nproc) &>/dev/null
		if [[ $? -eq 0 ]]; then
			WorkingStatus OK "Compiling libbrotli"
		else
			WorkingStatus Fail "Compiling libbrotli"
		fi

		WorkingStatus Process "Installing libbrotli"
		make install &>/dev/null
		if [[ $? -eq 0 ]]; then
			WorkingStatus OK "Installing libbrotli"
		else
			WorkingStatus Fail "Installing libbrotli"
		fi

		# Linking libraries to avoid errors
		if [[ ! -f /lib64/libbrotlienc.so.1 ]]; then
    		ln -s /usr/local/lib/libbrotlienc.so.1 /lib64
    	fi
		ldconfig &>/dev/null

		# ngx_brotli module
		cd ${WorkPath}
		WorkingStatus Process "Downloading ngx_brotli"
		git clone https://github.com/google/ngx_brotli &>/dev/null
		if [[ $? -eq 0 ]]; then
			WorkingStatus OK "Downloading ngx_brotli"
		else
			WorkingStatus Fail "Downloading ngx_brotli"
		fi
		NginxModules=$(echo $NginxModules; echo "--add-module=/usr/local/src/ngx_brotli")
	fi

	# More Headers
	if [[ "1" == $Headers ]]; then
		WorkingStatus Process "Downloading ngx_headers_more"
		wget -q https://github.com/openresty/headers-more-nginx-module/archive/v${HeadersVer}.tar.gz -P ${WorkPath}
		tar -xzf v${HeadersVer}.tar.gz
		if [[ $? -eq 0 ]]; then
			WorkingStatus OK "Downloading ngx_headers_more"
		else
			WorkingStatus Fail "Downloading ngx_headers_more"
		fi
		NginxModules=$(echo $NginxModules; echo "--add-module=/usr/local/src/headers-more-nginx-module-${HeadersVer}")
	fi

	# GeoIP
	if [[ "1" == $GeoIP ]]; then
		WorkingStatus Process "Downloading GeoIP databases"
		if ! rpm -q GeoIP-devel &>/dev/null; then
			if ! yum repolist | grep epel &>/dev/null ; then
				 rpm -ivh https://dl.fedoraproject.org/pub/epel/epel-release-latest-6.noarch.rpm &>/dev/null
			fi
			yum install -y GeoIP-devel --enablerepo=epel &>/dev/null
		fi

		if [[ ! -d $GeoIP_dat ]]; then
			mkdir -p $GeoIP_dat
		fi
		cd $GeoIP_dat
		wget -q http://geolite.maxmind.com/download/geoip/database/GeoLiteCountry/GeoIP.dat.gz
		wget -q http://geolite.maxmind.com/download/geoip/database/GeoLiteCity.dat.gz
		gunzip -f GeoIP.dat.gz
		gunzip -f GeoLiteCity.dat.gz
		if [[ $? -eq 0 ]]; then
			WorkingStatus OK "Downloading GeoIP databases"
		else
			WorkingStatus Fail "Downloading GeoIP databases"
		fi
		NginxModules=$(echo $NginxModules; echo "--with-http_geoip_module")
	fi

	# LibreSSL
	if [[ "1" == $LibreSSL ]]; then
		WorkingStatus Process "Downloading LibreSSL"
		wget -q http://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-${LibreSSLVer}.tar.gz -P ${WorkPath}
		tar -xzf ${WorkPath}/libressl-${LibreSSLVer}.tar.gz -C ${WorkPath}
		if [[ $? -eq 0 ]]; then
			WorkingStatus OK "Downloading LibreSSL"
		else
			WorkingStatus Fail "Downloading LibreSSL"
		fi

		WorkingStatus Process "Configuring LibreSSL"
		cd ${WorkPath}/libressl-${LibreSSLVer}
		./configure \
			LDFLAGS=-lrt \
			--prefix=/usr/local/src/libressl-${LibreSSLVer}/.openssl/ \
			--enable-shared=no &>/dev/null
		if [[ $? -eq 0 ]]; then
			WorkingStatus OK "Configuring LibreSSL"
		else
			WorkingStatus Fail "Configuring LibreSSL"
		fi

		WorkingStatus Process "Installing LibreSSL"
		make install-strip -j $(nproc) &>/dev/null
		if [[ $? -eq 0 ]]; then
			WorkingStatus OK "Installing LibreSSL"
		else
			WorkingStatus Fail "Installing LibreSSL"
		fi
		NginxModules=$(echo $NginxModules; echo "--with-openssl=/usr/local/src/libressl-${LibreSSLVer}")
	fi

	# OpenSSL
	if [[ "1" == $OpenSSL ]]; then
		WorkingStatus Process "Downloading OpenSSL"
		wget -q https://www.openssl.org/source/openssl-${OpenSSLVer}.tar.gz -P ${WorkPath}
		tar -xzf ${WorkPath}/openssl-${OpenSSLVer}.tar.gz -C ${WorkPath}
		cd ${WorkPath}/openssl-${OpenSSLVer}
		if [[ $? -eq 0 ]]; then
			WorkingStatus OK "Downloading OpenSSL"
		else
			WorkingStatus Fail "Downloading OpenSSL"
		fi

		# Cloudflare Patch support ChaCha20-Poly1305
		if [[ "1" == $Chacha ]]; then
			wget -q https://raw.githubusercontent.com/cloudflare/sslconfig/master/patches/openssl__chacha20_poly1305_draft_and_rfc_ossl102g.patch -O ${WorkPath}/chacha.patch -c &>/dev/null 
			patch -p1 < ${WorkPath}/chacha.patch &>/dev/null
			if [[ $? -eq 0 ]]; then
		 		WorkingStatus OK "Adding ChaCha to OpenSSL"
		 	else
		 		WorkingStatus Fail "Adding ChaCha to OpenSSL"
			fi 
		fi

		WorkingStatus Process "Configuring OpenSSL"
		./config &>/dev/null
		if [[ $? -eq 0 ]]; then
			WorkingStatus OK "Configuring OpenSSL"
		else
			WorkingStatus Fail "Configuring OpenSSL"
		fi
		NginxModules=$(echo $NginxModules; echo "--with-openssl=/usr/local/src/openssl-${OpenSSLVer}")
	fi
}

NginxUninstall() {
	echo ""
	echo "Welcome to the nginx automatic Uninstallation"
	echo ""
	echo "Nginx uninstall is starting"
	echo ""
	WorkingStatus Process "Nginx service stoping"
	if [[ $? -eq 0 ]]; then
		WorkingStatus OK "Nginx service stoping"
	else
		WorkingStatus Fail "Nginx service stoping"
	fi

	# remove all config
	WorkingStatus Process "Remove nginx env"
	rm -r /usr/sbin/nginx \
		/etc/logrotate.d/nginx \
		/etc/init.d/nginx \
		/var/cache/nginx \
		/var/log/nginx &>/dev/null
	WorkingStatus OK "Remove nginx env"
	
	WorkingStatus Process "Remove nginx config"
	rm -r /etc/nginx &>/dev/null
	if [[ $? -eq 0 ]]; then
		WorkingStatus OK "Remove nginx config"
	else
		WorkingStatus Fail "Remove nginx config"
	fi

	echo ""
	echo "Uninstallation successful !!"
	echo ""
}


Root=$(pwd)
if [[ $# -gt 0 ]]; then
	for opt in $@
	do
		case $opt in
			install)
				shift
				if [[ -f $Config ]]; then
					source $Root/$Config >&/dev/null
					welcome
					Dependencies
					AddModules
					NginxInstall
				else
					echo "Warning: Config $Config file not found"
					exit 1
				fi
				;;
			uninstall)
				shift
				NginxUninstall
				;;
			-c)
				shift
				Config=$1
				;;
			-h|--help|*)
				helpmsg
				;;
		esac
	done
else
	helpmsg
fi








