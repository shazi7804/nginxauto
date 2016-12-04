#!/bin/bash
#
# Program: Nginx install
# Author: scott
# Github: https://github.com/shazi7804
Config="auto.conf"
WorkPath="/tmp/nginxauto-$RANDOM-tmp" # build directory

# Choose your SSL implementation default use system openssl
# Google Chrome 51 removed SPDY as scheduled, but also removed NPN support.
# if the web server does not support ALPN, Chrome will not use HTTP2 when browsing your site.
# Currently OpenSSL must support at least 1.0.2 ALPN. (CentOS 6 default 1.0.1 max)
# You can try to choose
# ***LibreSSL     Maintains LibreSSL from OpenBSD.
# ***OpenSSL      Cloudflare patch version.
# ***BoringSSL    BoringSSL is a fork of OpenSSL that is designed to meet Google's needs.
OpenSSLVer="1.0.2j"
LibreSSLVer="2.4.2"


trap 'stop' SIGUSR1 SIGINT SIGHUP SIGQUIT SIGTERM SIGSTOP

stop() {
	exit 0
}

Welcome() {
	echo ""
	echo "Welcome to the nginx automatic installation"
	echo ""
	echo "Nginx installation is starting"
	echo ""
	echo "Nginx version: $NginxVer"
	if [[ "1" == $OpenSSL ]]; then
		echo "SSL: OpenSSL $OpenSSLVer with Cloudflare Patch support ChaCha20-Poly1305"
	elif [[ "1" == $LibreSSL ]]; then
		echo "SSL: LibreSSL $LibreSSLVer"
	elif [[ "1" == $BoringSSL ]]; then
		echo "SSL: BoringSSL"
	else
		echo "SSL: OpenSSL $(openssl version | awk -F" " '{print $2}')"
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
	echo "Usage: $0 [option]"
	echo ""
	echo "option:"
	echo "  install      Install nginx service."
	echo "  uninstall    Uninstall nginx service."
	echo "  -c           config file source."
	echo ""
	echo "SSL option: (default system openssl $(openssl version| awk -F" " '{print $2}'))"
	echo "  --openssl    Compile OpenSSL $OpenSSLVer with ChaCha20-Poly1305."
	echo "  --libressl   Compile LibreSSL $LibreSSLVer."
	echo "  --boringssl  Compile BoringSSL fork of OpenSSL that is designed to meet Google's needs."
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

	# Get nginx config: nginx.conf
	#					expire.conf
	#					user-agent.rules
	if [[ ! -e /etc/nginx/nginx.conf ]]; then
		WorkingStatus Process "Downloading nginx config"
		mkdir -p /etc/nginx
		if [[ ! -e ${SourceRoot}/conf/nginx.conf ]]; then
			wget -q https://raw.githubusercontent.com/shazi7804/nginxauto/master/conf/{{nginx,expire}.conf,user-agent.rules} -P /etc/nginx/ -c
		else
			cp ${SourceRoot}/conf/{{nginx,expire}.conf,user-agent.rules} /etc/nginx/
		fi
		if [[ $? -eq 0 ]]; then
			WorkingStatus OK "Downloading nginx config"
		else
			WorkingStatus Fail "Downloading nginx config"
		fi
	fi

	# Get ngx_pagespeed config
	if [[ "1" == $PageSpeed ]]; then
		WorkingStatus Process "Downloading ngx_pagespeed config"
		if [[ ! -e ${SourceRoot}/conf/ngx_pagespeed.conf ]]; then
			wget -q https://raw.githubusercontent.com/shazi7804/nginxauto/master/conf/ngx_pagespeed.conf -P /etc/nginx/ -c
		else
			cp ${SourceRoot}/conf/ngx_pagespeed.conf /etc/nginx/
		fi
		if [[ $? -eq 0 ]]; then
			WorkingStatus OK "Downloading ngx_pagespeed config"
		else
			WorkingStatus Fail "Downloading ngx_pagespeed config"
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

	# update timestamp so nginx won't try to build openssl
	if [[ "1" == $BoringSSL ]]; then
		touch ${WorkPath}/boringssl/.openssl/include/openssl/ssl.h
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
		cp ${SourceRoot}/conf/nginx.logrotate /etc/logrotate.d/nginx
		if [[ $? -ne 0 ]]; then
			wget -q https://raw.githubusercontent.com/shazi7804/nginxauto/master/conf/nginx.logrotate -P /etc/logrotate.d -c
		fi
	fi

	# boot service
	if [[ ! -e /etc/init.d/nginx ]]; then
		cp ${SourceRoot}/conf/nginx.service /etc/init.d/nginx
		if [[ $? -ne 0 ]]; then
			wget -q https://raw.githubusercontent.com/shazi7804/nginxauto/master/conf/nginx.service -P /etc/init.d -c
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
	
	# create example config
	if ! ls -A /etc/nginx/conf.d &>/dev/null; then
		cp ${SourceRoot}/conf/example-config/server.conf /etc/nginx/conf.d/0-server.conf	
	fi

	# Restart service
	WorkingStatus Process "Restart service"
	service nginx restart &>/dev/null
	if [[ $? -eq 0 ]]; then
		WorkingStatus OK "Restart service"
		# Clean install package 
		rm -r ${WorkPath}
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

		# Upgrade gcc+ 4.8
		if [ ! -e /opt/rh/devtoolset-2/root/usr/bin/gcc ] || [ ! -e /opt/rh/devtoolset-2/root/usr/bin/c++ ]; then
			WorkingStatus Process "Building gcc4.8+"
			rpm --import http://ftp.scientificlinux.org/linux/scientific/5x/x86_64/RPM-GPG-KEYs/RPM-GPG-KEY-cern
			wget -q -O /etc/yum.repos.d/slc6-devtoolset.repo http://linuxsoft.cern.ch/cern/devtoolset/slc6-devtoolset.repo -c
			yum install -y devtoolset-2-gcc-c++ devtoolset-2-binutils >&/dev/null
			if [[ $? -eq 0 ]]; then
				mv /usr/bin/gcc /usr/bin/gcc.default && mv /usr/bin/c++ /usr/bin/c++.default
				ln -fs /opt/rh/devtoolset-2/root/usr/bin/gcc /usr/bin/gcc && ln -fs /opt/rh/devtoolset-2/root/usr/bin/c++ /usr/bin/c++
				WorkingStatus OK "Building gcc4.8+"
			else
				WorkingStatus Fail "Building gcc4.8+"
			fi
		fi
		NginxModules=$(echo $NginxModules; echo "--add-module=${WorkPath}/ngx_pagespeed-release-${NPSVer}-beta --with-cc=/opt/rh/devtoolset-2/root/usr/bin/gcc")
	fi

	# Brotli
	if [[ "1" == $Brotli ]]; then
		WorkingStatus Process "Downloading libbrotli"
		if ! rpm -q libtool autoconf automake &>/dev/null; then
			yum install -y libtool autoconf automake &>/dev/null
		fi

		if [[ -d ${WorkPath}/libbrotli ]]; then
			rm -r ${WorkPath}/libbrotli
		fi

		if [[ -e ${WorkPath}/libbrotli ]]; then
			cd ${WorkPath}/libbrotli
			git fetch && git pull
		else
			git clone https://github.com/bagder/libbrotli "${WorkPath}/libbrotli" &>/dev/null
		fi
		
		if [[ $? -eq 0 ]]; then
			WorkingStatus OK "Downloading libbrotli"
		else
			WorkingStatus Fail "Downloading libbrotli"
		fi

		cd ${WorkPath}/libbrotli
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
		WorkingStatus Process "Downloading ngx_brotli"
		
		if [[ -d ${WorkPath}/ngx_brotli ]]; then
			rm -r ${WorkPath}/ngx_brotli
		fi

		if [[ -e ${WorkPath}/ngx_brotli ]]; then
			cd ${WorkPath}/ngx_brotli
			git fetch && git pull
		else
			git clone https://github.com/google/ngx_brotli "${WorkPath}/ngx_brotli" &>/dev/null
		fi

		if [[ $? -eq 0 ]]; then
			WorkingStatus OK "Downloading ngx_brotli"
		else
			WorkingStatus Fail "Downloading ngx_brotli"
		fi
		NginxModules=$(echo $NginxModules; echo "--add-module=${WorkPath}/ngx_brotli")
	fi

	# More Headers
	if [[ "1" == $Headers ]]; then
		WorkingStatus Process "Downloading ngx_headers_more"
		wget -q https://github.com/openresty/headers-more-nginx-module/archive/v${HeadersVer}.tar.gz -P ${WorkPath} -c
		tar -xzf ${WorkPath}/v${HeadersVer}.tar.gz -C ${WorkPath}
		if [[ $? -eq 0 ]]; then
			WorkingStatus OK "Downloading ngx_headers_more"
		else
			WorkingStatus Fail "Downloading ngx_headers_more"
		fi
		NginxModules=$(echo $NginxModules; echo "--add-module=${WorkPath}/headers-more-nginx-module-${HeadersVer}")
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

	# BoringSSL with go (Google)
	if [[ "1" == $BoringSSL ]]; then
		if [[ ! -e /usr/bin/go ]]; then
			yum -y install golang &>/dev/null		
		fi
		WorkingStatus Process "Downloading BoringSSL"
		if [[ -e ${WorkPath}/boringssl ]]; then
			cd ${WorkPath}/boringssl
			git fetch && git pull &>/dev/null
		else
			git clone "https://boringssl.googlesource.com/boringssl" "${WorkPath}/boringssl" &>/dev/null
		fi
		if [[ $? -eq 0 ]]; then
			WorkingStatus OK "Downloading BoringSSL"
		else
			WorkingStatus Fail "Downloading BoringSSL"
		fi
		
		# Upgrade gcc+ 4.8
		if [ ! -e /opt/rh/devtoolset-2/root/usr/bin/gcc ] || [ ! -e /opt/rh/devtoolset-3/root/usr/bin/c++ ]; then
			WorkingStatus Process "Building gcc4.8+"
			rpm --import http://ftp.scientificlinux.org/linux/scientific/5x/x86_64/RPM-GPG-KEYs/RPM-GPG-KEY-cern
			wget -q -O /etc/yum.repos.d/slc6-devtoolset.repo http://linuxsoft.cern.ch/cern/devtoolset/slc6-devtoolset.repo -c
			yum install -y devtoolset-2-gcc-c++ devtoolset-2-binutils >&/dev/null
			if [[ $? -eq 0 ]]; then
				mv /usr/bin/gcc /usr/bin/gcc.default && ln -s /opt/rh/devtoolset-2/root/usr/bin/gcc /usr/bin/gcc
				mv /usr/bin/c++ /usr/bin/c++.default && ln -s /opt/rh/devtoolset-2/root/usr/bin/c++ /usr/bin/c++
				WorkingStatus OK "Building gcc4.8+"
			else
				WorkingStatus Fail "Building gcc4.8+"
			fi
		fi

		# WorkingStatus Process "Building cmake 3.0"
		# # Upgrade cmake 3.0
		# wget -q http://www.cmake.org/files/v3.0/cmake-3.0.0.tar.gz -P ${WorkPath} -c
		# tar -xzf ${WorkPath}/cmake-3.0.0.tar.gz -C ${WorkPath}
		# cd ${WorkPath}/cmake-3.0.0 && ./bootstrap &> /dev/null
		# gmake &> /dev/null
		# if [[ $? -eq 0 ]]; then
		# 	cmake_bin="${WorkPath}/cmake-3.0.0/bin/cmake"
		# 	WorkingStatus OK "Building cmake 3.0 "
		# else
		# 	WorkingStatus Fail "Building cmake 3.0"
		# fi

		WorkingStatus Process "Configuring BoringSSL"
		mkdir -p ${WorkPath}/boringssl/build && cd ${WorkPath}/boringssl/build
		cmake .. &>/dev/null
		if [[ $? -eq 0 ]]; then
			WorkingStatus OK "Configuring BoringSSL"
		else
			WorkingStatus Fail "Configuring BoringSSL"
		fi

		WorkingStatus Process "Compiling BoringSSL"
		make &>/dev/null
		if [[ $? -eq 0 ]]; then
			WorkingStatus OK "Compiling BoringSSL"
		else
			WorkingStatus Fail "Compiling BoringSSL"
		fi

		mkdir -p ${WorkPath}/boringssl/.openssl/lib && cd ${WorkPath}/boringssl/.openssl
		ln -s ../include
		cp ${WorkPath}/boringssl/build/crypto/libcrypto.a ${WorkPath}/boringssl/build/ssl/libssl.a ${WorkPath}/boringssl/.openssl/lib

		NginxModules=$(echo $NginxModules; echo "--with-openssl=${WorkPath}/boringssl")
	
	fi

	# LibreSSL (OpenBSD)
	if [[ "1" == $LibreSSL ]]; then
		WorkingStatus Process "Downloading LibreSSL"
		wget -q http://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-${LibreSSLVer}.tar.gz -P ${WorkPath} -c
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
			--prefix=${WorkPath}/libressl-${LibreSSLVer}/.openssl/ \
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
		NginxModules=$(echo $NginxModules; echo "--with-openssl=${WorkPath}/libressl-${LibreSSLVer}")
	fi

	# OpenSSL with Cloudflare Patch support ChaCha20-Poly1305
	if [[ "1" == $OpenSSL ]]; then
		WorkingStatus Process "Downloading OpenSSL"
		wget -q https://www.openssl.org/source/openssl-${OpenSSLVer}.tar.gz -P ${WorkPath} -c
		tar -xzf ${WorkPath}/openssl-${OpenSSLVer}.tar.gz -C ${WorkPath}
		cd ${WorkPath}/openssl-${OpenSSLVer}
		if [[ $? -eq 0 ]]; then
			WorkingStatus OK "Downloading OpenSSL"
		else
			WorkingStatus Fail "Downloading OpenSSL"
		fi

		# ChaCha20-Poly1305
		if [[ ! -e ${SourceRoot}/patch/chacha_with_102j.patch ]]; then
			wget -q https://raw.githubusercontent.com/cloudflare/sslconfig/master/patches/openssl__chacha20_poly1305_draft_and_rfc_ossl102j.patch -O ${SourceRoot}/patch/chacha_with_102j.patch -c &>/dev/null 
		fi

		if [[ ! -f /usr/bin/patch ]]; then
			yum install -y patch &>/dev/null
		fi
		cd ${WorkPath}/openssl-${OpenSSLVer}
		patch -p1 < ${SourceRoot}/patch/chacha_with_102j.patch &>/dev/null


		if [[ $? -eq 0 ]]; then
	 		WorkingStatus OK "Adding ChaCha to OpenSSL"
	 	else
	 		WorkingStatus Fail "Adding ChaCha to OpenSSL"
		fi 

		WorkingStatus Process "Configuring OpenSSL"
		./config &>/dev/null
		if [[ $? -eq 0 ]]; then
			WorkingStatus OK "Configuring OpenSSL"
		else
			WorkingStatus Fail "Configuring OpenSSL"
		fi
		NginxModules=$(echo $NginxModules; echo "--with-openssl=${WorkPath}/openssl-${OpenSSLVer}")
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


SourceRoot=$(pwd)
if [[ $# -gt 0 ]]; then
	for opt in $@
	do
		case $opt in
			install)
				shift
				Install=1
				;;
			uninstall)
				shift
				NginxUninstall
				;;
			--openssl)
				OpenSSL=1
				;;
			--libressl)
				LibreSSL=1
				;;
			--boringssl)
				BoringSSL=1
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

if [[ $Install ]]; then
	if [[ -f $Config ]]; then
		source $SourceRoot/$Config >&/dev/null
		if [[ "$(id -u)" -ne 0 ]]; then 
			echo -e "This script is not intended to be run as root."
			exit 1;
		fi
		Welcome
		Dependencies
		AddModules
		NginxInstall
	else
		echo "Warning: Config $Config file not found"
		exit 1
	fi
fi







