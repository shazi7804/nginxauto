#!/bin/bash
#
# Program: Nginx install
# Author: scott
# Github: https://github.com/shazi7804
Config="auto.conf"
WorkPath="/tmp/nginxauto-$RANDOM-tmp" # build directory
Logfile="$WorkPath/nginxauto.log"


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
		echo ""
		echo "nginxauto compiled fail. Please check the $Logfile"
		exit 1
	elif [[ "Process" == $status ]]; then
		echo -ne "$message  [..]\r"
	fi
}

Dependencies(){
	local dep
	WorkingStatus Process "Verify dependencies"
	dep="wget git tar git autoconf gcc gcc-c++ make zlib-devel pcre-devel openssl-devel libxml2 libxslt-devel gd-devel geoipupdate perl-devel perl-ExtUtils-Embed"
	if rpm -q $dep &>> $Logfile; then
		WorkingStatus OK "Verify dependencies"
	else
		yum install -y $dep &>> $Logfile
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
	if [[ ! -e $NginxPrefix/nginx.conf ]]; then
		WorkingStatus Process "Downloading nginx config"
		mkdir -p $NginxPrefix
		if [[ ! -e ${SourceRoot}/conf/nginx.conf ]]; then
			wget -q https://raw.githubusercontent.com/shazi7804/nginxauto/master/conf/{{nginx,expire}.conf,user-agent.rules} -P $NginxPrefix/ -c
		else
			cp ${SourceRoot}/conf/{{nginx,expire}.conf,user-agent.rules} $NginxPrefix/
		fi
		if [[ $? -eq 0 ]]; then
			WorkingStatus OK "Downloading nginx config"
		else
			WorkingStatus Fail "Downloading nginx config"
		fi
	fi

	# Add module
	AddModules

	# Configuration
	WorkingStatus Process "Configuring nginx"
	cd ${WorkPath}/nginx-${NginxVer}
	./configure ${NginxConfiguration} ${NginxModules} &>> $Logfile
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
	make -j $(nproc) &>> $Logfile
	if [[ $? -eq 0 ]]; then
		WorkingStatus OK "Compiling nginx"
	else
		WorkingStatus Fail "Compiling nginx"
	fi

	# Install
	WorkingStatus Process "Installing nginx"
	make install &>> $Logfile
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

	# create nginx user
	if ! id $NginxOwner &>> $Logfile ; then
		adduser $NginxOwner -M	
	fi


	if [[ ! -x /etc/init.d/nginx ]]; then
		chmod +x /etc/init.d/nginx
	fi

	# default create cache directory
	if [[ ! -d $NginxCache ]]; then
		mkdir -p $NginxCache
	fi

	# check all permissions
	find $NginxCache ! -user $NginxOwner -exec chown $NginxOwner {} \;
	find $NginxCache ! -perm $NginxPerm -exec chmod $NginxPerm {} \;

	# init default file
	find $NginxPrefix -type f -iname "*.default" -delete &>> $Logfile

	if [[ -d $NginxPrefix/html ]]; then
		rm -r $NginxPrefix/html
	fi

	if [[ ! -d $NginxPrefix/conf.d ]]; then
		mkdir $NginxPrefix/conf.d
	fi
	
	# create example config
	if ! ls -A $NginxPrefix/conf.d &>> $Logfile; then
		cp ${SourceRoot}/conf/example-config/server.conf $NginxPrefix/conf.d/0-server.conf	
	fi

	# Restart service
	WorkingStatus Process "Restart service"
	service nginx restart &>> $Logfile
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

Module_PageSpeed() {
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
		yum install -y devtoolset-2-gcc-c++ devtoolset-2-binutils &>> $Logfile
		if [[ $? -eq 0 ]]; then
			mv /usr/bin/gcc /usr/bin/gcc.default && mv /usr/bin/c++ /usr/bin/c++.default
			ln -fs /opt/rh/devtoolset-2/root/usr/bin/gcc /usr/bin/gcc && ln -fs /opt/rh/devtoolset-2/root/usr/bin/c++ /usr/bin/c++
			WorkingStatus OK "Building gcc4.8+"
		else
			WorkingStatus Fail "Building gcc4.8+"
		fi
	fi

	# Get ngx_pagespeed config
	WorkingStatus Process "Downloading ngx_pagespeed config"
	if [[ ! -e ${SourceRoot}/conf/ngx_pagespeed.conf ]]; then
		wget -q https://raw.githubusercontent.com/shazi7804/nginxauto/master/conf/ngx_pagespeed.conf -P $NginxPrefix/ -c
	else
		cp ${SourceRoot}/conf/ngx_pagespeed.conf $NginxPrefix/
	fi
	if [[ $? -eq 0 ]]; then
		WorkingStatus OK "Downloading ngx_pagespeed config"
	else
		WorkingStatus Fail "Downloading ngx_pagespeed config"
	fi

	NginxModules=$(echo $NginxModules; echo "--add-module=${WorkPath}/ngx_pagespeed-release-${NPSVer}-beta --with-cc=/opt/rh/devtoolset-2/root/usr/bin/gcc")
}

Module_Brotli() {
	WorkingStatus Process "Downloading ngx_brotli"
	if [[ -d ${WorkPath}/ngx_brotli ]]; then
		rm -r ${WorkPath}/ngx_brotli
	fi

	if [[ -e ${WorkPath}/ngx_brotli ]]; then
		cd ${WorkPath}/ngx_brotli
		git fetch && git pull
	else
		git clone https://github.com/google/ngx_brotli "${WorkPath}/ngx_brotli" &>> $Logfile
		cd ${WorkPath}/ngx_brotli
		git submodule update --init &>> $Logfile
	fi

	if [[ $? -eq 0 ]]; then
		WorkingStatus OK "Downloading ngx_brotli"
		NginxModules=$(echo $NginxModules; echo "--add-module=${WorkPath}/ngx_brotli")
	else
		WorkingStatus Fail "Downloading ngx_brotli"
	fi
}

Module_Headers() {
	WorkingStatus Process "Downloading ngx_headers_more"
	wget -q https://github.com/openresty/headers-more-nginx-module/archive/v${HeadersVer}.tar.gz -P ${WorkPath} -c
	tar -xzf ${WorkPath}/v${HeadersVer}.tar.gz -C ${WorkPath}
	if [[ $? -eq 0 ]]; then
		WorkingStatus OK "Downloading ngx_headers_more"
	else
		WorkingStatus Fail "Downloading ngx_headers_more"
	fi
	NginxModules=$(echo $NginxModules; echo "--add-module=${WorkPath}/headers-more-nginx-module-${HeadersVer}")
}

Module_GeoIP() {
	WorkingStatus Process "Downloading GeoIP databases"
	if ! rpm -q GeoIP-devel &>> $Logfile; then
		if ! yum repolist | grep epel &>> $Logfile ; then
			 rpm -ivh https://dl.fedoraproject.org/pub/epel/epel-release-latest-6.noarch.rpm &>> $Logfile
		fi
		yum install -y GeoIP-devel --enablerepo=epel &>> $Logfile
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
		NginxModules=$(echo $NginxModules; echo "--with-http_geoip_module")
	else
		WorkingStatus Fail "Downloading GeoIP databases"
	fi
}

Module_SSL() {
	# BoringSSL with go (Google)
	if [[ "1" == $BoringSSL ]]; then
		if [[ ! -e /usr/bin/go ]]; then
			yum -y install golang cmake &>> $Logfile		
		fi
		WorkingStatus Process "Downloading BoringSSL"
		if [[ -e ${WorkPath}/boringssl ]]; then
			cd ${WorkPath}/boringssl
			git fetch && git pull &>> $Logfile
		else
			git clone "https://boringssl.googlesource.com/boringssl" "${WorkPath}/boringssl" &>> $Logfile
		fi
		if [[ $? -eq 0 ]]; then
			WorkingStatus OK "Downloading BoringSSL"
		else
			WorkingStatus Fail "Downloading BoringSSL"
		fi
		
		# Upgrade gcc+ 4.8
		if [ ! -e /opt/rh/devtoolset-2/root/usr/bin/gcc ] || [ ! -e /opt/rh/devtoolset-2/root/usr/bin/c++ ]; then
			WorkingStatus Process "Building gcc4.8+"
			rpm --import http://ftp.scientificlinux.org/linux/scientific/5x/x86_64/RPM-GPG-KEYs/RPM-GPG-KEY-cern
			wget -q -O /etc/yum.repos.d/slc6-devtoolset.repo http://linuxsoft.cern.ch/cern/devtoolset/slc6-devtoolset.repo -c
			yum install -y devtoolset-2-gcc-c++ devtoolset-2-binutils &>> $Logfile
			if [[ $? -eq 0 ]]; then
				mv /usr/bin/gcc /usr/bin/gcc.default && ln -s /opt/rh/devtoolset-2/root/usr/bin/gcc /usr/bin/gcc
				mv /usr/bin/c++ /usr/bin/c++.default && ln -s /opt/rh/devtoolset-2/root/usr/bin/c++ /usr/bin/c++
				WorkingStatus OK "Building gcc4.8+"
			else
				WorkingStatus Fail "Building gcc4.8+"
			fi
		fi

		WorkingStatus Process "Configuring BoringSSL"
		mkdir -p ${WorkPath}/boringssl/build && cd ${WorkPath}/boringssl/build
		cmake .. &>> $Logfile
		if [[ $? -eq 0 ]]; then
			WorkingStatus OK "Configuring BoringSSL"
		else
			WorkingStatus Fail "Configuring BoringSSL"
		fi

		WorkingStatus Process "Compiling BoringSSL"
		make &>> $Logfile
		if [[ $? -eq 0 ]]; then
			WorkingStatus OK "Compiling BoringSSL"
		else
			WorkingStatus Fail "Compiling BoringSSL"
		fi

		mkdir -p ${WorkPath}/boringssl/.openssl/lib && cd ${WorkPath}/boringssl/.openssl
		ln -s ../include
		cp ${WorkPath}/boringssl/build/crypto/libcrypto.a ${WorkPath}/boringssl/build/ssl/libssl.a ${WorkPath}/boringssl/.openssl/lib

		if [[ $NginxVer = +(1.11.4|1.11.5|1.11.6|1.11.7) ]]; then
			if [[ ! -f /usr/bin/patch ]]; then
				yum install -y patch &>> $Logfile
			fi
			cd ${WorkPath}/nginx-$NginxVer
			patch -p1 < ${SourceRoot}/patch/boringssl_fix_1.11.7.patch &>> $Logfile
		fi

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
			--enable-shared=no &>> $Logfile
		if [[ $? -eq 0 ]]; then
			WorkingStatus OK "Configuring LibreSSL"
		else
			WorkingStatus Fail "Configuring LibreSSL"
		fi

		WorkingStatus Process "Installing LibreSSL"
		make install-strip -j $(nproc) &>> $Logfile
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
			wget -q https://raw.githubusercontent.com/cloudflare/sslconfig/master/patches/openssl__chacha20_poly1305_draft_and_rfc_ossl102j.patch -O ${SourceRoot}/patch/chacha_with_102j.patch -c &>> $Logfile 
		fi

		if [[ ! -f /usr/bin/patch ]]; then
			yum install -y patch &>> $Logfile
		fi
		cd ${WorkPath}/openssl-${OpenSSLVer}
		patch -p1 < ${SourceRoot}/patch/chacha_with_102j.patch &>> $Logfile


		if [[ $? -eq 0 ]]; then
	 		WorkingStatus OK "Adding ChaCha to OpenSSL"
	 	else
	 		WorkingStatus Fail "Adding ChaCha to OpenSSL"
		fi 

		WorkingStatus Process "Configuring OpenSSL"
		./config &>> $Logfile
		if [[ $? -eq 0 ]]; then
			WorkingStatus OK "Configuring OpenSSL"
			NginxModules=$(echo $NginxModules; echo "--with-openssl=${WorkPath}/openssl-${OpenSSLVer}")
		else
			WorkingStatus Fail "Configuring OpenSSL"
		fi
	fi
}

AddModules() {
	if [[ "1" == $PageSpeed ]]; then
		Module_PageSpeed
	fi

	if [[ "1" == $Brotli ]]; then
		Module_Brotli
	fi

	if [[ "1" == $Headers ]]; then
		Module_Headers
	fi

	if [[ "1" == $GeoIP ]]; then
		Module_GeoIP
	fi

	if [[ "1" == $SSL ]]; then
		Module_SSL
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
		/var/log/nginx &> /dev/null
	WorkingStatus OK "Remove nginx env"
	
	WorkingStatus Process "Remove nginx config"
	rm -r $NginxPrefix &> /dev/null
	if [[ $? -eq 0 ]]; then
		WorkingStatus OK "Remove nginx config"
	else
		WorkingStatus Fail "Remove nginx config"
	fi

	echo ""
	echo "Uninstallation successful !!"
	echo ""
}

ssl_num=0

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
				Uninstall=1
				;;
			--openssl)
				OpenSSL=1
				SSL=1
				ssl_num=$((ssl_num+1))
				;;
			--libressl)
				LibreSSL=1
				SSL=1
				ssl_num=$((ssl_num+1))
				;;
			--boringssl)
				BoringSSL=1
				SSL=1
				ssl_num=$((ssl_num+1))
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
		source $SourceRoot/$Config
		if [[ "$(id -u)" -ne 0 ]]; then 
			echo -e "This script is not intended to be run as root."
			exit 1;
		fi

		if [[ $ssl_num -gt 1 ]]; then
			echo "Only one ssl type can be selected."
			exit 1
		elif [[ "0" == $ssl_num ]]; then
			echo "The default is enable ssl_module and you must select a ssl type."
			exit 1
		fi

		if [[ ! -d $WorkPath ]]; then
			mkdir -p $WorkPath
		fi
		Welcome
		Dependencies
		NginxInstall
	else
		echo "Warning: Config $Config file not found"
		exit 1
	fi
elif [[ $Uninstall ]]; then
	if [[ -f $Config ]]; then
		source $SourceRoot/$Config
		if [[ "$(id -u)" -ne 0 ]]; then 
			echo -e "This script is not intended to be run as root."
			exit 1;
		fi
		NginxUninstall
	fi
	
fi





