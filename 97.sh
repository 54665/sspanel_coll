#!/bin/bash
#
# Docker And BBR
#
# Copyright (c) 2020.

if readlink /proc/$$/exe | grep -q "Bash"; then
	echo "该脚本需要使用bash而不是sh运行"
	exit
fi
#删除多余内核
detele_kernel(){
	if [[ "${release}" == "centos" ]]; then
		rpm_total=`rpm -qa | grep kernel | grep -v "${kernel_version}" | grep -v "noarch" | wc -l`
		if [ "${rpm_total}" > "1" ]; then
			echo -e "检测到 ${rpm_total} 个其余内核，开始卸载..."
			for((integer = 1; integer <= ${rpm_total}; integer++)); do
				rpm_del=`rpm -qa | grep kernel | grep -v "${kernel_version}" | grep -v "noarch" | head -${integer}`
				echo -e "开始卸载 ${rpm_del} 内核..."
				rpm --nodeps -e ${rpm_del}
				echo -e "卸载 ${rpm_del} 内核卸载完成，继续..."
			done
			echo --nodeps -e "内核卸载完毕，继续..."
		else
			echo -e " 检测到 内核 数量不正确，请检查 !" && exit 1
		fi
	elif [[ "${release}" == "debian" || "${release}" == "ubuntu" ]]; then
		deb_total=`dpkg -l | grep linux-image | awk '{print $2}' | grep -v "${kernel_version}" | wc -l`
		if [ "${deb_total}" > "1" ]; then
			echo -e "检测到 ${deb_total} 个其余内核，开始卸载..."
			for((integer = 1; integer <= ${deb_total}; integer++)); do
				deb_del=`dpkg -l|grep linux-image | awk '{print $2}' | grep -v "${kernel_version}" | head -${integer}`
				echo -e "开始卸载 ${deb_del} 内核..."
				apt-get purge -y ${deb_del}
				echo -e "卸载 ${deb_del} 内核卸载完成，继续..."
			done
			echo -e "内核卸载完毕，继续..."
		else
			echo -e " 检测到 内核 数量不正确，请检查 !" && exit 1
		fi
	fi
}

#更新引导
BBR_grub(){
	if [[ "${release}" == "centos" ]]; then
        if [[ ${version} = "6" ]]; then
            if [ ! -f "/boot/grub/grub.conf" ]; then
                echo -e "${Error} /boot/grub/grub.conf 找不到，请检查."
                exit 1
            fi
            sed -i 's/^default=.*/default=0/g' /boot/grub/grub.conf
        elif [[ ${version} = "7" ]]; then
            if [ -f "/boot/grub2/grub.cfg" ]; then
				grub2-mkconfig  -o   /boot/grub2/grub.cfg
				grub2-set-default 0
				exit 1
			elif [ -f "/boot/efi/EFI/centos/grub.cfg" ]; then
				grub2-mkconfig  -o   /boot/efi/EFI/centos/grub.cfg
				grub2-set-default 0
				exit 1
			else
				echo -e "${Error} grub.cfg 找不到，请检查."
            fi
			#grub2-mkconfig  -o   /boot/grub2/grub.cfg
			#grub2-set-default 0
		
		elif [[ ${version} = "8" ]]; then
			grub2-mkconfig  -o   /boot/grub2/grub.cfg
			grubby --info=ALL|awk -F= '$1=="kernel" {print i++ " : " $2}'
        fi
    elif [[ "${release}" == "debian" || "${release}" == "ubuntu" ]]; then
        /usr/sbin/update-grub
		#exit 1
    fi
}
#############内核管理组件#############

#删除多余内核
detele_kernel(){
	if [[ "${release}" == "centos" ]]; then
		rpm_total=`rpm -qa | grep kernel | grep -v "${kernel_version}" | grep -v "noarch" | wc -l`
		if [ "${rpm_total}" > "1" ]; then
			echo -e "检测到 ${rpm_total} 个其余内核，开始卸载..."
			for((integer = 1; integer <= ${rpm_total}; integer++)); do
				rpm_del=`rpm -qa | grep kernel | grep -v "${kernel_version}" | grep -v "noarch" | head -${integer}`
				echo -e "开始卸载 ${rpm_del} 内核..."
				rpm --nodeps -e ${rpm_del}
				echo -e "卸载 ${rpm_del} 内核卸载完成，继续..."
			done
			echo --nodeps -e "内核卸载完毕，继续..."
		else
			echo -e " 检测到 内核 数量不正确，请检查 !" && exit 1
		fi
	elif [[ "${release}" == "debian" || "${release}" == "ubuntu" ]]; then
		deb_total=`dpkg -l | grep linux-image | awk '{print $2}' | grep -v "${kernel_version}" | wc -l`
		if [ "${deb_total}" > "1" ]; then
			echo -e "检测到 ${deb_total} 个其余内核，开始卸载..."
			for((integer = 1; integer <= ${deb_total}; integer++)); do
				deb_del=`dpkg -l|grep linux-image | awk '{print $2}' | grep -v "${kernel_version}" | head -${integer}`
				echo -e "开始卸载 ${deb_del} 内核..."
				apt-get purge -y ${deb_del}
				echo -e "卸载 ${deb_del} 内核卸载完成，继续..."
			done
			echo -e "内核卸载完毕，继续..."
		else
			echo -e " 检测到 内核 数量不正确，请检查 !" && exit 1
		fi
	fi
}

#更新引导
BBR_grub(){
	if [[ "${release}" == "centos" ]]; then
        if [[ ${version} = "6" ]]; then
            if [ ! -f "/boot/grub/grub.conf" ]; then
                echo -e "${Error} /boot/grub/grub.conf 找不到，请检查."
                exit 1
            fi
            sed -i 's/^default=.*/default=0/g' /boot/grub/grub.conf
        elif [[ ${version} = "7" ]]; then
            if [ -f "/boot/grub2/grub.cfg" ]; then
				grub2-mkconfig  -o   /boot/grub2/grub.cfg
				grub2-set-default 0
				exit 1
			elif [ -f "/boot/efi/EFI/centos/grub.cfg" ]; then
				grub2-mkconfig  -o   /boot/efi/EFI/centos/grub.cfg
				grub2-set-default 0
				exit 1
			else
				echo -e "${Error} grub.cfg 找不到，请检查."
            fi
			#grub2-mkconfig  -o   /boot/grub2/grub.cfg
			#grub2-set-default 0
		
		elif [[ ${version} = "8" ]]; then
			grub2-mkconfig  -o   /boot/grub2/grub.cfg
			grubby --info=ALL|awk -F= '$1=="kernel" {print i++ " : " $2}'
        fi
    elif [[ "${release}" == "debian" || "${release}" == "ubuntu" ]]; then
        /usr/sbin/update-grub
		#exit 1
    fi
}

#############内核管理组件#############

#检查安装bbr的系统要求
check_sys_bbr(){
	check_version
	if [[ "${release}" == "centos" ]]; then
		if [[ ${version} = "6" || ${version} = "7" || ${version} = "8" ]]; then
			installbbr
		else
			echo -e "${Error} BBR内核不支持当前系统 ${release} ${version} ${bit} !" && exit 1
		fi
	elif [[ "${release}" == "debian" ]]; then
		if [[ ${version} = "8" || ${version} = "9" || ${version} = "10" ]]; then
			installbbr
		else
			echo -e "${Error} BBR内核不支持当前系统 ${release} ${version} ${bit} !" && exit 1
		fi
	elif [[ "${release}" == "ubuntu" ]]; then
		if [[ ${version} = "16" || ${version} = "18" || ${version} = "19" || ${version} = "20" ]]; then
			installbbr
		else
			echo -e "${Error} BBR内核不支持当前系统 ${release} ${version} ${bit} !" && exit 1
		fi
	else
		echo -e "${Error} BBR内核不支持当前系统 ${release} ${version} ${bit} !" && exit 1
	fi
}
startbbrcake(){
	remove_all
	echo "net.core.default_qdisc=cake" >> /etc/sysctl.conf
	echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
	sysctl -p
	optimizing_system
	echo -e "${Info}BBR+cake修改成功，重启生效！"
}
#卸载全部加速
remove_all(){
	rm -rf bbrmod
	sed -i '/net.ipv4.tcp_retries2/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_slow_start_after_idle/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_fastopen/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_ecn/d' /etc/sysctl.conf
	sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf
    sed -i '/fs.file-max/d' /etc/sysctl.conf
	sed -i '/net.core.rmem_max/d' /etc/sysctl.conf
	sed -i '/net.core.wmem_max/d' /etc/sysctl.conf
	sed -i '/net.core.rmem_default/d' /etc/sysctl.conf
	sed -i '/net.core.wmem_default/d' /etc/sysctl.conf
	sed -i '/net.core.netdev_max_backlog/d' /etc/sysctl.conf
	sed -i '/net.core.somaxconn/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_syncookies/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_tw_reuse/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_tw_recycle/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_fin_timeout/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_keepalive_time/d' /etc/sysctl.conf
	sed -i '/net.ipv4.ip_local_port_range/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_max_syn_backlog/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_max_tw_buckets/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_rmem/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_wmem/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_mtu_probing/d' /etc/sysctl.conf
	sed -i '/net.ipv4.ip_forward/d' /etc/sysctl.conf
	sed -i '/fs.inotify.max_user_instances/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_syncookies/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_fin_timeout/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_tw_reuse/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_max_syn_backlog/d' /etc/sysctl.conf
	sed -i '/net.ipv4.ip_local_port_range/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_max_tw_buckets/d' /etc/sysctl.conf
	sed -i '/net.ipv4.route.gc_timeout/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_synack_retries/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_syn_retries/d' /etc/sysctl.conf
	sed -i '/net.core.somaxconn/d' /etc/sysctl.conf
	sed -i '/net.core.netdev_max_backlog/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_timestamps/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_max_orphans/d' /etc/sysctl.conf
	if [[ -e /appex/bin/lotServer.sh ]]; then
		bash <(wget -qO- https://git.io/lotServerInstall.sh) uninstall
	fi
	clear
	echo -e "${Info}:清除加速完成。"
	sleep 1s
}

#优化系统配置
optimizing_system(){
	sed -i '/net.ipv4.tcp_retries2/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_slow_start_after_idle/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_fastopen/d' /etc/sysctl.conf
	sed -i '/fs.file-max/d' /etc/sysctl.conf
	sed -i '/fs.inotify.max_user_instances/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_syncookies/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_fin_timeout/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_tw_reuse/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_max_syn_backlog/d' /etc/sysctl.conf
	sed -i '/net.ipv4.ip_local_port_range/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_max_tw_buckets/d' /etc/sysctl.conf
	sed -i '/net.ipv4.route.gc_timeout/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_synack_retries/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_syn_retries/d' /etc/sysctl.conf
	sed -i '/net.core.somaxconn/d' /etc/sysctl.conf
	sed -i '/net.core.netdev_max_backlog/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_timestamps/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_max_orphans/d' /etc/sysctl.conf
	sed -i '/net.ipv4.ip_forward/d' /etc/sysctl.conf
	echo "net.ipv4.tcp_retries2 = 8
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_fastopen = 3
fs.file-max = 1000000
fs.inotify.max_user_instances = 8192
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_tw_reuse = 1
net.ipv4.ip_local_port_range = 1024 65000
net.ipv4.tcp_max_syn_backlog = 16384
net.ipv4.tcp_max_tw_buckets = 6000
net.ipv4.route.gc_timeout = 100
net.ipv4.tcp_syn_retries = 1
net.ipv4.tcp_synack_retries = 1
net.core.somaxconn = 32768
net.core.netdev_max_backlog = 32768
net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_max_orphans = 32768
# forward ipv4
net.ipv4.ip_forward = 1">>/etc/sysctl.conf
	sysctl -p
	echo "*               soft    nofile           1000000
*               hard    nofile          1000000">/etc/security/limits.conf
	echo "ulimit -SHn 1000000">>/etc/profile
	read -p "需要重启VPS后，才能生效系统优化配置，是否现在重启 ? [Y/n] :" yn
	[ -z "${yn}" ] && yn="y"
	if [[ $yn == [Yy] ]]; then
		echo -e "${Info} VPS 重启中..."
		reboot
	fi
}

	kernel_version="5.6.15"
	bit=`uname -m`
	rm -rf bbr
	mkdir bbr && cd bbr
	
	if [[ "${release}" == "centos" ]]; then
		if [[ ${version} = "6" ]]; then
			if [[ ${bit} = "x86_64" ]]; then
				wget -N -O kernel-headers-c6.rpm https://chinagz2018-my.sharepoint.com/:u:/g/personal/ylx_chinagz2018_onmicrosoft_com/EUCmObDQnMZEmKnhxS67sJkBG8kjbx0bjNF-XwTtzvgtAA?download=1
				wget -N -O kernel-c6.rpm https://chinagz2018-my.sharepoint.com/:u:/g/personal/ylx_chinagz2018_onmicrosoft_com/EeC72joP3HVNmrIbjlPg_coBs7kj29Md4f9psAjZOuqOdg?download=1
			
				yum install -y kernel-c6.rpm
				yum install -y kernel-headers-c6.rpm
			
				#kernel_version="5.5.5"
			else
				echo -e "${Error} 还在用32位内核，别再见了 !" && exit 1
			fi
		
		elif [[ ${version} = "7" ]]; then
			if [[ ${bit} = "x86_64" ]]; then
				wget -N -O kernel-headers-c7.rpm https://chinagz2018-my.sharepoint.com/:u:/g/personal/ylx_chinagz2018_onmicrosoft_com/Ea2J4h6bZGVPsOFxcWKatQoB-9kscXFTlJWT4Np35MVfVw?download=1
				wget -N -O kernel-c7.rpm https://chinagz2018-my.sharepoint.com/:u:/g/personal/ylx_chinagz2018_onmicrosoft_com/ER6u_mV_MTtGmk6eJf9t01gBTBMWDjiOBdDJow3iTfRujQ?download=1

				yum install -y kernel-c7.rpm
				yum install -y kernel-headers-c7.rpm
			
				kernel_version="5.8.5"
			else
				echo -e "${Error} 还在用32位内核，别再见了 !" && exit 1
			fi	
		elif [[ ${version} = "8" ]]; then
			wget -N -O kernel-c8.rpm https://chinagz2018-my.sharepoint.com/:u:/g/personal/ylx_chinagz2018_onmicrosoft_com/ETadaTIeeQJCgxEXKlOFiCEBsBa-Y15QbDkv-HQGo2EHSQ?download=1
			wget -N -O kernel-headers-c8.rpm https://chinagz2018-my.sharepoint.com/:u:/g/personal/ylx_chinagz2018_onmicrosoft_com/EZEZyLBjDplMgSqDzyaqkvYBW06OOKDCcIQq27381fa5-A?download=1

			yum install -y kernel-c8.rpm
			yum install -y kernel-headers-c8.rpm
			
			#kernel_version="5.5.5"
	cd .. && rm -rf bbr	
	
	detele_kernel
	BBR_grub
	echo -e "${Tip} ${Red_font_prefix}请检查上面是否有内核信息，无内核千万别重启${Font_color_suffix}"
	echo -e "${Tip} ${Red_font_prefix}rescue不是正常内核，要排除这个${Font_color_suffix}"
	echo -e "${Tip} 重启VPS后，请重新运行脚本开启${Red_font_prefix}BBR${Font_color_suffix}"	
	#echo -e "${Tip} 内核安装完毕，请参考上面的信息检查是否安装成功及手动调整内核启动顺序"
startbbrcake