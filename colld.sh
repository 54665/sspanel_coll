#!/bin/bash
#
# 一个合集脚本2
#
# Copyright (c) 2020.

if readlink /proc/$$/exe | grep -q "Bash"; then
	echo "该脚本需要使用bash而不是sh运行"
	exit
fi

if [[ "$EUID" -ne 0 ]]; then
	echo "对不起你需要使用ROOT权限运行该脚本"
	exit
fi

beikong0_chushihua(){
echo "正在下载BBR脚本"
wget -N "https://github.000060000.xyz/tcp.sh"
chmod +x tcp.sh
./tcp.sh
}
beikong1_chushihua(){
echo "正在下载BBR脚本"
wget "https://dt.yixiagege.cn/shell/tcp-cn.sh"
chmod +x tcp-cn.sh
./tcp-cn.sh
}
beikong2_chushihua(){
echo "正在下载AWS脚本"
wget https://raw.githubusercontent.com/54665/awspro/master/aws.sh
chmod +x 777 aws.sh
bash aws.sh
}
beikong3_chushihua(){
echo "正在创建ROOT用户"
echo root:love.love |sudo chpasswd root
sudo sed -i 's/^.*PermitRootLogin.*/PermitRootLogin yes/g' /etc/ssh/sshd_config;
sudo sed -i 's/^.*PasswordAuthentication.*/PasswordAuthentication yes/g' /etc/ssh/sshd_config;
echo "默认Root密码:love.love"
sudo service sshd restart
}
beikong4_chushihua(){
docker version > /dev/null || curl -fsSL get.docker.com | bash
service docker restart
}
beikong5_chushihua(){
echo "正在添加自启任务"
echo "service docker restart" >> /etc/rc.d/rc.local
}
beikong6_chushihua(){
echo "正在安装V2-ui"
bash <(curl -Ls https://blog.sprov.xyz/v2-ui.sh)
}
beikong97_chushihua(){
echo "正在安装Docker"
docker version > /dev/null || curl -fsSL get.docker.com | bash
service docker restart
echo "正在添加自启任务"
echo "service docker restart" >> /etc/rc.d/rc.local
echo "正在安装BBR"
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
		fi
	
	elif [[ "${release}" == "debian" || "${release}" == "ubuntu" ]]; then
		if [[ "${release}" == "debian" ]]; then
			if [[ ${version} = "8" ]]; then
				if [[ ${bit} = "x86_64" ]]; then
					wget -N -O linux-image-d8.deb https://chinagz2018-my.sharepoint.com/:u:/g/personal/ylx_chinagz2018_onmicrosoft_com/EeNpacEol0ZDk5S5ARJ1G7wBI6hF0q-C--Nonxq31lO1iw?download=1
					wget -N -O linux-headers-d8.deb https://chinagz2018-my.sharepoint.com/:u:/g/personal/ylx_chinagz2018_onmicrosoft_com/EWmAacwLpdJPhs56m6KhxsEBnnZyqOPJggf-2XXHMfxCtw?download=1
				
					dpkg -i linux-image-d8.deb
					dpkg -i linux-headers-d8.deb
				
					#kernel_version="5.5.5"
				else
					echo -e "${Error} 还在用32位内核，别再见了 !" && exit 1
				fi
		
			elif [[ ${version} = "9" ]]; then
				if [[ ${bit} = "x86_64" ]]; then
					wget -N -O linux-image-d9.deb https://chinagz2018-my.sharepoint.com/:u:/g/personal/ylx_chinagz2018_onmicrosoft_com/EWrsOGQzcqJOrLzeaqXBh0sBbs9Np7anhs5JULwFAliGBg?download=1
					wget -N -O linux-headers-d9.deb https://chinagz2018-my.sharepoint.com/:u:/g/personal/ylx_chinagz2018_onmicrosoft_com/EbAGliMxbpZAtaqvjhcaexkB3owfi2PddFenWUEwMNkiXw?download=1
				
					dpkg -i linux-image-d9.deb
					dpkg -i linux-headers-d9.deb
				
					#kernel_version="5.5.5"
				else
					echo -e "${Error} 还在用32位内核，别再见了 !" && exit 1
				fi
			elif [[ ${version} = "10" ]]; then
				if [[ ${bit} = "x86_64" ]]; then
					wget -N -O linux-image-d10.deb https://chinagz2018-my.sharepoint.com/:u:/g/personal/ylx_chinagz2018_onmicrosoft_com/EX1N_JVwmSJFs4RQ7LqgQzcBurXyK2qUV9EnjYVWqGMs3Q?download=1
					wget -N -O linux-headers-d10.deb https://chinagz2018-my.sharepoint.com/:u:/g/personal/ylx_chinagz2018_onmicrosoft_com/EX4OVNaKJFtOhOH8US25-lEBeIr5WOi2rJGI55cTazMhdQ?download=1
				
					dpkg -i linux-image-d10.deb
					dpkg -i linux-headers-d10.deb
				
					kernel_version="5.7.7"
				else
					echo -e "${Error} 还在用32位内核，别再见了 !" && exit 1
				fi
			fi
		elif [[ "${release}" == "ubuntu" ]]; then
			if [[ ${version} = "16" ]]; then
				if [[ ${bit} = "x86_64" ]]; then
					wget -N -O linux-image-u16.deb https://chinagz2018-my.sharepoint.com/:u:/g/personal/ylx_chinagz2018_onmicrosoft_com/ERyDAcgbNptBjPGywtyy4zwB1S14VXAHEraobteVekwcNQ?download=1
					wget -N -O linux-headers-u16.deb https://chinagz2018-my.sharepoint.com/:u:/g/personal/ylx_chinagz2018_onmicrosoft_com/Eeka3lp7WAFOugowSi1F_eYBUXXdnx1dp1rI_aTg9XYtww?download=1
				
					dpkg -i linux-image-u16.deb
					dpkg -i linux-headers-u16.deb
				
					#kernel_version="5.4.14"
				else
					echo -e "${Error} 还在用32位内核，别再见了 !" && exit 1
				fi
		
			elif [[ ${version} = "18" ]]; then
				if [[ ${bit} = "x86_64" ]]; then
					wget -N -O linux-image-u18.deb https://chinagz2018-my.sharepoint.com/:u:/g/personal/ylx_chinagz2018_onmicrosoft_com/ERvqNJiLLrpKnLO9z3vCdZIB-GwZr2AKXO7t6dpTbEotmQ?download=1
					wget -N -O linux-headers-u18.deb https://chinagz2018-my.sharepoint.com/:u:/g/personal/ylx_chinagz2018_onmicrosoft_com/EWZdQsfxE5lAvL3xTHxS9H4BjYijqpxP-TokL1hLag7PIw?download=1
				
					dpkg -i linux-image-u18.deb
					dpkg -i linux-headers-u18.deb
				
					#kernel_version="5.4.14"
				else
					echo -e "${Error} 还在用32位内核，别再见了 !" && exit 1
				fi
			elif [[ ${version} = "19" ]]; then
				if [[ ${bit} = "x86_64" ]]; then
					wget -N -O linux-image-u19.deb https://chinagz2018-my.sharepoint.com/:u:/g/personal/ylx_chinagz2018_onmicrosoft_com/ESEgC1nVDmRFmQeJnSWujz4BYy-tnZa64EgX60dIQJjW9Q?download=1
					wget -N -O linux-headers-u19.deb https://chinagz2018-my.sharepoint.com/:u:/g/personal/ylx_chinagz2018_onmicrosoft_com/EcsC0aEv8KBHhG3jwRaF8r4BLqvFwBLK5JGy83dfhdV-zQ?download=1
				
					dpkg -i linux-image-u19.deb
					dpkg -i linux-headers-u19.deb
				
					#kernel_version="5.4.14"
				else
					echo -e "${Error} 还在用32位内核，别再见了 !" && exit 1
				fi
			elif [[ ${version} = "20" ]]; then
				if [[ ${bit} = "x86_64" ]]; then
					wget -N -O linux-image-u20.deb https://chinagz2018-my.sharepoint.com/:u:/g/personal/ylx_chinagz2018_onmicrosoft_com/EYqsZWWiss1JvRW5gsfGxckBQhV1IiQgOqzlFmzUJAAdpg?download=1
					wget -N -O linux-headers-u20.deb https://chinagz2018-my.sharepoint.com/:u:/g/personal/ylx_chinagz2018_onmicrosoft_com/ESJMvds9OwRKlSPEoHYeMPcB4CIbP9rO3hcdGmzAsJqCVQ?download=1
				
					dpkg -i linux-image-u20.deb
					dpkg -i linux-headers-u20.deb
				
					#kernel_version="5.4.14"
				else
					echo -e "${Error} 还在用32位内核，别再见了 !" && exit 1
				fi	
			fi				
			
		#else	
		#	wget http://security.debian.org/debian-security/pool/updates/main/o/openssl/libssl1.0.0_1.0.1t-1+deb8u10_amd64.deb
		#	wget -N --no-check-certificate http://${github}/bbr/debian-ubuntu/linux-headers-${kernel_version}-all.deb
		#	wget -N --no-check-certificate http://${github}/bbr/debian-ubuntu/${bit}/linux-headers-${kernel_version}.deb
		#	wget -N --no-check-certificate http://${github}/bbr/debian-ubuntu/${bit}/linux-image-${kernel_version}.deb
	
		#	dpkg -i libssl1.0.0_1.0.1t-1+deb8u10_amd64.deb
		#	dpkg -i linux-headers-${kernel_version}-all.deb
		#	dpkg -i linux-headers-${kernel_version}.deb
		#	dpkg -i linux-image-${kernel_version}.deb
		fi
	fi
	
	cd .. && rm -rf bbr	
	
	detele_kernel
	BBR_grub
	echo -e "${Tip} ${Red_font_prefix}请检查上面是否有内核信息，无内核千万别重启${Font_color_suffix}"
	echo -e "${Tip} ${Red_font_prefix}rescue不是正常内核，要排除这个${Font_color_suffix}"
	echo -e "${Tip} 重启VPS后，请重新运行脚本开启${Red_font_prefix}BBR${Font_color_suffix}"	
	echo -e "${Tip} 内核安装完毕，请参考上面的信息检查是否安装成功及手动调整内核启动顺序"
	remove_all
	echo "net.core.default_qdisc=cake" >> /etc/sysctl.conf
	echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
	sysctl -p
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
}
beikong98_chushihua(){
echo "标准测速脚本"
curl -fsL https://ilemonra.in/LemonBenchIntl | bash -s spfast
}
beikong99_chushihua(){
echo "脚本升级中"
rm -rf /usr/bin/coll
curl -o /usr/bin/coll -Ls https://raw.githubusercontent.com/54665/sspanel_coll/master/colld.sh
chmod +x /usr/bin/coll
}
echo && echo -e " 合集脚本 V1.0.1 。

 ${Green_font_prefix}1.${Font_color_suffix} BBR脚本国外
 ${Green_font_prefix}2.${Font_color_suffix} BBR脚本国内
 ${Green_font_prefix}3.${Font_color_suffix} AWS流量统计脚本
 ${Green_font_prefix}4.${Font_color_suffix} 创建ROOT用户
 ${Green_font_prefix}5.${Font_color_suffix} 安装DocKer
 ${Green_font_prefix}6.${Font_color_suffix} DocKer自启
 ${Green_font_prefix}7.${Font_color_suffix} V2-UI
 ${Green_font_prefix}97.${Font_color_suffix} 节点一键
 ${Green_font_prefix}98.${Font_color_suffix} 标准测速脚本
 ${Green_font_prefix}99.${Font_color_suffix} 脚本升级" && echo
stty erase '^H' && read -p " 请输入数字 [1-99]:" num
case "$num" in
	1)
	beikong0_chushihua
	;;
	2)
	beikong1_chushihua
	;;
	3)
	beikong2_chushihua
	;;
	4)
	beikong3_chushihua
	;;
	5)
	beikong4_chushihua
	;;
	6)
	beikong5_chushihua
	;;
	7)
	beikong6_chushihua
	;;
	97)
	beikong97_chushihua
	;;
	98)
	beikong98_chushihua
	;;
	99)
	beikong99_chushihua
	;;
	
	*)
	echo "请输入正确数字 [1-99]"
	;;
esac