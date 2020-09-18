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
wget -N "https://github.000060000.xyz/tcp.sh"
chmod +x tcp.sh
./tcp.sh
1
./tcp.sh
12
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
	beikong98_chushihua
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