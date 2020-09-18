#!/bin/bash
#
# 初始化
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

        echo "初始化"
    	echo "开始安装依赖"
		echo "安装依赖"
		yum install wget -y
		yum install epel-release -y
		apt-get install wget -y
		apt-get install epel-release -y
		
	echo "正在下载管理脚本"
    curl -o /usr/bin/coll -Ls https://raw.githubusercontent.com/54665/sspanel_coll/master/colld.sh
	chmod +x /usr/bin/coll
    echo "安装完成，请输入 coll 打开脚本菜单"