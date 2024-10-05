#!/bin/bash

# 检查并安装iptables
if ! command -v iptables &> /dev/null; then
    echo "iptables未安装，正在安装..."
    apt-get update
    apt-get install -y iptables
else
    echo "iptables已安装"
fi

# 检查并安装iptables-persistent
if ! dpkg -l | grep -q iptables-persistent; then
    echo "iptables-persistent未安装，正在安装..."
    apt-get install -y iptables-persistent
else
    echo "iptables-persistent已安装"
fi

# 清除现有的规则
iptables -F
iptables -t nat -F

# 启用数据转发
echo "Enabling IP forwarding..."
echo 1 > /proc/sys/net/ipv4/ip_forward
echo 1 > /proc/sys/net/ipv6/conf/all/forwarding

# 选择协议
echo "Select the protocol for forwarding:"
echo "1. IPv4"
echo "2. IPv6"
read -p "Enter your choice (1 or 2): " protocol_choice

# 获取特定网络接口
interface=$(ip addr show | awk '/state UP/ {print $2}' | sed 's/:$//g' | head -n 1)

# 协议选择
read -p "Select the forwarding protocol (tcp/udp): " protocol
protocol=${protocol:-tcp}  # 默认tcp

if [[ $protocol != "tcp" && $protocol != "udp" ]]; then
    echo "Invalid protocol choice. Exiting."
    exit 1
fi

# 获取本机的IPv4和IPv6地址
ipv4_address=$(hostname -I | awk '{print $1}')
ipv6_address=$(ip -6 addr show | awk '/inet6/ && /scope global/ {print $2}' | sed 's%/%[%g; s%$%]:%g' | head -n 1)


if [[ $protocol_choice -eq 1 ]]; then
    # IPv4配置
    read -p "Enter the local port to forward: " local_port
    read -p "Enter the target IPv4 address: " target_ip
    read -p "Enter the target port: " target_port

    # 设置 PREROUTING 规则
    if [[ $protocol == "tcp" ]]; then
        iptables -t nat -A PREROUTING -i $interface -p tcp --dport $local_port -j DNAT --to-destination $target_ip:$target_port
        iptables -t nat -A PREROUTING -i $interface -p udp --dport $local_port -j DNAT --to-destination $target_ip:$target_port
    elif [[ $protocol == "udp" ]]; then
        iptables -t nat -A PREROUTING -i $interface -p udp --dport $local_port -j DNAT --to-destination $target_ip:$target_port
    fi

    # 设置 POSTROUTING 规则
    if [[ $protocol == "tcp" ]]; then
        iptables -t nat -A POSTROUTING -o $interface -p tcp -d $target_ip --dport $target_port -j SNAT --to-source $ipv4_address
        iptables -t nat -A POSTROUTING -o $interface -p udp -d $target_ip --dport $target_port -j SNAT --to-source $ipv4_address
    elif [[ $protocol == "udp" ]]; then
        iptables -t nat -A POSTROUTING -o $interface -p udp -d $target_ip --dport $target_port -j SNAT --to-source $ipv4_address
    fi

    # 设置 FORWARD 规则
    iptables -A FORWARD -i $interface -o $interface -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    if [[ $protocol == "tcp" ]]; then
        iptables -A FORWARD -i $interface -p tcp -d $target_ip --dport $target_port -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
        iptables -A FORWARD -i $interface -p udp -d $target_ip --dport $target_port -j ACCEPT
    elif [[ $protocol == "udp" ]]; then
        iptables -A FORWARD -i $interface -p udp -d $target_ip --dport $target_port -j ACCEPT
    fi


elif [[ $protocol_choice -eq 2 ]]; then
    # IPv6配置
    read -p "Enter the local port to forward: " local_port
    read -p "Enter the target IPv6 address (use [IPV6_ADDRESS]:PORT format): " target_ip_port
    # 提取IPv6地址和端口
    target_ip=$(echo "$target_ip_port" | grep -oP '\[\K[^\]]+')
    target_port=$(echo "$target_ip_port" | grep -oP ':(\d+)$' | sed 's/://')

    # 确保目标地址和端口不为空
    if [[ -z "$target_ip" || -z "$target_port" ]]; then
        echo "Invalid target address or port. Exiting."
        exit 1
    fi

    # 调试输出
    echo "Forwarding from port $local_port to [$target_ip]:$target_port"

    # 设置 NAT 规则
    if [[ $protocol == "tcp" ]]; then
        # TCP转发
        ip6tables -t nat -A PREROUTING -i $interface -p tcp --dport $local_port -j DNAT --to-destination $target_ip:$target_port
        ip6tables -t nat -A POSTROUTING -o $interface -p tcp -d $target_ip --dport $target_port -j SNAT --to-source $ipv6_address

        # UDP转发
        ip6tables -t nat -A PREROUTING -i $interface -p udp --dport $local_port -j DNAT --to-destination $target_ip:$target_port
        ip6tables -t nat -A POSTROUTING -o $interface -p udp -d $target_ip --dport $target_port -j SNAT --to-source $ipv6_address
    elif [[ $protocol == "udp" ]]; then
        # 仅UDP转发
        ip6tables -t nat -A PREROUTING -i $interface -p udp --dport $local_port -j DNAT --to-destination $target_ip:$target_port
        ip6tables -t nat -A POSTROUTING -o $interface -p udp -d $target_ip --dport $target_port -j SNAT --to-source $ipv6_address
    fi
    
    # 设置 FORWARD 规则
    ip6tables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    if [[ $protocol == "tcp" ]]; then
        ip6tables -A FORWARD -p tcp -d $target_ip --dport $target_port -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
    elif [[ $protocol == "udp" ]]; then
        ip6tables -A FORWARD -p udp -d $target_ip --dport $target_port -j ACCEPT
    fi
    

else
    echo "Invalid choice. Exiting."
    exit 1
fi

# 设置日志记录（低级别，减少干扰）
iptables -A FORWARD -j LOG --log-prefix "Forwarded packet: " --log-level 4
# 设置ipv6日志记录
ip6tables -A FORWARD -j LOG --log-prefix "Forwarded IPv6 packet: " --log-level 4

# 保存配置
iptables-save > /etc/iptables/rules.v4
ip6tables-save > /etc/iptables/rules.v6

# 重启iptables服务
echo "Restarting iptables..."
systemctl restart netfilter-persistent

echo "已配置成功！"
