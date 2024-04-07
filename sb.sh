#!/bin/sh
log() {
    if [ "$2" = "2" ]; then
        printf "\033[31m[%s]\033[0m %s\n" "$(date '+%Y-%m-%d %H:%M:%S')" "$1"
    elif [ "$2" = "1" ]; then
        printf "\033[33m[%s]\033[0m %s\n" "$(date '+%Y-%m-%d %H:%M:%S')" "$1"
    else
        printf "\033[32m[%s]\033[0m %s\n" "$(date '+%Y-%m-%d %H:%M:%S')" "$1"
    fi
}

rootdir=$(cat /etc/profile | grep sbdir | awk -F "\"" '{print $2}')
# 如果没有rootdir则报错
if [ -z "$rootdir" ]; then
  log "not found sbdir in /etc/profile" 2
  log "please write export sbdir=\"/etc/sb\""
  exit 1
fi
config_file_path=$rootdir/config.ini
if [ ! -f "$config_file_path" ]; then
  log "config.ini not found" 2
  exit 1
fi
# fwmark
firewall_mark=0x2333
# tproxy端口
tproxy_port=7893
# 前置DNS端口
front_dns_port=5553
sb_dns_port=1053
# LAN网关IP 用于挟持转发过来的 dns v4
lan_gateway_ipv4=$(ip addr show br-lan | grep 'inet ' | awk '{print $2}' | cut -d'/' -f1)
while IFS='=' read -r key value || [ -n "$value" ]; do
    case "$key" in \#*|"") continue ;; esac
    key=$(echo "$key" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    value=$(echo "$value" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    eval "$(echo "$key" | sed 's/[^a-zA-Z0-9_]/_/g')='$value'"
done < "$config_file_path"
host_ipv4=$(ip a 2>&1 | grep -w 'inet' | grep 'global' | grep 'br' | grep -Ev 'iot|metric' | grep -E ' 1(92|0|72)\.' | sed 's/.*inet.//g' | sed 's/br.*$//g')
reserve_ipv4="0.0.0.0/8 10.0.0.0/8 127.0.0.0/8 100.64.0.0/10 169.254.0.0/16 172.16.0.0/12 192.168.0.0/16 224.0.0.0/4 240.0.0.0/4"
if [ -z "$front_dns_port" ]; then
  log "front_dns_port is empty, use sb_dns_port" 1
  # log "skip CN will not work in iptables"
  front_dns_port=$sb_dns_port
fi

update_config() {
  local key=$1
  local value=$2
  if grep -q "^[[:space:]]*$key[[:space:]]*=" "$config_file_path"; then
    sed -i "s|^[[:space:]]*$key[[:space:]]*=.*|$key=$value|" "$config_file_path"
  else
    if [ "$(tail -c1 "$config_file_path")" ]; then
      echo >> "$config_file_path"
    fi
    echo "$key=$value" >> "$config_file_path"
  fi
}


stop() {
  ip rule del fwmark $firewall_mark table 100 > /dev/null 2>&1
  ip route del local default dev lo table 100 > /dev/null 2>&1
  # 清理dns转发 v4
  iptables -t nat -D PREROUTING -p tcp --dport 53 -d $lan_gateway_ipv4 -j sb_dns 2> /dev/null
  iptables -t nat -D PREROUTING -p udp --dport 53 -d $lan_gateway_ipv4 -j sb_dns 2> /dev/null
  iptables -t nat -F sb_dns 2> /dev/null
  iptables -t nat -X sb_dns 2> /dev/null
  # 清理dns转发 v6
  ip6tables -t nat -D PREROUTING -p tcp --dport 53 -j sbv6_dns 2> /dev/null
  ip6tables -t nat -D PREROUTING -p udp --dport 53 -j sbv6_dns 2> /dev/null
  ip6tables -t nat -F sbv6_dns 2> /dev/null
  ip6tables -t nat -X sbv6_dns 2> /dev/null
  # 清理 mangle 规则
  iptables -t mangle -D PREROUTING -j sb > /dev/null 2>&1
  iptables -t mangle -D PREROUTING -d 198.18.0.0/16 -j sb 2> /dev/null
  iptables -t mangle -F sb 2> /dev/null
  iptables -t mangle -X sb 2> /dev/null
  ipset destroy cn_ip 2> /dev/null
  log "TPROXY规则清理完成"
}

start() {
  if iptables -t mangle -L | grep -q sb; then
      log "sb rule already exists in iptables." 1
      log "try to stop sb first" 1
      service sb stop > /dev/null 2>&1
      service sb start
      return
  fi
  for i in $(seq 1 20)
  do
    if netstat -anp | grep 'LISTEN' | grep sing-box > /dev/null; then
      netstat -anp | grep 'LISTEN' | grep sing-box
      break
    else
      if [ $i -eq 20 ]; then
        log "sing-box start failed" 2
        exit 1
      fi
      log "Waiting for sing-box to start..."
      sleep 1
    fi
  done
  log "start set sb tproxy"
  modprobe xt_TPROXY &>/dev/null
  # 配置CN列表
  # log "创建CN IPSET"
  ipset create cn_ip hash:net
  awk '!/^$/&&!/^#/{printf("add cn_ip %s\n",$0)}' $rootdir/cn_ip.txt | ipset restore
  # log "开始配置TPROXY"
  ip rule add fwmark $firewall_mark table 100
  ip route add local default dev lo table 100
  iptables -t mangle -N sb
  iptables -t mangle -A sb -p udp --dport 53 -j RETURN
  # 局域网流量不要进来
  for ip in $host_ipv4 $reserve_ipv4; do #跳过目标保留地址及目标本机网段
    # log "跳过 $ip"
    iptables -t mangle -A sb -d $ip -j RETURN
  done
  # 跳过CN IP
  # log "跳过CN IP"
  iptables -t mangle -A sb -m set --match-set cn_ip dst -j RETURN
  # 黑名单
  if [ -f "$rootdir/blacklist" ]; then
    for mac in $(cat $rootdir/blacklist); do #mac黑名单
      # log "跳过 $mac"
      iptables -t mangle -A sb -m mac --mac-source $mac -j RETURN
    done
  fi
  # 代理本机局域网流量
  for ip in $host_ipv4; do
    # log "代理 $ip"
    iptables -t mangle -A sb -p tcp -s $ip -j TPROXY --on-port $tproxy_port --tproxy-mark $firewall_mark
    iptables -t mangle -A sb -p udp -s $ip -j TPROXY --on-port $tproxy_port --tproxy-mark $firewall_mark
  done
  iptables -t mangle -A PREROUTING -j sb
  iptables -t mangle -A PREROUTING -d 198.18.0.0/16 -j sb

  # 配置DNS
  # log "开始配置DNS"
  iptables -t nat -N sb_dns

  if [ -f "$rootdir/blacklist" ]; then
    for mac in $(cat $rootdir/blacklist); do #mac黑名单
      # log "跳过 DNS $mac"
      iptables -t nat -A sb_dns -m mac --mac-source $mac -j RETURN
    done
  fi
  iptables -t nat -A sb_dns -p tcp -j REDIRECT --to $front_dns_port
  iptables -t nat -A sb_dns -p udp -j REDIRECT --to $front_dns_port
  log "DNS转发到 $front_dns_port"
  iptables -t nat -I PREROUTING -p tcp -d $lan_gateway_ipv4 --dport 53 -j sb_dns
  iptables -t nat -I PREROUTING -p udp -d $lan_gateway_ipv4 --dport 53 -j sb_dns


  # dns_v6
  # log "开始配置DNSv6"
  ip6tables -t nat -N sbv6_dns > /dev/null 2>&1
  if [ -f "$rootdir/blacklist" ]; then
    for mac in $(cat $rootdir/blacklist); do #mac黑名单
      # log "跳过 DNSv6 $mac"
      ip6tables -t nat -A sbv6_dns -m mac --mac-source $mac -j RETURN
    done
  fi
  # dnsv6 全部挟持
  ip6tables -t nat -A sbv6_dns -p tcp -j REDIRECT --to $front_dns_port
  ip6tables -t nat -A sbv6_dns -p udp -j REDIRECT --to $front_dns_port
  ip6tables -t nat -I PREROUTING -p tcp --dport 53 -j sbv6_dns
  ip6tables -t nat -I PREROUTING -p udp --dport 53 -j sbv6_dns
  # log "TPROXY配置完成"
  iptables -t nat -L sb_dns -n
  iptables -t mangle -L sb -n
  echo -e "\033[32msb服务已启动\033[0m http://$lan_gateway_ipv4:9999/ui"
}

update_geoip() {
  if [ -z "$geoip_update_url" ]; then
    log "geoip_update_url is empty" 2
    exit 1
  fi
  log "正在下载 GeoIP 数据库..."
  curl -#SL -o $rootdir/cn_ip.txt $geoip_update_url
  if [ $? -ne 0 ]; then
    log "下载 GeoIP 数据库失败，请检查网络连接" 2
    exit 1
  fi
  log "更新 GeoIP 数据库完成"
  # 如果存在 ipset 则更新
  if ipset list cn_ip > /dev/null 2>&1; then
    ipset flush cn_ip
    awk '!/^$/&&!/^#/{printf("add cn_ip %s\n",$0)}' $rootdir/cn_ip.txt | ipset restore
    log "刷新 GeoIP 数据库完成"
  fi
}


# crontab 使用
update_subscribe() {
  local url=$subscribe_url
  if [ -z "$url" ]; then
    log "订阅链接为空，请先在config.ini中配置subscribe_url字段" 2
    exit 1
  fi
  log "正在下载订阅链接: $url"
  curl -#SL -A "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36" $url -o /tmp/sb_yaml_temp
  if [ $? -ne 0 ]; then
      log "下载订阅链接失败，请检查网络连接" 2
      exit 1
  fi
  $rootdir/sing-box check -c /tmp/sb_yaml_temp
  if [ $? -ne 0 ]; then
      log "订阅链接解析失败，请检查订阅链接" 2
      exit 1
  fi
  mv /tmp/sb_yaml_temp $rootdir/config.json
  service sb start
}

subscribe() {
  local url=${1:-$subscribe_url}
  # 如果没有订阅链接则报错
  if [ -z "$url" ]; then
    log "订阅链接为空，请先在config.ini中配置subscribe_url字段" 2
    exit 1
  fi
  # 使用 curl 下载订阅链接
  # local yaml_content=$(curl -sSL $url)
  # 输出正在下载 某个 url
  log "正在下载订阅链接: $url"
  curl -#SL -A "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36" $url -o /tmp/sb_yaml_temp
  # 如果下载失败则退出
  if [ $? -ne 0 ]; then
      log "下载订阅链接失败，请检查网络连接" 2
      exit 1
  fi
  log "开始测试配置文件..."
  $rootdir/sing-box check -c /tmp/sb_yaml_temp
  if [ $? -ne 0 ]; then
      log "订阅链接解析失败，请检查订阅链接" 2
      exit 1
  fi
  # 将订阅链接写入配置文件
  mv /tmp/sb_yaml_temp $rootdir/config.json
  update_config "subscribe_url" "$url"
  read -p "订阅链接已更新 是否重启sb? [1/0]: " replace
  if [ "$replace" = "1" ]; then
    service sb start
  fi
}

welcome() {
  # 检查是否有进程
  local pid=$(pidof sing-box | awk '{print $NF}')
  echo -----------------------------------------------
  echo -e "\033[30;46m欢迎使用OhMySB！\033[0m                版本: \033[32m1.0.0\033[0m"
  # 显示DNS模式
  if [ -n "$pid" ];then
    echo -e "sb进程: \033[32m$pid\033[0m"
    local rss=`cat /proc/$pid/status | grep -w VmRSS | awk '{print $2,$3}'`
    local s=$((($(date +%s) - $(date +%s -r /proc/$pid))))
    echo -e "当前内存占用: \033[44m"$rss"\033[0m                已运行: \033[44m$((s/3600))小时$(((s%3600)/60))分钟$((s%60))秒\033[0m"
  else
    echo -e "SB服务: \033[31m未运行\033[0m"
  fi
  echo -----------------------------------------------
  # 启动和重启是绿色的文字 sb 服务器是白色的
  echo -e "1 \e[32m启动/重启\e[0msb服务"
  echo -e "2 \e[31m停止\e[0msb服务"
  echo -e "3 \e[33m设置\e[0m订阅链接"
  echo -e "4 \e[33m刷新\e[0m订阅链接"
  echo -e "5 \e[32m检查\e[0m配置文件"
  echo -e "6 \e[34m更新\e[0mGeoIP数据库"
  echo -----------------------------------------------
  echo -e "0 退出"
  echo -----------------------------------------------
  read -p "请输入操作编号: " num
  case $num in
    1)
      service sb start
      welcome
      ;;
    2)
      service sb stop >> /dev/null 2>&1
      # 死循环检查是否有进程
      while true; do
        local pid=$(pidof sb | awk '{print $NF}')
        if [ -z "$pid" ]; then
          log "sb服务已停止" 1
          break
        fi
      done
      welcome
      ;;
    3)
      read -p "请输入订阅链接: " url
      # 正则匹配是否是url
      if ! echo "$url" | grep -q "http"; then
        log "请输入正确的订阅链接" 2
      fi
      subscribe $url
      ;;
    4)
      subscribe
      ;;
    5)
      $rootdir/sing-box check -c $rootdir/config.json
      if [ $? -eq 0 ]; then
        log "配置文件检查通过" 1
      else
        log "配置文件检查失败" 2
      fi
      ;;
    6)
      update_geoip
      ;;
    0)
      exit 0
      ;;
    *)
      log "输入错误" 2
      welcome
      ;;
  esac
}

case "$1" in
  subscribe)
    subscribe "$2"
    ;;
  update_subscribe)
    update_subscribe
    ;;
  start_tproxy)
    start
    ;;
  stop_tproxy)
    stop
    ;;
  start)
    service sb start
    ;;
  stop)
    service sb stop
    ;;
  *)
    welcome
    ;;
esac