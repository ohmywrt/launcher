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

rootdir=$(cat /etc/profile | grep clashdir | awk -F "\"" '{print $2}')
# 如果没有rootdir则报错
if [ -z "$rootdir" ]; then
  log "not found clashdir in /etc/profile" 2
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
# fakeip / redir
dns_mode=fakeip
# 前置DNS端口
front_dns_port=5553
clash_dns_port=1053
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
  log "front_dns_port is empty, use clash_dns_port" 1
  log "skip CN will not work in iptables"
  front_dns_port=$clash_dns_port
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
  iptables -t nat -D PREROUTING -p tcp --dport 53 -d $lan_gateway_ipv4 -j clash_dns 2> /dev/null
  iptables -t nat -D PREROUTING -p udp --dport 53 -d $lan_gateway_ipv4 -j clash_dns 2> /dev/null
  iptables -t nat -F clash_dns 2> /dev/null
  iptables -t nat -X clash_dns 2> /dev/null
  # 清理dns转发 v6
  ip6tables -t nat -D PREROUTING -p tcp --dport 53 -j clashv6_dns 2> /dev/null
  ip6tables -t nat -D PREROUTING -p udp --dport 53 -j clashv6_dns 2> /dev/null
  ip6tables -t nat -F clashv6_dns 2> /dev/null
  ip6tables -t nat -X clashv6_dns 2> /dev/null
  # 清理 mangle 规则
  iptables -t mangle -D PREROUTING -j clash > /dev/null 2>&1
  iptables -t mangle -D PREROUTING -d 198.18.0.0/16 -j clash 2> /dev/null
  iptables -t mangle -F clash 2> /dev/null
  iptables -t mangle -X clash 2> /dev/null
  ipset destroy cn_ip 2> /dev/null
  log "TPROXY规则清理完成"
}

start() {
  modprobe xt_TPROXY &>/dev/null
  if iptables -t mangle -L | grep -q clash; then
      log "clash rule already exists in iptables." 1
      log "try to stop clash first" 1
      service clash stop > /dev/null 2>&1
  fi
  # 配置CN列表
  # log "创建CN IPSET"
  ipset create cn_ip hash:net
  awk '!/^$/&&!/^#/{printf("add cn_ip %s\n",$0)}' $rootdir/cn_ip.txt | ipset restore
  # log "开始配置TPROXY"
  ip rule add fwmark $firewall_mark table 100
  ip route add local default dev lo table 100
  iptables -t mangle -N clash
  iptables -t mangle -A clash -p udp --dport 53 -j RETURN
  # 局域网流量不要进来
  for ip in $host_ipv4 $reserve_ipv4; do #跳过目标保留地址及目标本机网段
    # log "跳过 $ip"
    iptables -t mangle -A clash -d $ip -j RETURN
  done
  # 跳过CN IP
  # log "跳过CN IP"
  iptables -t mangle -A clash -m set --match-set cn_ip dst -j RETURN
  # 黑名单
  if [ -f "$rootdir/blacklist" ]; then
    for mac in $(cat $rootdir/blacklist); do #mac黑名单
      # log "跳过 $mac"
      iptables -t mangle -A clash -m mac --mac-source $mac -j RETURN
    done
  fi
  # 代理本机局域网流量
  for ip in $host_ipv4; do
    # log "代理 $ip"
    iptables -t mangle -A clash -p tcp -s $ip -j TPROXY --on-port $tproxy_port --tproxy-mark $firewall_mark
    iptables -t mangle -A clash -p udp -s $ip -j TPROXY --on-port $tproxy_port --tproxy-mark $firewall_mark
  done
  iptables -t mangle -A PREROUTING -j clash
  # fakeip
  if [ "$dns_mode" = "fakeip" ]; then
    iptables -t mangle -A PREROUTING -d 198.18.0.0/16 -j clash
  fi

  # 配置DNS
  # log "开始配置DNS"
  iptables -t nat -N clash_dns

  if [ -f "$rootdir/blacklist" ]; then
    for mac in $(cat $rootdir/blacklist); do #mac黑名单
      # log "跳过 DNS $mac"
      iptables -t nat -A clash_dns -m mac --mac-source $mac -j RETURN
    done
  fi
  if [ "$dns_mode" = "fakeip" ]; then
    iptables -t nat -A clash_dns -p tcp -j REDIRECT --to $front_dns_port
    iptables -t nat -A clash_dns -p udp -j REDIRECT --to $front_dns_port
    log "fakeip模式下 DNS转发到 $front_dns_port"
  else
    iptables -t nat -A clash_dns -p tcp -j REDIRECT --to $clash_dns_port
    iptables -t nat -A clash_dns -p udp -j REDIRECT --to $clash_dns_port
    log "redir模式下 DNS转发到 $clash_dns_port"
  fi
  iptables -t nat -I PREROUTING -p tcp -d $lan_gateway_ipv4 --dport 53 -j clash_dns
  iptables -t nat -I PREROUTING -p udp -d $lan_gateway_ipv4 --dport 53 -j clash_dns


  # dns_v6
  # log "开始配置DNSv6"
  ip6tables -t nat -N clashv6_dns > /dev/null 2>&1
  if [ -f "$rootdir/blacklist" ]; then
    for mac in $(cat $rootdir/blacklist); do #mac黑名单
      # log "跳过 DNSv6 $mac"
      ip6tables -t nat -A clashv6_dns -m mac --mac-source $mac -j RETURN
    done
  fi
  # dnsv6 全部挟持
  if [ "$dns_mode" = "fakeip" ]; then
    ip6tables -t nat -A clashv6_dns -p tcp -j REDIRECT --to $front_dns_port
    ip6tables -t nat -A clashv6_dns -p udp -j REDIRECT --to $front_dns_port
  else
    ip6tables -t nat -A clashv6_dns -p tcp -j REDIRECT --to $clash_dns_port
    ip6tables -t nat -A clashv6_dns -p udp -j REDIRECT --to $clash_dns_port
  fi
  ip6tables -t nat -I PREROUTING -p tcp --dport 53 -j clashv6_dns
  ip6tables -t nat -I PREROUTING -p udp --dport 53 -j clashv6_dns
  # log "TPROXY配置完成"
  echo -e "\033[32mclash服务已启动\033[0m http://$lan_gateway_ipv4:9999/ui"
}


build_config() {
  local yaml=$(echo "$1" | awk '/^dns:/{flag=1; next}/^[a-z]/{flag=0}!flag')
  yaml=$(echo "$yaml" | awk '/^profile:/{flag=1; next}/^[a-z]/{flag=0}!flag')
  yaml=$(echo "$yaml" | awk '/^sniffer:/{flag=1; next}/^[a-z]/{flag=0}!flag')
  yaml=$(echo "$yaml" | sed '/^tproxy-port:/d')
  yaml=$(echo "$yaml" | sed '/^external-controller:/d')
  yaml=$(echo "$yaml" | sed '/^secret:/d')

  local enhanced_mode="fake-ip"
  [ "$dns_mode" != "fakeip" ] && enhanced_mode="redir-host"

  local dns_yaml="
${yaml}
dns:
  enable: true
  ipv6: true
  prefer-h3: false
  enhanced-mode: $enhanced_mode
  fake-ip-range: 198.18.0.1/16
  listen: 0.0.0.0:$clash_dns_port
  nameserver:
    - 127.0.0.1:53
  fallback:
    - https://1.1.1.1/dns-query
    - https://dns.cloudflare.com/dns-query
    - https://dns.google/dns-query
    - tls://1.1.1.1:853
    - tls://8.8.8.8:853
  default-nameserver:
    - 223.5.5.5
    - 119.28.28.28
  fake-ip-filter:
    - \"*.lan\"
    - \"*.williamchan.me\"
    - \"*.xincetest.com\"
  fallback-filter:
    geoip: true
    geoip-code: CN
sniffer:
  enable: true
profile:
  store-selected: true
  store-fake-ip: true
tproxy-port: $tproxy_port
external-controller: :9999
external-ui: ui
secret: 123456
"
  echo "$dns_yaml"

}
# crontab 使用
update_subscribe() {
  local url=$subscribe_url
  if [ -z "$url" ]; then
    log "订阅链接为空，请先在config.ini中配置subscribe_url字段" 2
    exit 1
  fi
  log "正在下载订阅链接: $url"
  local yaml_content=$(curl -#SL -A "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36" $url)
  if [ $? -ne 0 ]; then
      log "下载订阅链接失败，请检查网络连接" 2
      exit 1
  fi
  echo "$(build_config "$yaml_content")" > /tmp/clash_yaml_temp
  $rootdir/clash -t -d $rootdir -f /tmp/clash_yaml_temp
  if [ $? -ne 0 ]; then
      log "订阅链接解析失败，请检查订阅链接" 2
      exit 1
  fi
  mv /tmp/clash_yaml_temp $rootdir/config.yaml
  service clash start
}

update_country_db() {
  if [ -z "$country_db_update_url" ]; then
    log "country_update_url is empty" 2
    exit 1
  fi
  log "正在下载 Country 数据库..."
  curl -#SL -o $rootdir/Country.mmdb $country_db_update_url
  if [ $? -ne 0 ]; then
    log "下载 Country 数据库失败，请检查网络连接" 2
    exit 1
  fi
  log "更新 Country 数据库完成"
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
  local yaml_content=$(curl -#SL -A "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36" $url)
  # 如果下载失败则退出
  if [ $? -ne 0 ]; then
      log "下载订阅链接失败，请检查网络连接" 2
      exit 1
  fi
  # 随机输出到某个tmp文件中
  echo "$(build_config "$yaml_content")" > /tmp/clash_yaml_temp
  log "开始测试配置文件..."
  $rootdir/clash -t -d $rootdir -f /tmp/clash_yaml_temp
  if [ $? -ne 0 ]; then
      log "订阅链接解析失败，请检查订阅链接" 2
      exit 1
  fi
  # 将订阅链接写入配置文件
  mv /tmp/clash_yaml_temp $rootdir/config.yaml
  update_config "subscribe_url" "$url"
  read -p "订阅链接已更新 是否重启clash? [1/0]: " replace
  if [ "$replace" = "1" ]; then
    service clash start
  fi
}

welcome() {
  # 检查是否有进程
  local pid=$(pidof clash | awk '{print $NF}')
  echo -----------------------------------------------
  echo -e "\033[30;46m欢迎使用OhMyclash！\033[0m		版本: \033[32m1.0.0\033[0m"
  # 显示DNS模式
  echo -e "当前DNS模式: \033[32m$dns_mode\033[0m"
  if [ -n "$pid" ];then
    echo -e "clash进程: \033[32m$pid\033[0m"
    local rss=`cat /proc/$pid/status | grep -w VmRSS | awk '{print $2,$3}'`
    local s=$((($(date +%s) - $(date +%s -r /proc/$pid))))
    echo -e "当前内存占用: \033[44m"$rss"\033[0m		已运行: \033[44m$((s/3600))小时$(((s%3600)/60))分钟$((s%60))秒\033[0m"
  else
    echo -e "clash服务: \033[31m未运行\033[0m"
  fi
  echo -----------------------------------------------
  # 启动和重启是绿色的文字 clash 服务器是白色的
  echo -e "1 \e[32m启动/重启\e[0mclash服务"
  echo -e "2 \e[31m停止\e[0mclash服务"
  echo -e "3 \e[33m更换\e[0m订阅链接"
  echo -e "4 \e[33m刷新\e[0m订阅链接"
  # 切换dns模式
  if [ "$dns_mode" = "fakeip" ]; then
    echo -e "5 切换DNS模式为\e[33m为Redir\e[0m"
  else
    echo -e "5 切换DNS模式为\e[33mFakeIP\e[0m"
  fi
  # 更新geoip
  echo -e "6 更新\e[33mGeoIP\e[0m数据库（iptables绕过CN使用）"
  echo -e "7 更新\e[33mCountry\e[0m数据库（内核Geo规则使用）"
  echo -----------------------------------------------
  echo -e "0 退出"
  echo -----------------------------------------------
  read -p "请输入操作编号: " num
  case $num in
    1)
      service clash start
      welcome
      ;;
    2)
      service clash stop >> /dev/null 2>&1
      # 死循环检查是否有进程
      while true; do
        local pid=$(pidof clash | awk '{print $NF}')
        if [ -z "$pid" ]; then
          log "clash服务已停止" 1
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
      # 提示切换dns模式
      read -p "确认切换：请勿频繁切换，客户端有缓存问题 [1/0]: " dns
      if [ "$dns" != "1" ]; then
        welcome
      fi

      if [ "$dns_mode" = "fakeip" ]; then
        update_config "dns_mode" "redir"
        dns_mode="redir"
      else
        update_config "dns_mode" "fakeip"
        dns_mode="fakeip"
      fi
      local yaml=$(cat $rootdir/config.yaml)
      echo "$(build_config "$yaml")" > $rootdir/config.yaml
      service clash start
      welcome
      ;;
    6)
      update_geoip
      ;;
    7)
      update_country_db
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
  start)
    start
    ;;
  stop)
    stop
    ;;
  update_db)
    update_country_db
    update_geoip
    ;;
  *)
    welcome
    ;;
esac