#!/bin/sh /etc/rc.common

START=99

SERVICE_DAEMONIZE=1
SERVICE_WRITE_PID=1
USE_PROCD=1
DIR=$(cat /etc/profile | grep clashdir | awk -F "\"" '{print $2}')

start_service() {
  $DIR/clash.sh start
  if [ "$?" = "0" ];then
    #使用procd创建clash后台进程
    procd_open_instance
    procd_set_param respawn
    procd_set_param stderr 0
    procd_set_param stdout 0
    procd_set_param command $DIR/clash -d $DIR
    procd_close_instance
  fi
}

stop_service() {
  $DIR/clash.sh stop
}
