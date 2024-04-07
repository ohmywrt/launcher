# 超便捷

*** 仅适用于 OpenWrt (iptables) ***

使用 fakeip 可选指定前置DNS分流 内置分流处理

## 初始化环境

下载的所有内容放到 /etc/sb`/etc/profile`确保存在
```shell
alias sb="sh /etc/sb/sb.sh"
export sbdir="/etc/sb"
```

## 复制服务 依赖服务

```shell
cp sb.services.sh /etc/init.d/sb
chmod +x /etc/init.d/sb
```

## 注意事项
1. 确保你的环境中没有DNS转发相关的规则 验证方式 iptables -n -t nat -L | grep 53
2. 不要和其他任何软件共用，删干净，且已停止服务，否则规则互相影响


![17a093ef2beadef39c20abcdf55c07e3](https://github.com/ohmywrt/launcher/assets/9210430/265716dd-6bae-41cd-9536-48a033fe7454)
