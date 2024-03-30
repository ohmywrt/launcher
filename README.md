# 超便捷

*** 仅适用于 OpenWrt (iptables) ***

1. 模式1 fakeip 需要有一个前置DNS分流域名，否则CN流量全部进内核（小白不要尝试）
2. 模式2 redir 常规模式


## 初始化环境

下载的所有内容放到 /etc/clash，且`/etc/profile`确保存在
```shell
alias clash="sh /etc/clash/clash.sh"
export clashdir="/etc/clash"
```

## 复制服务 依赖服务

```shell
cp clash.services.sh /etc/init.d/clash
chmod +x /etc/init.d/clash
```
## 使用

![image](https://github.com/luckyyyyy/launcher/assets/9210430/27ac7d7c-a80a-4951-a985-5a25959387b5)

## 注意事项
1. 确保你的环境中没有DNS转发相关的规则 验证方式 iptables -n -t nat -L | grep 53
2. 不要和其他任何软件共用，删干净，且已停止服务，否则规则互相影响
