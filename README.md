# 超便捷

*** 仅适用于 OpenWrt ***

1. 模式1 fakeip 需要有一个前置DNS分流域名，否则CN流量全部进内核（小白不要尝试）
2. 模式2 redir 常规模式


## 初始化环境

`/etc/profile`确保存在
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

clash