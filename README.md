# wifi_crack_windows
wifi crack project for windows

如使用本工程代码用于商业软件, 请在Thanks列表里署个名boywhp@126.com, 谢谢!

我的weibo: http://weibo.com/u/2702964511 欢迎打赏

1. 命令行参数

/Install	安装卸载wifi过滤驱动，未指定情况下，程序会自动检测并安装驱动
/Uninstall	卸载wifi过滤驱动
/Deauth 	发起deauth攻击，默认会不发起Deauth攻击
/Dump		将原始数据dump到dump.pcap文件
/Channel 1-13	指定wifi频道(默认会对整个1-13频道进行扫描，每个频道10s)
/Fakeap		自动应答wifi Prob实施FakeAP攻击
/Bssid	bc:d1:77:f9:1d:cc	指定Bssid

2. 常用场景

/Deauth /Channel x	对指定的频道自动进行wifi攻击，并抓取EAPOL握手包，容易被用户察觉
/Channel x	对指定频道进行嗅探，抓取EAPOL握手包，适合长时间运行

3. 注意事项

win7运行需要管理员权限
部分wifi硬件（Ralink）在程序Deauth攻击退出后可能会出现无法正常工作，请手工重置wifi网卡
Deauth攻击需要wifi硬件驱动支持，或者手工patch，请在patch目录里面查找是否有对应的驱动
部分网卡需要连接成功一次才能抓包
