## 简介
za-mysql-sniffer 是一个基于 MySQL 协议的抓包工具，实时抓取并解析 MySQL Server 端或 Client 端请求并以特定格式输出。
该项目是在mysql-sniffer的基础进行了功能拓展。
原mysql-sniffer项目地址:https://github.com/Qihoo360/mysql-sniffer

相比mysql-sniffer,输出结果中新增了目的ip、源端口、目的端口、源mac、目的mac、sql执行状态等信息，并增加了将结果以json格式输出到tcp网络的功能。

## 使用
建议在 centos6.2 及以上编译安装，并用 root 运行。

### 依赖
glib2-devel(2.28.8)、libpcap-devel(1.4.0)、libnet-devel(1.1.6)

### 安装
```
cd za-mysql-sniffer
mkdir proj
cd proj
cmake ../
make
cd bin/
```
### 参数：

```
./mysql-sniffer -h
Usage mysql-sniffer [-d] -i eth0 -p 3306,3307,3308 -T 127.0.0.1:12345 -l /var/log/mysql-sniffer/ -e stderr
         [-d] -i eth0 -r 3000-4000
         -d daemon mode.
         -s how often to split the log file(minute, eg. 1440). if less than 0, split log everyday
         -i interface. Default to eth0
         -p port, default to 3306. Multiple ports should be splited by ','. eg. 3306,3307
            this option has no effect when -f is set.
         -r port range, Don't use -r and -p at the same time
         -l query log DIRECTORY. Make sure that the directory is accessible. Default to stdout.
         -e error log FILENAME or 'stderr'. if set to /dev/null, runtime error will not be recorded
         -f filename. use pcap file instead capturing the network interface
         -w white list. dont capture the port. Multiple ports should be splited by ','.
         -t truncation length. truncate long query if it's longer than specified length. Less than 0 means no truncation
         -n keeping tcp stream count, if not set, default is 65536. if active tcp count is larger than the specified count, mysql-sniffer will remove the oldest one
         -T query log sink to tcp
```

## 示例
### 1. 实时抓取某端口信息并打印到屏幕
输出格式为：访问用户，数据库类型(1表示mysql)，数据库名，返回数据行数，时间，耗时，sql执行结果状态，源ip，目的ip，源port，目的port，源mac，目的mac，执行语句 

```
root         1   NULL        1   2022-04-14 15:41:00              0      true    10.xx.xx.xx    10.xx.xx.xx    51532    3306   00:16:3e:ab:cc:a6      ee:ff:ff:ff:ff:ff       select @@version_comment limit 1...
root         1   NULL        0   2022-04-14 15:41:26              0      false   10.xx.xx.xx    10.xx.xx.xx    51532    3306   00:16:3e:ab:cc:a6      ee:ff:ff:ff:ff:ff       adsfasf...
root         1   NULL       15   2022-04-14 15:42:13             35      true    10.xx.xx.xx    10.xx.xx.xx    51532    3306   00:16:3e:ab:cc:a6       ee:ff:ff:ff:ff:ff       show databases...
root         1   NULL        1   2022-04-14 15:42:29              0      true    10.xx.xx.xx    10.xx.xx.xx    51532    3306   00:16:3e:ab:cc:a6       ee:ff:ff:ff:ff:ff       SELECT DATABASE()...
root         1   fleet       0   2022-04-14 15:42:29              0      true    10.xx.xx.xx    10.xx.xx.xx    51532    3306   00:16:3e:ab:cc:a6       ee:ff:ff:ff:ff:ff       use fleet...
root         1   fleet      15   2022-04-14 15:42:29              0      true    10.xx.xx.xx    10.xx.xx.xx    51532    3306   00:16:3e:ab:cc:a6       ee:ff:ff:ff:ff:ff       show databases...
root         1   fleet      31   2022-04-14 15:42:29              0      true    10.xx.xx.xx    10.xx.xx.xx    51532    3306   00:16:3e:ab:cc:a6       ee:ff:ff:ff:ff:ff       show tables...
root         1   fleet      31   2022-04-14 15:42:39              0      true    10.xx.xx.xx    10.xx.xx.xx    51532    3306   00:16:3e:ab:cc:a6       ee:ff:ff:ff:ff:ff       show tables...


``` 
### 2. 实时抓取某端口信息并打印到文件
-l 指定日志输出路径，日志文件将以 port.log 命名。

```
mysql-sniffer -i eth0 -p 3306 -l /tmp
```
### 3. 实时抓取多个端口信息并打印到文件
-l 指定日志输出路径，-p 指定需要抓取的端口列表逗号分割。日志文件将以各自 port.log 命名。

```
mysql-sniffer -i eth0 -p 3306,3307,3310 -l /tmp
```
### 4. 日志实时输出到tcp网络
-T 指定tcp的ip、port, -l 指定发送失败时的日志输出路径

```
mysql-sniffer -i eth0 -p 3306 -T 127.0.0.1:1234 -l logs
```
……

<img src="http://i.imgur.com/pL4ni57.png" width = "500" alt="2">

