# Networkcap
This is a c++ pratice project for using Npcap and Imgui to create a network packet caputer software

# Note
Make Sure you have Npcap window installed
https://npcap.com/#download

# Filter Expersion
It is same as Npcap and libpcap bpf program string filter
Example : port 80, tcp port 80


# Interface
if your compile yourself the start window frame will be small, you can dock by yourself how you like the layout by docking.
![interface](https://github.com/RuiTheSaltyFish/networkcap/assets/121046801/2cbb2da3-d90d-4484-acf8-c511eb08d9a0)


# Known Issues
Some time will throw string too long exception, may cause by casting the u_char packet to string.
*still under investigate

# 中文
# 备注
请记得在电脑内安装Npcap以确保能够运行

# 过滤表达式
和libpcap和npcap里的bpf 过滤字符串是一样的

# 现有问题
在转换pcap数据字节到字符有些数据包会抛出 string too long 异常.未解決
