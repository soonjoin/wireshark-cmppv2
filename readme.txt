1. 将CMPPv2.lua复制到wireshark安装目录，如C:\Program Files\Wireshark
2. 修改wireshark安装目录下的init.lua，在文件最后位置增加：
dofile("CMPPv2.lua")

MacOS Catalina下复制到Personal Lua Plugins目录即可，无需修改init.lua脚本