# 说明

这是一个按照设定参数自动检查Windows安全日志并将攻击IP自动添加到防火墙进行屏蔽的简单程序。
可下载源码编译或直接下载Release.zip解压后使用

在AutoBlock.config中配置参数：

````
  <appSettings>
    <!-- 检测间隔 -->
    <add key="checkIntervalSeconds" value="10" />
    <!-- 防火墙规则名称 -->
    <add key="ruleName" value="@AutoBlock" />
    <!-- RDP端口 -->
    <add key="port" value="3389" />
    <!-- 以下为屏蔽阈值，可自行修改和添加，block后面的数字为时间区间单位为秒，value为触发屏蔽攻击IP的阈值(攻击次数) -->
    <add key="block1" value="5" />
    <add key="block10" value="10" />
    <add key="block60" value="20" />
    <add key="block300" value="60" />
    <add key="block600" value="100" />
    <add key="block3600" value="200" />
  </appSettings>
````

**注意！因需要读取Windows系统日志，所以需要以管理员身份运行。**

## Readme

This is a simple program that automatically checks the Windows security log according to the set parameters and automatically adds the attack IP to the firewall for shielding.
You can download the source code to compile or just download Release.zip directly to decompress and use
Configure the parameters in AutoBlock.config:

````
  <appSettings>
    <!-- check interval -->
    <add key="checkIntervalSeconds" value="10" />
    <!-- name for firewall rule -->
    <add key="ruleName" value="@AutoBlock" />
    <!-- RDP port -->
    <add key="port" value="3389" />
    <!-- The following is the thresholds, which can be modified or added by itself. The number after the block is the time range, expressed in seconds. value is the threshold (attack times). -->
    <add key="block1" value="5" />
    <add key="block10" value="10" />
    <add key="block60" value="20" />
    <add key="block300" value="60" />
    <add key="block600" value="100" />
    <add key="block3600" value="200" />
  </appSettings>
````

