# Frida Android分析工具集

## 简介

这是一套基于Frida的Android应用分析工具集，主要用于应用逆向分析、安全测试和脱壳操作。工具集包含多个专用脚本，每个脚本针对不同的分析场景。

## 工具列表

### 核心工具

- **通用脱壳工具.js** - 自动检测并脱壳各类加固应用
- **反检测脚本.js** - 绕过各种反调试和反Frida检测机制
- **启动脚本.js** - 简化Frida注入流程，提供基础反检测功能

### 功能脚本

- **基础API拦截.js** - 拦截常用Android API调用
- **SSL证书绕过.js** - 绕过SSL证书固定
- **反调试检测绕过.js** - 绕过常见的反调试检测机制
- **加密解密函数Hook.js** - 拦截并打印加解密函数的参数和结果
- **网络请求拦截.js** - 监控和修改网络请求
- **文件操作拦截.js** - 监控文件读写操作
- **WebView注入.js** - 向WebView注入JavaScript代码
- **UI渲染性能监控.js** - 监控UI渲染性能
- **内存使用监控.js** - 监控应用内存使用情况
- **应用启动流程监控.js** - 分析应用启动流程
- **Root检测绕过.js** - 绕过Root检测
- **Native层函数追踪.js** - 追踪Native层函数调用
- **内存搜索修改.js** - 搜索和修改内存中的数据

## 使用方法



### 快速开始

1. 安装Frida：
   ```
   pip install frida-tools
   ```

2. 在Android设备上安装frida-server

3. 使用脱壳工具：
   ```
   frida -U -f 目标应用包名 -l 通用脱壳工具.js --no-pause
   ```

4. 如果遇到反调试保护，使用分步注入方法：
   ```
   frida -U -f 目标应用包名 -l 启动脚本.js --no-pause
   ```
   
   然后在另一个终端：
   ```
   frida -U -p <PID> -l 反检测脚本.js
   frida -U -p <PID> -l 通用脱壳工具.js
   ```

## 环境要求

- Frida 14.0+
- Python 3.6+
- Root权限的Android设备
- Android 5.0-12.0 (API级别21-31)

## 注意事项

- 本工具仅用于安全研究和学习目的
- 请勿用于非法用途
- 部分功能可能需要根据目标应用进行定制

## 贡献

欢迎提交Pull Request或Issue来改进工具集。 