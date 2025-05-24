/*
 * 脚本名称：监控execve进程执行.js
 * 功能描述：监控Android应用调用execve系统调用执行外部程序的行为
 * 
 * 适用场景：
 *   - 分析应用执行外部命令的行为
 *   - 检测应用是否执行root相关命令
 *   - 分析应用的系统交互方式
 *   - 监控可能的恶意行为
 *   - 检测应用的环境检测机制
 *
 * 使用方法：
 *   1. frida -U -f 目标应用包名 -l 监控execve进程执行.js --no-pause
 *   2. 或者 frida -U --attach-pid 目标进程PID -l 监控execve进程执行.js
 *   3. 观察控制台输出，分析应用执行的外部命令
 *
 * 启动方式说明：
 *   - -U: 使用USB连接的设备
 *   - -f: 指定以spawn方式启动的应用包名
 *   - --attach-pid: 附加到已运行的进程
 *   - --no-pause: 注入后不暂停应用执行
 *
 * 工作原理：
 *   Hook libc.so库中的execve函数，这是Linux系统执行外部程序的基础系统调用。
 *   当应用通过Native层代码调用execve执行外部命令时，脚本会记录被执行的程序路径。
 *   execve是Runtime.exec和ProcessBuilder等Java API在底层使用的系统调用。
 *
 * 安全关注点：
 *   - 应用可能执行su命令检测root权限
 *   - 执行shell命令检测设备环境
 *   - 调用外部程序执行敏感操作
 *   - 通过ps、netstat等命令检测调试工具
 */

// Hook execve，监控进程执行（常用于反检测、反Root）
Interceptor.attach(Module.findExportByName("libc.so", "execve"), {
    onEnter: function (args) {
        // 读取被执行的程序路径
        var path = args[0].readCString();
        console.log("[*] 检测到execve系统调用:");
        console.log("    执行路径: " + path);
        
        // 尝试读取命令行参数
        try {
            var argv = [];
            var i = 1;
            while (true) {
                var arg = args[1].add(Process.pointerSize * i).readPointer();
                if (arg.isNull()) break;
                
                var argStr = arg.readCString();
                argv.push(argStr);
                i++;
                
                // 防止参数过多导致循环过长
                if (i > 20) break;
            }
            
            if (argv.length > 0) {
                console.log("    命令参数: " + argv.join(" "));
            }
        } catch (e) {
            console.log("    无法读取命令参数: " + e);
        }
        
        // 打印调用堆栈
        console.log("    调用堆栈:");
        console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)
            .map(DebugSymbol.fromAddress).join('\n    '));
    },
    onLeave: function (retval) {
        // 分析返回值
        var ret = retval.toInt32();
        if (ret < 0) {
            console.log("    执行失败，返回值: " + ret);
        }
    }
});

console.log("[*] execve系统调用监控已启动"); 