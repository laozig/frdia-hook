/*
 * 脚本名称：通杀进程创建.js
 * 功能：自动监控fork/execve/system等进程创建相关系统调用，辅助分析子进程、命令执行
 * 适用场景：反检测、进程注入、命令执行分析、so逆向
 * 使用方法：
 *   1. frida -U -f 包名 -l 通杀进程创建.js --no-pause
 *   2. 查看控制台输出，获取进程创建信息
 * 启动方式说明：
 *   - -U 代表使用USB连接的设备
 *   - -f 代表以spawn方式启动目标应用（推荐，可以捕获启动阶段的进程创建）
 *   - --no-pause 指示Frida不要暂停应用执行，保证App正常运行
 *   - 也可使用 -F 以attach方式附加到已运行的进程
 * 参数说明：
 *   - 包名：目标应用的包名，如com.example.app
 * 监控函数说明：
 *   - fork(): 创建子进程，子进程是父进程的副本，返回值为子进程ID
 *   - execve(): 执行程序，替换当前进程镜像，参数包括程序路径和参数
 *   - system(): 执行shell命令，内部通过fork和execve实现
 * 函数参数详解：
 *   - fork(): 无参数，返回值为进程ID
 *   - execve(const char *pathname, char *const argv[], char *const envp[])：
 *     - pathname：要执行的程序路径
 *     - argv：传递给程序的参数数组
 *     - envp：环境变量数组
 *   - system(const char *command)：
 *     - command：要执行的shell命令字符串
 * 实际应用场景：
 *   - 检测恶意应用创建后门进程
 *   - 分析应用执行的shell命令
 *   - 监控应用是否尝试提权或执行敏感操作
 *   - 发现应用通过子进程绕过检测的行为
 * 注意事项：
 *   - 某些加固so需配合反检测脚本
 *   - 在Android中，fork和execve通常由zygote进程处理
 *   - 应用可能使用JNI调用这些函数以避开Java层监控
 *   - 使用ptrace或其他手段防止进程被调试时也会调用这些函数
 */

// 通杀进程创建
// 定义要监控的函数列表，这些函数都与进程创建相关
['fork', 'execve', 'system'].forEach(function (func) {
    try {
        // 在libc.so库中查找导出的目标函数地址
        // libc.so是C标准库，包含了进程操作的核心函数
        var addr = Module.findExportByName('libc.so', func);
        
        if (addr) {
            // 如果找到函数地址，则附加拦截器
            Interceptor.attach(addr, {
                // 在函数调用前执行的回调
                onEnter: function (args) {
                    // 记录函数调用和参数
                    if (func === 'fork') {
                        // fork()没有参数
                        console.log('[*] ' + func + ' 调用: 创建新进程');
                        // 打印调用堆栈，帮助找出调用来源
                        console.log('    调用堆栈: ' + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n    '));
                    }
                    else if (func === 'execve') {
                        // 解析execve的第一个参数：程序路径
                        var path = Memory.readUtf8String(args[0]);
                        console.log('[*] ' + func + ' 调用: 执行程序: ' + path);
                        
                        // 尝试解析参数数组
                        try {
                            var i = 1;
                            var argAddr = Memory.readPointer(args[1]);
                            var argList = [];
                            while (!argAddr.isNull()) {
                                var arg = Memory.readUtf8String(argAddr);
                                argList.push(arg);
                                i++;
                                argAddr = Memory.readPointer(args[1].add(i * Process.pointerSize));
                            }
                            console.log('    参数列表: ' + JSON.stringify(argList));
                        } catch (e) {
                            console.log('    无法读取参数列表: ' + e);
                        }
                    }
                    else if (func === 'system') {
                        // 解析system的参数：命令字符串
                        var cmd = Memory.readUtf8String(args[0]);
                        console.log('[*] ' + func + ' 调用: 执行命令: ' + cmd);
                        
                        // 分析命令内容，检查是否有敏感操作
                        if (cmd.indexOf('su ') >= 0 || cmd.indexOf('sudo ') >= 0) {
                            console.log('    [!] 警告: 检测到疑似提权操作');
                        }
                        if (cmd.indexOf('mount ') >= 0 || cmd.indexOf('dd ') >= 0) {
                            console.log('    [!] 警告: 检测到疑似文件系统操作');
                        }
                        if (cmd.indexOf('kill ') >= 0 || cmd.indexOf('pkill ') >= 0) {
                            console.log('    [!] 警告: 检测到进程终止操作');
                        }
                    }
                    else {
                        // 通用参数输出
                        var arg0 = Memory.readUtf8String(args[0]);
                        console.log('[*] ' + func + ' 调用, 参数: ' + arg0);
                    }
                },
                
                // 在函数返回时执行的回调
                onLeave: function (retval) {
                    if (func === 'fork') {
                        var pid = retval.toInt32();
                        if (pid > 0) {
                            console.log('[*] ' + func + ' 成功创建子进程, PID: ' + pid);
                        } else if (pid === 0) {
                            console.log('[*] 当前进程是fork的子进程');
                        } else {
                            console.log('[*] ' + func + ' 失败, 错误码: ' + pid);
                        }
                    } else {
                        // 对于execve和system，记录返回值
                        // execve成功不会返回，system返回命令执行的状态码
                        console.log('[*] ' + func + ' 返回: ' + retval);
                    }
                }
            });
            
            console.log('[+] 成功Hook ' + func + ' 函数');
        } else {
            console.log('[-] 未找到函数: ' + func);
        }
    } catch (e) {
        console.log('[-] Hook ' + func + ' 时出错: ' + e);
    }
});

console.log("[*] 进程创建监控已启动");

// 注：更完整的实现应该还包括：
// 1. Runtime.exec() Java层的命令执行
// 2. ProcessBuilder Java层的进程构建
// 3. vfork() 另一种进程创建方式
// 4. clone() Linux特有的进程创建函数
// 5. posix_spawn() POSIX标准的进程创建函数 