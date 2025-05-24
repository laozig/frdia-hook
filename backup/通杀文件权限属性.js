/*
 * 脚本名称：通杀文件权限属性.js
 * 功能：自动监控文件权限操作，如chmod、chown、stat等系统调用
 * 适用场景：权限提升分析、安全检测分析、文件访问模式分析
 * 使用方法：
 *   1. frida -U -f 包名 -l 通杀文件权限属性.js --no-pause
 *   2. 查看控制台输出，获取文件权限操作信息
 * 启动方式说明：
 *   - -U 代表使用USB连接的设备
 *   - -f 代表以spawn方式启动目标应用
 *   - --no-pause 指示Frida不要暂停应用执行，保证App正常运行
 *   - 也可使用 -F 以attach方式附加到已运行的进程
 * 参数说明：
 *   - 包名：目标应用的包名，如com.example.app
 * 监控函数说明：
 *   - chmod: 修改文件访问权限
 *   - chown: 修改文件所有者和组
 *   - stat/lstat/fstat: 获取文件状态信息
 *   - access: 检查文件访问权限
 *   - getcwd: 获取当前工作目录
 *   - mkdir: 创建目录
 *   - rmdir: 删除目录
 * 文件权限说明：
 *   - 0400: 所有者可读(r)
 *   - 0200: 所有者可写(w)
 *   - 0100: 所有者可执行(x)
 *   - 0040: 组可读(r)
 *   - 0020: 组可写(w)
 *   - 0010: 组可执行(x)
 *   - 0004: 其他可读(r)
 *   - 0002: 其他可写(w)
 *   - 0001: 其他可执行(x)
 *   - 4000: 设置用户ID位(SUID)
 *   - 2000: 设置组ID位(SGID)
 *   - 1000: 黏着位(Sticky bit)
 * 输出内容：
 *   - 函数调用: 显示操作的函数名
 *   - 文件路径: 涉及的文件路径
 *   - 权限值: 修改或检查的权限值
 *   - 调用位置: 执行操作的代码位置
 * 实际应用场景：
 *   - 检测可能的权限提升操作
 *   - 分析应用的文件权限管理
 *   - 发现可能的安全风险
 *   - Root检测和绕过分析
 * 注意事项：
 *   - 某些加固应用需配合反检测脚本
 *   - Android系统限制了普通应用可设置的权限
 */

// 通杀文件权限属性
(function() {
    // 敏感路径列表，对这些路径操作通常有安全隐患
    var sensitivePaths = [
        "/data/local/tmp",
        "/data/data",
        "/data/app",
        "/system/bin",
        "/system/xbin",
        "/proc",
        "/dev",
        "/etc/hosts",
        "/etc/passwd",
        "/etc/shadow"
    ];
    
    // 辅助函数: 检查是否为敏感路径
    function isSensitivePath(path) {
        if (!path) return false;
        for (var i = 0; i < sensitivePaths.length; i++) {
            if (path.indexOf(sensitivePaths[i]) === 0) {
                return true;
            }
        }
        return false;
    }
    
    // 辅助函数: 获取堆栈简短表示
    function getStackSummary(context) {
        var backtrace = Thread.backtrace(context, Backtracer.ACCURATE);
        return backtrace.slice(0, 4).map(DebugSymbol.fromAddress).join("\n    ");
    }
    
    // 辅助函数: 格式化权限模式为可读格式
    function formatMode(mode) {
        if (typeof mode !== 'number') {
            try {
                mode = parseInt(mode);
                if (isNaN(mode)) return "无效模式";
            } catch (e) {
                return "无效模式";
            }
        }
        
        var permString = "";
        
        // 文件类型
        if (mode & 0x4000) permString += "d"; // 目录
        else if (mode & 0x8000) permString += "-"; // 普通文件
        else if (mode & 0x2000) permString += "c"; // 字符设备
        else if (mode & 0x6000) permString += "b"; // 块设备
        else if (mode & 0x1000) permString += "p"; // FIFO
        else if (mode & 0xA000) permString += "l"; // 符号链接
        else if (mode & 0xC000) permString += "s"; // Socket
        else permString += "?";
        
        // 用户权限
        permString += (mode & 0x0100) ? "r" : "-";
        permString += (mode & 0x0080) ? "w" : "-";
        permString += (mode & 0x0040) ? 
            ((mode & 0x0800) ? "s" : "x") : 
            ((mode & 0x0800) ? "S" : "-");
        
        // 组权限
        permString += (mode & 0x0020) ? "r" : "-";
        permString += (mode & 0x0010) ? "w" : "-";
        permString += (mode & 0x0008) ? 
            ((mode & 0x0400) ? "s" : "x") : 
            ((mode & 0x0400) ? "S" : "-");
        
        // 其他人权限
        permString += (mode & 0x0004) ? "r" : "-";
        permString += (mode & 0x0002) ? "w" : "-";
        permString += (mode & 0x0001) ? 
            ((mode & 0x0200) ? "t" : "x") : 
            ((mode & 0x0200) ? "T" : "-");
        
        return "0" + mode.toString(8) + " (" + permString + ")";
    }
    
    // 辅助函数: 解析stat结构体
    function parseStat(statPtr) {
        try {
            // stat结构布局可能因平台不同而异
            // 这里以常见的Linux/Android为例
            var mode = Memory.readU16(statPtr.add(0)); // st_mode通常是第一个字段
            var uid = Memory.readU32(statPtr.add(8));  // 用户ID
            var gid = Memory.readU32(statPtr.add(12)); // 组ID
            var size = Memory.readU32(statPtr.add(20)); // 文件大小
            
            return {
                mode: formatMode(mode),
                uid: uid,
                gid: gid,
                size: size
            };
        } catch (e) {
            return { error: "无法解析stat结构: " + e };
        }
    }
    
    // 定义要监控的函数列表和它们的处理逻辑
    var monitorFunctions = [
        {
            name: "chmod",
            argTypes: ["char *", "mode_t"],
            onEnter: function(args) {
                this.path = Memory.readUtf8String(args[0]);
                this.mode = args[1].toInt32();
            },
            onLeave: function(retval) {
                var ret = retval.toInt32();
                console.log('[*] chmod("' + this.path + '", ' + formatMode(this.mode) + '): ' + 
                           (ret === 0 ? "成功" : "失败，错误码=" + (-ret)));
                
                if (isSensitivePath(this.path)) {
                    console.log('    [!] 警告: 修改敏感路径权限');
                }
                
                if (this.mode & 0x4000) {
                    console.log('    [!] 注意: 设置了SUID/SGID/粘滞位');
                }
                
                console.log('    调用堆栈: ');
                console.log('    ' + getStackSummary(this.context));
            }
        },
        {
            name: "chown",
            argTypes: ["char *", "uid_t", "gid_t"],
            onEnter: function(args) {
                this.path = Memory.readUtf8String(args[0]);
                this.owner = args[1].toInt32();
                this.group = args[2].toInt32();
            },
            onLeave: function(retval) {
                var ret = retval.toInt32();
                console.log('[*] chown("' + this.path + '", ' + this.owner + ', ' + this.group + '): ' + 
                           (ret === 0 ? "成功" : "失败，错误码=" + (-ret)));
                
                if (isSensitivePath(this.path)) {
                    console.log('    [!] 警告: 修改敏感路径所有者');
                }
                
                if (this.owner === 0 || this.group === 0) {
                    console.log('    [!] 警告: 尝试设置root所有权');
                }
                
                console.log('    调用堆栈: ');
                console.log('    ' + getStackSummary(this.context));
            }
        },
        {
            name: "stat",
            argTypes: ["char *", "struct stat *"],
            onEnter: function(args) {
                this.path = Memory.readUtf8String(args[0]);
                this.statPtr = args[1];
            },
            onLeave: function(retval) {
                var ret = retval.toInt32();
                console.log('[*] stat("' + this.path + '"): ' + 
                           (ret === 0 ? "成功" : "失败，错误码=" + (-ret)));
                
                if (ret === 0) {
                    var statInfo = parseStat(this.statPtr);
                    console.log('    文件信息: ' + JSON.stringify(statInfo));
                }
                
                // 检查是否访问敏感路径，可能是在进行环境检测
                if (isSensitivePath(this.path)) {
                    console.log('    [!] 注意: 检查敏感路径状态，可能为安全检测');
                }
                
                // 检查特定路径访问，可能是root检测
                if (this.path.indexOf("/system/bin/su") !== -1 || 
                    this.path.indexOf("/system/xbin/su") !== -1 ||
                    this.path.indexOf("/su") !== -1 ||
                    this.path.indexOf("/magisk") !== -1) {
                    console.log('    [!] 警告: 检测root相关文件');
                }
            }
        },
        {
            name: "lstat",
            argTypes: ["char *", "struct stat *"],
            onEnter: function(args) {
                this.path = Memory.readUtf8String(args[0]);
                this.statPtr = args[1];
            },
            onLeave: function(retval) {
                var ret = retval.toInt32();
                console.log('[*] lstat("' + this.path + '"): ' + 
                           (ret === 0 ? "成功" : "失败，错误码=" + (-ret)));
                
                if (ret === 0) {
                    var statInfo = parseStat(this.statPtr);
                    console.log('    文件信息: ' + JSON.stringify(statInfo));
                }
                
                // 检查特定情况
                if (this.path.indexOf("proc/self") !== -1) {
                    console.log('    [!] 注意: 进程自检查，可能为调试器或注入检测');
                }
            }
        },
        {
            name: "fstat",
            argTypes: ["int", "struct stat *"],
            onEnter: function(args) {
                this.fd = args[0].toInt32();
                this.statPtr = args[1];
            },
            onLeave: function(retval) {
                var ret = retval.toInt32();
                console.log('[*] fstat(' + this.fd + '): ' + 
                           (ret === 0 ? "成功" : "失败，错误码=" + (-ret)));
                
                if (ret === 0) {
                    var statInfo = parseStat(this.statPtr);
                    console.log('    文件信息: ' + JSON.stringify(statInfo));
                }
            }
        },
        {
            name: "access",
            argTypes: ["char *", "int"],
            onEnter: function(args) {
                this.path = Memory.readUtf8String(args[0]);
                this.mode = args[1].toInt32();
                
                // 解析访问模式
                var modeStr = "";
                if (this.mode === 0) modeStr = "F_OK (存在检查)";
                else {
                    if (this.mode & 4) modeStr += "R_OK (读) ";
                    if (this.mode & 2) modeStr += "W_OK (写) ";
                    if (this.mode & 1) modeStr += "X_OK (执行) ";
                }
                
                this.modeStr = modeStr;
            },
            onLeave: function(retval) {
                var ret = retval.toInt32();
                console.log('[*] access("' + this.path + '", ' + this.modeStr + '): ' + 
                           (ret === 0 ? "成功" : "失败，错误码=" + (-ret)));
                
                // 检查是否访问敏感路径或root路径
                if (this.path.indexOf("/system/bin/su") !== -1 || 
                    this.path.indexOf("/system/xbin/su") !== -1) {
                    console.log('    [!] 警告: 检测root权限文件');
                }
                
                if (ret === 0 && this.mode & 1 && 
                    (this.path.indexOf("/system/") === 0 || this.path.indexOf("/data/") === 0)) {
                    console.log('    [!] 注意: 检查系统目录可执行权限');
                }
            }
        },
        {
            name: "mkdir",
            argTypes: ["char *", "mode_t"],
            onEnter: function(args) {
                this.path = Memory.readUtf8String(args[0]);
                this.mode = args[1].toInt32();
            },
            onLeave: function(retval) {
                var ret = retval.toInt32();
                console.log('[*] mkdir("' + this.path + '", ' + formatMode(this.mode) + '): ' + 
                           (ret === 0 ? "成功" : "失败，错误码=" + (-ret)));
                
                if (isSensitivePath(this.path)) {
                    console.log('    [!] 警告: 在敏感路径创建目录');
                }
            }
        },
        {
            name: "rmdir",
            argTypes: ["char *"],
            onEnter: function(args) {
                this.path = Memory.readUtf8String(args[0]);
            },
            onLeave: function(retval) {
                var ret = retval.toInt32();
                console.log('[*] rmdir("' + this.path + '"): ' + 
                           (ret === 0 ? "成功" : "失败，错误码=" + (-ret)));
                
                if (isSensitivePath(this.path)) {
                    console.log('    [!] 警告: 删除敏感路径目录');
                }
            }
        },
        {
            name: "getcwd",
            argTypes: ["char *", "size_t"],
            onEnter: function(args) {
                this.buf = args[0];
                this.size = args[1].toInt32();
            },
            onLeave: function(retval) {
                try {
                    var cwd = Memory.readUtf8String(retval);
                    console.log('[*] getcwd(): "' + cwd + '"');
                } catch (e) {
                    console.log('[*] getcwd(): 无法获取值: ' + e);
                }
            }
        }
    ];
    
    // 遍历所有要监控的函数并进行Hook
    monitorFunctions.forEach(function(func) {
        try {
            var addr = Module.findExportByName('libc.so', func.name);
        if (addr) {
            Interceptor.attach(addr, {
                    onEnter: function(args) {
                        this.context = this.context; // 保存调用上下文
                        if (func.onEnter) {
                            func.onEnter.call(this, args);
                        } else {
                            // 通用处理
                            if (args[0]) {
                                try {
                                    var arg0 = Memory.readUtf8String(args[0]);
                                    console.log('[*] ' + func.name + ' 调用, 参数: ' + arg0);
                                } catch (e) {
                                    console.log('[*] ' + func.name + ' 调用, 参数: ' + args[0]);
                                }
                            } else {
                                console.log('[*] ' + func.name + ' 调用');
                            }
                        }
                    },
                    onLeave: function(retval) {
                        if (func.onLeave) {
                            func.onLeave.call(this, retval);
                        } else {
                            // 通用处理
                            console.log('[*] ' + func.name + ' 返回: ' + retval);
                        }
                    }
                });
                
                console.log('[+] 成功Hook ' + func.name + ' 函数');
            } else {
                console.log('[-] 未找到函数 ' + func.name);
            }
        } catch (e) {
            console.log('[-] Hook ' + func.name + ' 失败: ' + e);
        }
    });
    
    console.log("[*] 文件权限属性监控已启动");
    console.log("[*] 监控范围: chmod, chown, stat/lstat/fstat, access, mkdir, rmdir, getcwd");
})(); 