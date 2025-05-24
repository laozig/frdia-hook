/**
 * Frida启动脚本
 * 
 * 功能：简化Frida注入流程，自动处理反调试保护
 * 使用方法：frida -U -f 目标应用包名 -l 启动脚本.js --no-pause
 */

(function() {
    // 配置选项
    const config = {
        // 目标应用包名（如果为空则使用命令行指定的包名）
        targetPackage: "",
        // 是否自动注入反检测脚本
        injectAntiDetection: true,
        // 是否自动注入脱壳工具
        injectUnpacker: true,
        // 注入延迟（毫秒）
        injectionDelay: 3000,
        // 是否打印详细日志
        verbose: true
    };

    // 颜色输出
    const colors = {
        reset: "\x1b[0m",
        red: "\x1b[31m",
        green: "\x1b[32m",
        yellow: "\x1b[33m",
        blue: "\x1b[34m",
        magenta: "\x1b[35m",
        cyan: "\x1b[36m",
        white: "\x1b[37m"
    };

    function colorLog(color, message) {
        console.log(colors[color] + message + colors.reset);
    }

    function logInfo(message) {
        colorLog("green", "[*] " + message);
    }

    function logWarn(message) {
        colorLog("yellow", "[!] " + message);
    }

    function logError(message) {
        colorLog("red", "[-] " + message);
    }

    function logSuccess(message) {
        colorLog("cyan", "[+] " + message);
    }

    function logDebug(message) {
        if (config.verbose) {
            colorLog("magenta", "[D] " + message);
        }
    }

    // 获取当前路径
    function getCurrentPath() {
        return Process.cwd();
    }

    // 读取脚本内容
    function readScriptContent(scriptPath) {
        try {
            const File = Java.use("java.io.File");
            const FileInputStream = Java.use("java.io.FileInputStream");
            const ByteArrayOutputStream = Java.use("java.io.ByteArrayOutputStream");
            
            const file = File.$new(scriptPath);
            if (!file.exists()) {
                logError("脚本文件不存在: " + scriptPath);
                return null;
            }
            
            const fis = FileInputStream.$new(file);
            const baos = ByteArrayOutputStream.$new();
            
            const buffer = Java.array('byte', new Array(4096).fill(0));
            let bytesRead;
            while ((bytesRead = fis.read(buffer)) !== -1) {
                baos.write(buffer, 0, bytesRead);
            }
            
            fis.close();
            
            return baos.toString();
        } catch (e) {
            logError("读取脚本文件失败: " + e);
            return null;
        }
    }

    // 注入基础反检测
    function injectBasicAntiDetection() {
        try {
            // 1. 隐藏Frida线程
            const Thread = Java.use("java.lang.Thread");
            Thread.currentThread.implementation = function() {
                const thread = this.currentThread();
                if (thread.getName().indexOf("Frida") >= 0 || 
                    thread.getName().indexOf("frida") >= 0 ||
                    thread.getName().indexOf("gum-js-loop") >= 0) {
                    logDebug("隐藏Frida线程: " + thread.getName());
                    thread.setName("ART-Daemon");
                }
                return thread;
            };

            // 2. 禁用调试检测
            const Debug = Java.use("android.os.Debug");
            Debug.isDebuggerConnected.implementation = function() {
                return false;
            };

            // 3. 隐藏敏感文件
            const File = Java.use("java.io.File");
            File.exists.implementation = function() {
                const fileName = this.getAbsolutePath();
                if (fileName.indexOf("frida") !== -1 || 
                    fileName.indexOf("su") !== -1 ||
                    fileName.indexOf("magisk") !== -1) {
                    return false;
                }
                return this.exists();
            };

            logSuccess("基础反检测已注入");
        } catch (e) {
            logError("注入基础反检测失败: " + e);
        }
    }

    // 主函数
    function main() {
        Java.perform(function() {
            try {
                logInfo("启动脚本初始化...");
                
                // 获取目标应用包名
                let packageName = config.targetPackage;
                if (!packageName) {
                    try {
                        const ActivityThread = Java.use("android.app.ActivityThread");
                        const app = ActivityThread.currentApplication();
                        if (app) {
                            packageName = app.getPackageName();
                        }
                    } catch (e) {
                        logDebug("获取包名失败: " + e);
                    }
                }
                
                logInfo("目标应用: " + packageName);
                
                // 注入基础反检测
                injectBasicAntiDetection();
                
                // 延迟注入主脚本
                setTimeout(function() {
                    logInfo("准备注入主脚本...");
                    
                    // 这里我们不能直接注入其他脚本，而是提示用户如何操作
                    logSuccess("启动脚本已成功运行");
                    logInfo("请在另一个终端窗口执行以下命令:");
                    logInfo("1. 获取进程PID: frida-ps -U | grep " + packageName);
                    logInfo("2. 注入反检测脚本: frida -U -p <PID> -l 反检测脚本.js");
                    logInfo("3. 注入脱壳工具: frida -U -p <PID> -l 通用脱壳工具.js");
                    
                }, config.injectionDelay);
                
            } catch (e) {
                logError("启动脚本初始化失败: " + e);
            }
        });
    }

    // 启动
    setTimeout(main, 0);
})(); 