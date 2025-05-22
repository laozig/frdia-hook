/**
 * Frida DEX脱壳模块使用指南
 * 本文件展示了dex_dumper.js模块的高级用法和实用场景
 */

// 基本用法：脱壳常见加固保护
function basicUnpacking() {
    // 加载模块
    var dexDumper = require('../modules/dex_dumper.js')({
        // 配置日志级别
        logLevel: 'info',
        // 启用日志文件保存
        fileLogging: true,
        logFilePath: '/sdcard/frida_dex_dumper.log'
    }, console, null);

    // 设置输出目录
    dexDumper.setOutputDirectory('/sdcard/frida_dex_dumps/');
    
    console.log("[*] DEX脱壳模块已初始化");
    
    // 30秒后显示统计结果
    setTimeout(function() {
        dexDumper.showStats();
    }, 30000);
}

// 内存优化：低内存设备使用，减少内存压力
function memoryOptimizedUnpacking() {
    var dexDumper = require('../modules/dex_dumper.js')({
        logLevel: 'info'
    }, console, null);
    
    // 优化内存使用
    dexDumper.setFilterSystemClasses(true);  // 过滤系统类
    dexDumper.setScanInterval(15000);        // 扫描间隔增加到15秒
    dexDumper.setDexSizeLimit(10240, 15 * 1024 * 1024); // 限制DEX大小
    
    console.log("[*] 内存优化的DEX脱壳模块已初始化");
}

// 针对华为HMS应用的专门脱壳配置
function huaweiHmsUnpacking() {
    var dexDumper = require('../modules/dex_dumper.js')({
        logLevel: 'debug'
    }, console, null);
    
    // 仅启用华为相关保护处理
    dexDumper.enableProtection('华为HMS加固', true);
    dexDumper.enableProtection('华为安全', true);
    dexDumper.enableProtection('海思加固', true);
    
    // 禁用其他保护类型
    const disabledProtections = ['梆梆', '爱加密', '360加固', '腾讯乐固'];
    disabledProtections.forEach(p => dexDumper.enableProtection(p, false));
    
    // 设置专门的输出目录
    dexDumper.setOutputDirectory('/sdcard/hms_dumps/');
    
    // 周期性扫描
    var count = 0;
    var scanTimer = setInterval(function() {
        console.log(`[*] 执行第${++count}次扫描`);
        dexDumper.scanNow();
        
        if (count >= 10) {
            clearInterval(scanTimer);
            dexDumper.showStats();
        }
    }, 10000);
    
    console.log("[*] HMS应用脱壳模块已初始化");
}

// 字节跳动应用脱壳配置
function bytedanceUnpacking() {
    var dexDumper = require('../modules/dex_dumper.js')({
        logLevel: 'debug'
    }, console, null);
    
    // 仅专注于字节跳动加固
    dexDumper.enableProtection('字节跳动加固', true);
    
    // 禁用其他保护处理以提高性能
    const allProtections = ['梆梆', '爱加密', '360加固', '腾讯乐固', '阿里聚安全', 
                           '百度加固', '娜迦', '盛大加固', '网秦加固', '几维安全', 
                           '通付盾', '瑞星加固', 'APKProtect', '顶像科技', '珊瑚灵御', 
                           '金丝雀', '华为HMS加固', '华为安全', '海思加固', '新版爱加密',
                           '携程加固', '微信小程序加固', '猎豹加固', 'OPPO加固', 'vivo加固'];
    
    allProtections.forEach(p => {
        if (p !== '字节跳动加固') {
            dexDumper.enableProtection(p, false);
        }
    });
    
    // 添加应用行为监控，在关键Activity创建时脱壳
    Java.perform(function() {
        try {
            // 针对抖音等应用的主Activity
            const mainActivityClasses = [
                "com.ss.android.ugc.aweme.main.MainActivity",
                "com.ss.android.article.news.activity.MainActivity",
                "com.ss.android.lark.main.app.MainActivity"
            ];
            
            mainActivityClasses.forEach(className => {
                try {
                    const activityClass = Java.use(className);
                    activityClass.onCreate.overload('android.os.Bundle').implementation = function(bundle) {
                        const result = this.onCreate(bundle);
                        console.log(`[*] 检测到 ${className} 创建，触发脱壳`);
                        
                        // 强制类加载和内存扫描
                        dexDumper.forceLoadClasses();
                        dexDumper.scanNow();
                        
                        return result;
                    };
                    console.log(`[+] 已Hook ${className}`);
                } catch (e) {
                    // 忽略未找到的类
                }
            });
        } catch (e) {
            console.log(`[-] 设置Activity监控失败: ${e}`);
        }
    });
    
    console.log("[*] 字节跳动应用脱壳模块已初始化");
}

// 批量处理提取的DEX文件
function processDexFiles() {
    // 此函数展示如何在DEX提取后处理文件
    Java.perform(function() {
        try {
            const File = Java.use("java.io.File");
            const dumpDir = new File("/sdcard/frida_dumps/");
            
            if (!dumpDir.exists() || !dumpDir.isDirectory()) {
                console.log("[-] 找不到提取目录");
                return;
            }
            
            const files = dumpDir.listFiles();
            console.log(`[*] 找到 ${files.length} 个文件`);
            
            let dexCount = 0;
            for (let i = 0; i < files.length; i++) {
                const file = files[i];
                const fileName = file.getName();
                
                if (fileName.endsWith(".dex")) {
                    dexCount++;
                    const fileSize = file.length();
                    console.log(`[+] DEX文件: ${fileName}, 大小: ${Math.floor(fileSize / 1024)}KB`);
                    
                    // 这里可以添加其他处理逻辑
                    // 例如：验证DEX头、修复损坏的DEX等
                }
            }
            
            console.log(`[*] 总共 ${dexCount} 个DEX文件`);
        } catch (e) {
            console.log(`[-] 处理DEX文件失败: ${e}`);
        }
    });
}

// 高级脱壳：结合反调试绕过和自定义Hook
function advancedUnpacking() {
    // 1. 首先绕过反调试保护
    Java.perform(function() {
        try {
            // 常见反调试检测
            const Debug = Java.use("android.os.Debug");
            Debug.isDebuggerConnected.implementation = function() {
                return false;
            };
            
            // 绕过常见反调试检测类
            const antiDebugClasses = [
                "com.secure.check.EmulatorDetector",
                "com.xxlib.utils.SecurityCheckUtil",
                "com.bangcle.safebox.SafeBox"
            ];
            
            antiDebugClasses.forEach(className => {
                try {
                    const clazz = Java.use(className);
                    
                    // 尝试拦截所有返回boolean的方法
                    for (const methodName in clazz) {
                        try {
                            if (methodName.startsWith("check") || methodName.startsWith("detect") || 
                                methodName.startsWith("is")) {
                                const method = clazz[methodName];
                                if (method && method.returnType && 
                                    method.returnType.className === "boolean") {
                                    method.implementation = function() {
                                        console.log(`[*] 绕过反调试检测: ${className}.${methodName}`);
                                        return false;
                                    };
                                }
                            }
                        } catch (e) {
                            // 忽略单个方法的错误
                        }
                    }
                } catch (e) {
                    // 忽略找不到的类
                }
            });
            
            console.log("[+] 反调试绕过设置完成");
        } catch (e) {
            console.log(`[-] 设置反调试绕过失败: ${e}`);
        }
    });
    
    // 2. 然后加载DEX脱壳模块
    var dexDumper = require('../modules/dex_dumper.js')({
        logLevel: 'info'
    }, console, null);
    
    console.log("[*] 高级脱壳设置完成");
}

// 选择需要执行的方法并启动
function main() {
    // 选择一种脱壳方法执行
    // 根据目标应用类型取消注释对应的方法调用
    
    basicUnpacking();
    //memoryOptimizedUnpacking();
    //huaweiHmsUnpacking();
    //bytedanceUnpacking();
    //advancedUnpacking();
    
    // 处理提取的DEX文件 (可在脱壳完成后执行)
    //setTimeout(processDexFiles, 60000);
}

// 在正确的时机执行main函数
setTimeout(main, 1000); 