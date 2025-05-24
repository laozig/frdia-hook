/**
 * Frida DEX脱壳模块使用指南
 * 本文件展示了dex_dumper.js模块的高级用法和实用场景
 * 
 * 包含功能:
 * - 基本脱壳: 适用于大多数常见加固保护
 * - 内存优化脱壳: 适用于低配置设备
 * - 厂商定制脱壳: 针对华为HMS、字节跳动等特定厂商加固
 * - 高级脱壳: 结合反调试绕过和自定义分析
 * - 批量处理: 提取的DEX文件处理工具
 */

/**
 * ================ 使用方法说明 ================
 * 
 * 【启动方法】
 * 1. 通过USB连接Android设备并确保已授权ADB调试
 * 2. 确保设备上已安装并启动Frida服务端
 * 3. 使用以下命令启动脱壳:
 *    - spawn模式启动目标应用并注入:
 *      frida -U -f 包名 -l path/to/frida_master.js --no-pause
 *    - attach模式注入到运行中的应用:
 *      frida -U -p 进程ID -l path/to/frida_master.js
 *    - 列出设备上运行的进程:
 *      frida-ps -U
 * 
 * 【参数配置】
 * 修改下面的main()函数来选择合适的脱壳方案:
 * - basicUnpacking(): 基础脱壳方案，适用于大多数应用
 * - memoryOptimizedUnpacking(): 适用于低内存设备
 * - huaweiHmsUnpacking(): 适用于华为HMS应用
 * - bytedanceUnpacking(): 适用于字节跳动应用
 * - advancedUnpacking(): 适用于有复杂保护的应用
 * 
 * 【输出目录】
 * 默认情况下，脱壳的DEX文件将保存在以下位置:
 * - /sdcard/frida_dex_dumps/ (基本脱壳)
 * - /sdcard/hms_dumps/ (华为应用脱壳)
 * 可以通过dexDumper.setOutputDirectory()函数修改输出路径
 * 
 * 【日志文件】
 * 默认情况下，日志将输出到:
 * - /sdcard/frida_dex_dumper.log
 * 可以通过配置修改日志路径或禁用文件日志
 * 
 * 【脱壳后处理】
 * 脱壳后的DEX文件可以使用以下工具进一步处理:
 * - dex2jar: 将DEX转换为JAR文件
 * - jadx: 反编译DEX为Java源码
 * - ByteCode Viewer: 可视化分析DEX文件
 * - 本脚本中的processDexFiles()函数用于分析处理提取的DEX文件
 */

// 基本用法：脱壳常见加固保护
/**
 * 基本脱壳配置
 * 适用于大多数常见的加固保护，如360加固、爱加密、梆梆等
 * 脱壳后的DEX文件将保存在/sdcard/frida_dex_dumps/目录下
 */
function basicUnpacking() {
    // 加载模块
    var dexDumper = require('../modules/dex_dumper.js')({
        // 配置日志级别
        logLevel: 'info',        // 可选值: 'info', 'debug', 'warn', 'error'
        // 启用日志文件保存
        fileLogging: true,       // 将日志保存到文件
        logFilePath: '/sdcard/frida_dex_dumper.log'  // 日志文件路径
    }, console, null);

    // 设置输出目录
    dexDumper.setOutputDirectory('/sdcard/frida_dex_dumps/');  // DEX文件保存路径
    
    console.log("[*] DEX脱壳模块已初始化");
    
    // 30秒后显示统计结果
    // 这个延时可以根据应用的复杂度调整，复杂应用可能需要更长时间
    setTimeout(function() {
        dexDumper.showStats();  // 显示提取的DEX文件统计信息
    }, 30000);
}

// 内存优化：低内存设备使用，减少内存压力
/**
 * 内存优化脱壳配置
 * 适用于内存受限设备(如低配置手机)或大型复杂应用
 * 通过优化扫描参数减少内存占用和CPU使用率
 */
function memoryOptimizedUnpacking() {
    var dexDumper = require('../modules/dex_dumper.js')({
        logLevel: 'info'
    }, console, null);
    
    // 优化内存使用
    dexDumper.setFilterSystemClasses(true);  // 过滤系统类，减少处理量
    dexDumper.setScanInterval(15000);        // 扫描间隔增加到15秒，减少CPU使用
    dexDumper.setDexSizeLimit(10240, 15 * 1024 * 1024); // 限制DEX大小范围，避免处理过大文件
    
    console.log("[*] 内存优化的DEX脱壳模块已初始化");
}

// 针对华为HMS应用的专门脱壳配置
/**
 * 华为HMS应用专用脱壳配置
 * 针对华为HMS框架和华为安全保护机制的特殊处理
 * 专为华为手机上运行的应用定制，提高脱壳成功率
 */
function huaweiHmsUnpacking() {
    var dexDumper = require('../modules/dex_dumper.js')({
        logLevel: 'debug'  // 使用debug级别以获取更详细的日志
    }, console, null);
    
    // 仅启用华为相关保护处理
    dexDumper.enableProtection('华为HMS加固', true);  // 华为HMS框架保护
    dexDumper.enableProtection('华为安全', true);     // 华为安全保护
    dexDumper.enableProtection('海思加固', true);     // 华为海思加固
    
    // 禁用其他保护类型
    // 这可以提高性能并减少不必要的处理
    const disabledProtections = ['梆梆', '爱加密', '360加固', '腾讯乐固'];
    disabledProtections.forEach(p => dexDumper.enableProtection(p, false));
    
    // 设置专门的输出目录
    dexDumper.setOutputDirectory('/sdcard/hms_dumps/');
    
    // 周期性扫描
    // 对HMS应用进行多次扫描，确保捕获所有动态加载的DEX
    var count = 0;
    var scanTimer = setInterval(function() {
        console.log(`[*] 执行第${++count}次扫描`);
        dexDumper.scanNow();  // 立即执行一次内存扫描
        
        if (count >= 10) {  // 执行10次后停止
            clearInterval(scanTimer);
            dexDumper.showStats();  // 显示统计信息
        }
    }, 10000);  // 每10秒执行一次
    
    console.log("[*] HMS应用脱壳模块已初始化");
}

// 字节跳动应用脱壳配置
/**
 * 字节跳动应用专用脱壳配置
 * 适用于抖音、今日头条等字节跳动系应用
 * 针对字节跳动自研加固方案的特殊处理
 * 在关键Activity创建时进行额外的脱壳尝试
 */
function bytedanceUnpacking() {
    var dexDumper = require('../modules/dex_dumper.js')({
        logLevel: 'debug'  // 使用debug级别记录详细日志
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
    // 字节跳动应用通常在主Activity创建时会完成DEX加载
    Java.perform(function() {
        try {
            // 针对抖音等应用的主Activity
            const mainActivityClasses = [
                "com.ss.android.ugc.aweme.main.MainActivity",  // 抖音主界面
                "com.ss.android.article.news.activity.MainActivity",  // 今日头条主界面
                "com.ss.android.lark.main.app.MainActivity"  // 飞书主界面
            ];
            
            mainActivityClasses.forEach(className => {
                try {
                    const activityClass = Java.use(className);
                    activityClass.onCreate.overload('android.os.Bundle').implementation = function(bundle) {
                        const result = this.onCreate(bundle);
                        console.log(`[*] 检测到 ${className} 创建，触发脱壳`);
                        
                        // 强制类加载和内存扫描
                        dexDumper.forceLoadClasses();  // 强制加载所有类，触发解密
                        dexDumper.scanNow();  // 立即扫描内存查找DEX
                        
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
/**
 * 批量处理脱壳后的DEX文件
 * 此函数用于在脱壳完成后对提取的DEX文件进行处理
 * 可用于检查DEX完整性、分析文件大小、转换为JAR等后处理操作
 */
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
                    // 例如：使用dexdump工具分析DEX结构
                    // 例如：使用dex2jar转换为jar文件便于反编译
                }
            }
            
            console.log(`[*] 总共 ${dexCount} 个DEX文件`);
        } catch (e) {
            console.log(`[-] 处理DEX文件失败: ${e}`);
        }
    });
}

// 高级脱壳：结合反调试绕过和自定义Hook
/**
 * 高级脱壳配置
 * 结合反调试绕过和自定义Hook，用于应对复杂的加固场景
 * 适用于具有多重保护机制的应用，如同时具有加固和自定义完整性校验的应用
 */
function advancedUnpacking() {
    // 1. 首先绕过反调试保护
    // 许多加固应用会先进行反调试检测，必须首先绕过这些检测
    Java.perform(function() {
        try {
            // 常见反调试检测
            const Debug = Java.use("android.os.Debug");
            Debug.isDebuggerConnected.implementation = function() {
                return false;  // 返回false表示没有调试器连接
            };
            
            // 绕过常见反调试检测类
            const antiDebugClasses = [
                "com.secure.check.EmulatorDetector",     // 模拟器检测
                "com.xxlib.utils.SecurityCheckUtil",     // 安全检查工具
                "com.bangcle.safebox.SafeBox"            // 梆梆加固安全盒子
            ];
            
            antiDebugClasses.forEach(className => {
                try {
                    const clazz = Java.use(className);
                    
                    // 尝试拦截所有返回boolean的方法
                    // 通常检测方法都会返回布尔值表示是否检测到问题
                    for (const methodName in clazz) {
                        try {
                            if (methodName.startsWith("check") || methodName.startsWith("detect") || 
                                methodName.startsWith("is")) {
                                const method = clazz[methodName];
                                if (method && method.returnType && 
                                    method.returnType.className === "boolean") {
                                    method.implementation = function() {
                                        console.log(`[*] 绕过反调试检测: ${className}.${methodName}`);
                                        return false;  // 返回false表示没有检测到问题
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
    // 反调试绕过后，再进行DEX脱壳
    var dexDumper = require('../modules/dex_dumper.js')({
        logLevel: 'info'
    }, console, null);
    
    console.log("[*] 高级脱壳设置完成");
}

// 选择需要执行的方法并启动
/**
 * 主函数 - 选择要执行的脱壳方法
 * 根据目标应用类型取消注释相应的方法调用
 * 只应启用一种脱壳方法，避免它们相互干扰
 */
function main() {
    // 选择一种脱壳方法执行
    // 根据目标应用类型取消注释对应的方法调用
    
    basicUnpacking();              // 默认脱壳方法，适用于大多数应用
    //memoryOptimizedUnpacking();  // 内存优化版本，适用于低配置设备
    //huaweiHmsUnpacking();        // 华为HMS应用专用
    //bytedanceUnpacking();        // 字节跳动应用专用
    //advancedUnpacking();         // 高级脱壳，用于复杂保护场景
    
    // 处理提取的DEX文件 (可在脱壳完成后执行)
    // 建议设置较长延时，确保脱壳过程完成
    //setTimeout(processDexFiles, 60000);  // 1分钟后处理DEX文件
}

// 在正确的时机执行main函数
// 延迟1秒启动，确保Frida注入完成
setTimeout(main, 1000); 