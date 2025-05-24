/*
 * 脚本名称：dump_动态加载dex.js
 * 功能描述：监控并提取Android应用动态加载的DEX文件，获取隐藏代码
 * 
 * 适用场景：
 *   - 提取动态加载的插件或模块代码
 *   - 分析应用运行时加载的DEX文件内容
 *   - 辅助逆向动态代码加载机制
 *   - 获取应用为规避静态分析而采用的动态加载代码
 *   - 分析插件化框架和热修复机制
 *
 * 使用方法：
 *   1. frida -U -f 目标应用包名 -l dump_动态加载dex.js --no-pause
 *   2. 或者 frida -U --attach-pid 目标进程PID -l dump_动态加载dex.js
 *   3. 操作应用，触发动态加载行为
 *   4. 提取保存在指定路径的DEX文件
 *
 * 启动方式说明：
 *   - -U: 使用USB连接的设备
 *   - -f: 指定以spawn方式启动的应用包名
 *   - --attach-pid: 附加到已运行的进程
 *   - --no-pause: 注入后不暂停应用执行
 *
 * 工作原理：
 *   Hook dalvik.system.DexClassLoader和dalvik.system.InMemoryDexClassLoader类的构造方法，
 *   当应用使用这些类加载器加载DEX文件时，提取出DEX文件内容或路径。
 *   对于文件形式的DEX，记录其路径；对于内存形式的DEX，将其字节数组保存到文件中。
 *   这样可以捕获所有通过标准类加载器动态加载的代码。
 *
 * 注意事项：
 *   - 此脚本主要针对标准ClassLoader加载机制
 *   - 部分应用可能使用自定义加载机制需要额外处理
 *   - 加密的DEX文件可能需要配合其他脚本解密
 *   - 获取的DEX文件可能需要修复或转换为标准格式
 *   - 确保设备有足够存储空间保存提取的DEX文件
 */

// 监控并提取动态加载的DEX文件
// 作用：拦截应用动态加载DEX文件的行为，获取被加载的DEX文件内容或路径。
Java.perform(function () {
    // 存储导出的DEX文件的目录
    var outputDir = "/data/local/tmp/";
    
    // 获取应用包名，用于生成唯一文件名
    try {
        var currentApplication = Java.use('android.app.ActivityThread').currentApplication();
        var context = currentApplication.getApplicationContext();
        var packageName = context.getPackageName();
        outputDir = "/data/data/" + packageName + "/";
        console.log("[*] 目标应用: " + packageName);
    } catch (e) {
        console.log("[!] 获取应用信息失败: " + e);
    }
    
    // Hook DexClassLoader构造函数
    var DexClassLoader = Java.use('dalvik.system.DexClassLoader');
    DexClassLoader.$init.implementation = function (dexPath, optimizedDirectory, librarySearchPath, parent) {
        console.log("\n[*] DexClassLoader初始化");
        console.log("    DEX路径: " + dexPath);
        console.log("    优化目录: " + optimizedDirectory);
        console.log("    库搜索路径: " + librarySearchPath);
        
        // 可选：复制dexPath指定的文件到我们的输出目录
        try {
            if (dexPath) {
                var fileName = dexPath.split('/').pop();
                var timestamp = new Date().getTime();
                var outputPath = outputDir + "dumped_" + timestamp + "_" + fileName;
                
                // 复制文件
                var input = Java.use("java.io.FileInputStream").$new(dexPath);
                var output = Java.use("java.io.FileOutputStream").$new(outputPath);
                var buffer = Java.array('byte', new Array(1024));
                var length;
                
                while ((length = input.read(buffer)) > 0) {
                    output.write(buffer, 0, length);
                }
                
                output.flush();
                output.close();
                input.close();
                
                console.log("[+] DEX文件已保存到: " + outputPath);
            }
        } catch (e) {
            console.log("[!] 复制DEX文件失败: " + e);
        }
        
        // 调用原始构造函数
        return this.$init(dexPath, optimizedDirectory, librarySearchPath, parent);
    };
    
    // Hook InMemoryDexClassLoader (Android 8.0+)
    try {
        var InMemoryDexClassLoader = Java.use('dalvik.system.InMemoryDexClassLoader');
        InMemoryDexClassLoader.$init.overload('java.nio.ByteBuffer', 'java.lang.ClassLoader').implementation = function (buffer, parent) {
            console.log("\n[*] InMemoryDexClassLoader初始化");
            
            try {
                // 保存内存中的DEX字节数据
                if (buffer) {
                    var bytes = Java.array('byte', buffer.capacity());
                    var origPosition = buffer.position();
                    buffer.position(0); // 重置到开始位置
                    buffer.get(bytes);
                    buffer.position(origPosition); // 还原位置
                    
                    // 保存DEX字节数组到文件
                    var timestamp = new Date().getTime();
                    var outputPath = outputDir + "dumped_memory_dex_" + timestamp + ".dex";
                    var outputFile = Java.use("java.io.FileOutputStream").$new(outputPath);
                    outputFile.write(bytes);
                    outputFile.flush();
                    outputFile.close();
                    
                    console.log("[+] 内存DEX已保存到: " + outputPath);
                }
            } catch (e) {
                console.log("[!] 保存内存DEX失败: " + e);
            }
            
            // 调用原始构造函数
            return this.$init(buffer, parent);
        };
    } catch (e) {
        console.log("[!] 无法Hook InMemoryDexClassLoader: " + e);
    }
    
    console.log("[*] 动态DEX加载监控已启动");
}); 