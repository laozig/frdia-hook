/*
 * 脚本名称：自动ClassLoader脱壳.js
 * 功能描述：遍历应用中所有ClassLoader，提取已加载的DEX文件路径，辅助脱壳分析
 * 
 * 适用场景：
 *   - 分析使用自定义ClassLoader的加固应用
 *   - 提取动态加载的DEX文件
 *   - 分析插件化框架的类加载机制
 *   - 研究热修复技术的实现原理
 *   - 绕过应用的代码保护措施
 *
 * 使用方法：
 *   1. frida -U -f 目标应用包名 -l 自动ClassLoader脱壳.js --no-pause
 *   2. 或者 frida -U --attach-pid 目标进程PID -l 自动ClassLoader脱壳.js
 *   3. 操作应用，观察控制台输出的已加载DEX文件路径
 *   4. 配合frida-dexdump等工具提取感兴趣的DEX文件
 *
 * 启动方式说明：
 *   - -U: 使用USB连接的设备
 *   - -f: 指定以spawn方式启动的应用包名（推荐，可捕获启动时加载的DEX）
 *   - --attach-pid: 附加到已运行的进程
 *   - --no-pause: 注入后不暂停应用执行
 *
 * 工作原理：
 *   脚本使用Java.enumerateClassLoaders遍历应用中所有活跃的ClassLoader实例，
 *   对于每个BaseDexClassLoader类型的加载器，提取其pathList字段中的dexElements数组，
 *   该数组包含了所有已加载的DEX文件信息。脚本遍历这些元素，提取并打印每个DEX文件的路径。
 *   与dump_所有dex内存.js不同，此脚本专注于从ClassLoader角度分析类加载路径，
 *   可以发现一些通过常规方法难以检测的自定义加载机制。
 *
 * 注意事项：
 *   - 需要root权限或Frida服务器具有对应权限
 *   - 此脚本仅显示DEX路径，不会自动提取DEX文件
 *   - 某些高级加固可能会混淆或隐藏ClassLoader的关键字段
 *   - 对于内存中直接加载的DEX，可能无法显示实际文件路径
 *   - 建议与frida-dexdump等工具配合使用，实现自动提取
 *   - 可能需要配合反检测脚本使用，避免被应用发现
 */

// 自动ClassLoader脱壳.js
Java.perform(function () {
    // 存储找到的类加载器
    var loaders = [];
    
    // 遍历所有类加载器
    Java.enumerateClassLoaders({
        onMatch: function (loader) {
            loaders.push(loader);
        },
        onComplete: function () {
            // 分析每个类加载器中的DEX文件
            loaders.forEach(function (loader) {
                try {
                    // 尝试将加载器转换为BaseDexClassLoader类型
                    var pathList = Java.cast(loader, Java.use('dalvik.system.BaseDexClassLoader')).pathList.value;
                    var dexElements = pathList.dexElements.value;
                    
                    // 遍历dexElements数组，提取每个DEX文件信息
                    for (var i = 0; i < dexElements.length; i++) {
                        var dexFile = dexElements[i].dexFile.value;
                        if (dexFile) {
                            var dexPath = dexFile.getName();
                            console.log('[*] ClassLoader已加载dex: ' + dexPath);
                            // 可结合frida-dexdump自动dump
                        }
                    }
                } catch (e) {
                    // 忽略非BaseDexClassLoader类型的加载器或访问失败的情况
                }
            });
        }
    });
}); 