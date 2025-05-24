/*
 * 脚本名称：dump_所有dex内存.js
 * 功能描述：遍历并记录应用中所有已加载的DEX文件路径，便于后续提取分析
 * 
 * 适用场景：
 *   - 分析多DEX应用的代码结构
 *   - 发现应用动态加载的代码模块
 *   - 配合DEX提取工具进行脱壳
 *   - 分析插件化和热更新框架
 *   - 追踪应用的类加载来源
 *
 * 使用方法：
 *   1. frida -U -f 目标应用包名 -l dump_所有dex内存.js --no-pause
 *   2. 或者 frida -U --attach-pid 目标进程PID -l dump_所有dex内存.js
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
 *   脚本首先获取应用的上下文环境，然后遍历所有活跃的ClassLoader实例。
 *   对于每个BaseDexClassLoader类型的加载器，提取其pathList字段中的dexElements数组，
 *   该数组包含了所有已加载的DEX文件信息。脚本遍历这些元素，提取并打印每个DEX文件的路径，
 *   这些信息可以用于后续的DEX文件提取和分析工作。
 *
 * 注意事项：
 *   - 需要root权限或Frida服务器具有对应权限
 *   - 此脚本仅显示DEX路径，不会自动提取DEX文件
 *   - 对于内存中动态生成的DEX，可能无法显示实际文件路径
 *   - 某些加固应用可能使用自定义类加载机制隐藏DEX
 *   - 建议与frida-dexdump等工具配合使用，实现自动提取
 *   - 可能需要配合反检测脚本使用，避免被应用发现
 */

// dump_所有dex内存.js
Java.perform(function () {
    // 获取应用上下文
    var currentApplication = Java.use('android.app.ActivityThread').currentApplication();
    var context = currentApplication.getApplicationContext();
    var filesDir = context.getFilesDir().getAbsolutePath();
    
    // 遍历所有类加载器
    Java.enumerateClassLoaders({
        onMatch: function (loader) {
            try {
                // 尝试将加载器转换为BaseDexClassLoader类型
                var pathList = Java.cast(loader, Java.use('dalvik.system.BaseDexClassLoader')).pathList.value;
                var dexElements = pathList.dexElements.value;
                
                // 遍历dexElements数组，提取每个DEX文件信息
                for (var i = 0; i < dexElements.length; i++) {
                    var dexFile = dexElements[i].dexFile.value;
                    if (dexFile) {
                        var dexPath = dexFile.getName();
                        console.log('[*] 已加载dex: ' + dexPath);
                        // 可结合frida-dexdump自动dump
                    }
                }
            } catch (e) {
                // 忽略非BaseDexClassLoader类型的加载器
            }
        },
        onComplete: function () {
            // 遍历完成
        }
    });
}); 