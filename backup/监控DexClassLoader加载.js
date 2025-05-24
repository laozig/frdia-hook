/*
 * 脚本名称：监控DexClassLoader加载.js
 * 功能描述：监控应用使用DexClassLoader加载外部DEX文件的行为
 * 
 * 适用场景：
 *   - 分析应用动态加载外部代码的行为
 *   - 发现应用热更新或插件化机制
 *   - 监控应用从网络、SD卡等位置加载的代码
 *   - 分析加固应用的解密后DEX加载过程
 *   - 追踪应用运行时加载的恶意代码
 *
 * 使用方法：
 *   1. frida -U -f 目标应用包名 -l 监控DexClassLoader加载.js --no-pause
 *   2. 或者 frida -U --attach-pid 目标进程PID -l 监控DexClassLoader加载.js
 *   3. 操作应用，观察控制台输出的DEX加载路径
 *
 * 启动方式说明：
 *   - -U: 使用USB连接的设备
 *   - -f: 指定以spawn方式启动的应用包名
 *   - --attach-pid: 附加到已运行的进程
 *   - --no-pause: 注入后不暂停应用执行
 *
 * 工作原理：
 *   Hook dalvik.system.DexClassLoader类的构造函数，该类是Android系统中专门用于加载外部DEX文件的类加载器。
 *   当应用创建DexClassLoader实例加载外部DEX文件时，脚本会拦截构造函数调用并记录DEX文件的路径，
 *   这有助于发现应用动态加载的代码来源，如网络下载的更新包、内置的加密DEX等。
 *
 * 注意事项：
 *   - 现代Android应用可能使用其他类加载器如PathClassLoader、InMemoryDexClassLoader等
 *   - 建议与dump_classloader_dex.js等脚本配合使用，获取更全面的信息
 *   - 发现外部DEX后，可以使用frida-dexdump等工具提取DEX文件进行分析
 *   - 某些应用可能对加载的DEX路径进行混淆或使用内存加载方式规避检测
 *   - 与监控ClassLoader动态加载.js配合使用效果更佳
 */

// Hook DexClassLoader，监控动态 dex 加载
Java.perform(function () {
    var DexClassLoader = Java.use("dalvik.system.DexClassLoader");
    DexClassLoader.$init.implementation = function (dexPath, optimizedDirectory, librarySearchPath, parent) {
        console.log("[*] DexClassLoader loaded dex: " + dexPath);
        return this.$init(dexPath, optimizedDirectory, librarySearchPath, parent);
    };
}); 