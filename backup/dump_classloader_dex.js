/*
 * 脚本名称：dump_classloader_dex.js
 * 功能描述：监控应用使用ClassLoader加载DEX文件的行为，便于分析和提取动态加载的DEX
 * 
 * 适用场景：
 *   - 分析应用动态加载代码的行为
 *   - 检测应用使用的插件化框架
 *   - 提取应用热更新或动态下发的代码
 *   - 分析加固应用的类加载机制
 *   - 研究多DEX应用的代码加载流程
 *
 * 使用方法：
 *   1. frida -U -f 目标应用包名 -l dump_classloader_dex.js --no-pause
 *   2. 或者 frida -U --attach-pid 目标进程PID -l dump_classloader_dex.js
 *   3. 操作应用触发DEX加载，观察控制台输出的DEX路径
 *   4. 可选：结合frida-dexdump等工具自动提取加载的DEX文件
 *
 * 启动方式说明：
 *   - -U: 使用USB连接的设备
 *   - -f: 指定以spawn方式启动的应用包名
 *   - --attach-pid: 附加到已运行的进程
 *   - --no-pause: 注入后不暂停应用执行
 *
 * 工作原理：
 *   Hook dalvik.system.BaseDexClassLoader类的构造函数，该类是所有DEX类加载器的基类。
 *   当应用创建新的类加载器实例加载DEX文件时，脚本会拦截并记录DEX文件的路径，
 *   这可以揭示应用动态加载的代码来源，包括内部存储、assets目录或网络下载的DEX文件。
 *   通过分析这些DEX文件的来源和内容，可以深入了解应用的动态代码执行机制。
 *
 * 注意事项：
 *   - 应用可能使用多种类加载器，此脚本仅监控BaseDexClassLoader
 *   - 部分加固或混淆应用可能使用自定义加载机制规避标准类加载器
 *   - DEX路径可能是临时文件，需要及时提取或备份
 *   - 对于网络下载的DEX，可以配合网络监控脚本一起使用
 *   - 某些优化过的DEX加载可能包含ODEX等形式，需要额外处理
 */

// Hook BaseDexClassLoader构造函数，监控DEX加载
Java.perform(function () {
    var BaseDexClassLoader = Java.use('dalvik.system.BaseDexClassLoader');
    BaseDexClassLoader.$init.implementation = function (dexPath, optimizedDirectory, librarySearchPath, parent) {
        console.log('[*] ClassLoader加载dex: ' + dexPath);
        // 这里可结合frida-dexdump等工具自动dump
        return this.$init(dexPath, optimizedDirectory, librarySearchPath, parent);
    };
}); 