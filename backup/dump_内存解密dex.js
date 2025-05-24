/*
 * 脚本名称：dump_内存解密dex.js
 * 功能描述：监控并记录应用解密并加载DEX文件的行为，有助于获取内存中解密后的DEX文件
 * 
 * 适用场景：
 *   - 分析加固应用的DEX解密流程
 *   - 提取动态解密并加载的DEX文件
 *   - 绕过应用的加密保护机制
 *   - 分析代码混淆和保护机制
 *   - 获取运行时动态生成的代码
 *
 * 使用方法：
 *   1. frida -U -f 目标应用包名 -l dump_内存解密dex.js --no-pause
 *   2. 或者 frida -U --attach-pid 目标进程PID -l dump_内存解密dex.js
 *   3. 操作应用触发DEX加载，观察控制台输出
 *   4. 可选：结合frida-dexdump等工具在检测到DEX加载时自动提取内存中的DEX文件
 *
 * 启动方式说明：
 *   - -U: 使用USB连接的设备
 *   - -f: 指定以spawn方式启动的应用包名
 *   - --attach-pid: 附加到已运行的进程
 *   - --no-pause: 注入后不暂停应用执行
 *
 * 工作原理：
 *   Hook dalvik.system.DexFile类的loadDex方法，这是Android系统用于加载DEX文件的关键API。
 *   当应用调用此方法加载解密后的DEX文件时，脚本会拦截并记录源文件路径和输出路径，
 *   这通常发生在加固应用解密其保护的DEX文件后。此时内存中已经存在解密后的DEX内容，
 *   可以与内存dump工具配合使用来提取这些解密后的DEX文件。
 *
 * 注意事项：
 *   - 需要配合内存dump工具（如frida-dexdump）才能实际提取DEX文件
 *   - 某些加固应用可能使用自定义类加载器或非标准方式加载DEX，需要额外监控
 *   - 加载DEX的时机可能很早，建议使用spawn模式以捕获应用启动时的DEX加载
 *   - 当解密的DEX仅存在于内存中时，需要及时捕获，应用可能会在使用后清除
 *   - 部分应用可能实现了反Frida检测，需要配合反检测脚本使用
 */

// Hook DexFile的loadDex方法，监控DEX加载过程
Java.perform(function () {
    var DexFile = Java.use('dalvik.system.DexFile');
    DexFile.loadDex.overload('java.lang.String', 'java.lang.String', 'int').implementation = function (sourcePath, outputPath, flags) {
        console.log('[*] 内存解密dex加载: ' + sourcePath + ' -> ' + outputPath);
        // 这里可结合frida-dexdump等工具自动dump内存dex
        return this.loadDex(sourcePath, outputPath, flags);
    };
}); 