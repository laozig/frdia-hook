/*
 * 脚本名称：dump_内存dex到文件.js
 * 功能描述：自动监控并转储应用加载的DEX文件到本地存储
 * 
 * 适用场景：
 *   - 提取加固应用解密后的DEX文件
 *   - 获取动态加载的插件或热更新DEX
 *   - 分析应用的代码保护机制
 *   - 提取内存中的动态生成代码
 *   - 绕过应用的DEX文件保护措施
 *
 * 使用方法：
 *   1. frida -U -f 目标应用包名 -l dump_内存dex到文件.js --no-pause
 *   2. 或者 frida -U --attach-pid 目标进程PID -l dump_内存dex到文件.js
 *   3. 操作应用触发DEX加载
 *   4. DEX文件将被自动保存到/data/data/[包名]/dump_xxx.dex
 *   5. 使用adb pull /data/data/[包名]/dump_xxx.dex 命令提取文件到电脑
 *
 * 启动方式说明：
 *   - -U: 使用USB连接的设备
 *   - -f: 指定以spawn方式启动的应用包名（推荐，可捕获启动时加载的DEX）
 *   - --attach-pid: 附加到已运行的进程
 *   - --no-pause: 注入后不暂停应用执行
 *
 * 工作原理：
 *   Hook dalvik.system.DexFile类的loadDex方法，该方法是Android系统加载DEX文件的关键API。
 *   当应用调用此方法加载DEX文件时，脚本会拦截调用并记录源文件路径和输出路径，
 *   然后读取源文件内容并将其复制到应用的私有目录下，使用dump_前缀命名。
 *   这种方式可以获取应用在运行时解密或动态加载的DEX文件，包括那些通常无法直接访问的文件。
 *
 * 注意事项：
 *   - 需要root权限或Frida服务器具有对应权限
 *   - 某些加固应用可能在内存中直接加载DEX，此时源文件可能无法正确转储
 *   - 部分应用可能使用自定义类加载器或非标准方式加载DEX
 *   - 对于内存中动态生成的DEX，建议使用frida-dexdump等工具
 *   - 转储的文件保存在应用私有目录，需要使用adb命令提取
 *   - 可能需要配合反检测脚本使用，避免被应用发现
 */

// dump_内存dex到文件.js
Java.perform(function () {
    var DexFile = Java.use('dalvik.system.DexFile');
    DexFile.loadDex.overload('java.lang.String', 'java.lang.String', 'int').implementation = function (sourcePath, outputPath, flags) {
        var result = this.loadDex(sourcePath, outputPath, flags);
        console.log('[*] DEX加载: ' + sourcePath + ' -> ' + outputPath);
        // 自动dump到指定路径
        try {
            var File = Java.use('java.io.File');
            var src = File.$new(sourcePath);
            var dst = File.$new('/data/data/' + Java.use('android.os.Build').USER.value + '/dump_' + src.getName());
            var fis = Java.use('java.io.FileInputStream').$new(src);
            var fos = Java.use('java.io.FileOutputStream').$new(dst);
            var buffer = Java.array('byte', [1024]);
            var len;
            while ((len = fis.read(buffer)) > 0) {
                fos.write(buffer, 0, len);
            }
            fis.close();
            fos.close();
            console.log('[*] DEX已dump到: ' + dst.getAbsolutePath());
        } catch (e) {
            console.log('[!] dump dex error: ' + e);
        }
        return result;
    };
}); 