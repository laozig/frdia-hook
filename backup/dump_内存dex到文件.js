/*
 * 脚本名称：dump_内存dex到文件.js
 * 功能：自动dump内存中的DEX文件到本地/data/data/包名/目录下
 * 适用场景：壳类应用脱壳、动态加载DEX分析
 * 使用方法：
 *   1. 启动目标App（推荐spawn方式，防止壳检测）
 *   2. frida -U -f 包名 -l dump_内存dex到文件.js --no-pause
 *   3. 脚本会自动在DEX加载时dump到/data/data/包名/dump_xxx.dex
 *   4. 用adb pull拉取文件分析
 * 启动方式说明：
 *   - -U 代表USB设备
 *   - -f 代表spawn启动（推荐）
 *   - --no-pause 保证App正常运行
 * 注意事项：
 *   - 需root或frida-server有写/data/data权限
 *   - 某些壳可能需配合其他反检测脚本
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