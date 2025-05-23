// dump_内存解密dex.js
Java.perform(function () {
    var DexFile = Java.use('dalvik.system.DexFile');
    DexFile.loadDex.overload('java.lang.String', 'java.lang.String', 'int').implementation = function (sourcePath, outputPath, flags) {
        console.log('[*] 内存解密dex加载: ' + sourcePath + ' -> ' + outputPath);
        // 这里可结合frida-dexdump等工具自动dump内存dex
        return this.loadDex(sourcePath, outputPath, flags);
    };
}); 