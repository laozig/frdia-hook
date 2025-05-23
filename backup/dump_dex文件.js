// dump_dex文件.js
Java.perform(function () {
    var DexFile = Java.use('dalvik.system.DexFile');
    DexFile.loadDex.overload('java.lang.String', 'java.lang.String', 'int').implementation = function (sourcePath, outputPath, flags) {
        console.log('[*] DEX加载: ' + sourcePath + ' -> ' + outputPath);
        var result = this.loadDex(sourcePath, outputPath, flags);
        // 这里可结合frida-dexdump等工具自动dump内存dex
        return result;
    };
}); 