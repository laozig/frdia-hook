// dump_动态加载dex.js
Java.perform(function () {
    var DexClassLoader = Java.use('dalvik.system.DexClassLoader');
    DexClassLoader.$init.implementation = function (dexPath, optimizedDirectory, librarySearchPath, parent) {
        console.log('[*] 动态加载dex: ' + dexPath);
        // 这里可结合frida-dexdump等工具自动dump
        return this.$init(dexPath, optimizedDirectory, librarySearchPath, parent);
    };
    var PathClassLoader = Java.use('dalvik.system.PathClassLoader');
    PathClassLoader.$init.implementation = function (dexPath, parent) {
        console.log('[*] PathClassLoader加载dex: ' + dexPath);
        // 这里可结合frida-dexdump等工具自动dump
        return this.$init(dexPath, parent);
    };
}); 