// dump_classloader_dex.js
Java.perform(function () {
    var BaseDexClassLoader = Java.use('dalvik.system.BaseDexClassLoader');
    BaseDexClassLoader.$init.implementation = function (dexPath, optimizedDirectory, librarySearchPath, parent) {
        console.log('[*] ClassLoader加载dex: ' + dexPath);
        // 这里可结合frida-dexdump等工具自动dump
        return this.$init(dexPath, optimizedDirectory, librarySearchPath, parent);
    };
}); 