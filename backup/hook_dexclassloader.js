// Hook DexClassLoader，监控动态 dex 加载
Java.perform(function () {
    var DexClassLoader = Java.use("dalvik.system.DexClassLoader");
    DexClassLoader.$init.implementation = function (dexPath, optimizedDirectory, librarySearchPath, parent) {
        console.log("[*] DexClassLoader loaded dex: " + dexPath);
        return this.$init(dexPath, optimizedDirectory, librarySearchPath, parent);
    };
}); 