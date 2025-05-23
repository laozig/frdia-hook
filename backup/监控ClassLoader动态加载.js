// Hook ClassLoader 的 loadClass 方法，监控类的动态加载
Java.perform(function () {
    var ClassLoader = Java.use("java.lang.ClassLoader");
    ClassLoader.loadClass.overload('java.lang.String').implementation = function (name) {
        console.log("[*] ClassLoader.loadClass: " + name);
        return this.loadClass(name);
    };
}); 