// Hook 沙箱检测常用方法，绕过沙箱检测
Java.perform(function () {
    var System = Java.use('java.lang.System');
    System.getProperty.overload('java.lang.String').implementation = function (key) {
        if (key.indexOf('vbox') !== -1 || key.indexOf('virtualbox') !== -1 || key.indexOf('qemu') !== -1) {
            console.log("[*] System.getProperty called for sandbox check: " + key + " (return fake)");
            return "";
        }
        return this.getProperty(key);
    };
}); 