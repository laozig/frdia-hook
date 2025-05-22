// Hook 检查 root 的常用方法，绕过 root 检测
Java.perform(function () {
    var File = Java.use('java.io.File');
    File.exists.implementation = function () {
        var path = this.getAbsolutePath();
        if (path.indexOf("su") !== -1 || path.indexOf("busybox") !== -1) {
            console.log("[*] File.exists called for root check: " + path + " (return false)");
            return false;
        }
        return this.exists();
    };
}); 