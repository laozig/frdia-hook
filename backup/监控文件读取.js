// Hook FileInputStream，监控文件读取
Java.perform(function () {
    var FileInputStream = Java.use("java.io.FileInputStream");
    FileInputStream.$init.overload('java.lang.String').implementation = function (filename) {
        console.log("[*] FileInputStream open file: " + filename);
        return this.$init(filename);
    };
}); 