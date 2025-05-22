// Hook FileOutputStream，监控文件写入
Java.perform(function () {
    var FileOutputStream = Java.use("java.io.FileOutputStream");
    FileOutputStream.$init.overload('java.lang.String').implementation = function (filename) {
        console.log("[*] FileOutputStream write file: " + filename);
        return this.$init(filename);
    };
}); 