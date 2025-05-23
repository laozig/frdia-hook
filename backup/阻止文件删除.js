// Hook 文件删除操作，监控和阻止文件删除
Java.perform(function () {
    var File = Java.use('java.io.File');
    File.delete.implementation = function () {
        var path = this.getAbsolutePath();
        console.log("[*] File.delete called: " + path + " (blocked)");
        return false; // 阻止删除
    };
}); 