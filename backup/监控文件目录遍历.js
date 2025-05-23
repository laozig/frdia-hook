// 监控文件目录遍历
Java.perform(function () {
    var File = Java.use('java.io.File');
    File.listFiles.implementation = function () {
        console.log('[*] 遍历文件目录: ' + this.getAbsolutePath());
        return this.listFiles();
    };
    File.list.implementation = function () {
        console.log('[*] 遍历文件目录: ' + this.getAbsolutePath());
        return this.list();
    };
}); 