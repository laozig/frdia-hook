// 通杀系统时间获取
Java.perform(function () {
    var System = Java.use('java.lang.System');
    System.currentTimeMillis.implementation = function () {
        var t = this.currentTimeMillis();
        console.log('[*] System.currentTimeMillis: ' + t);
        return t;
    };
    var Date = Java.use('java.util.Date');
    Date.$init.overload().implementation = function () {
        var d = this.$init();
        console.log('[*] new Date(): ' + d.toString());
        return d;
    };
}); 