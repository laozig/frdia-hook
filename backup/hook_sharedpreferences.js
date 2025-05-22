// Hook SharedPreferences 的 getString 和 putString 方法，监控配置读写
Java.perform(function () {
    var SharedPreferences = Java.use("android.app.SharedPreferencesImpl");
    SharedPreferences.getString.overload('java.lang.String', 'java.lang.String').implementation = function (key, defValue) {
        var result = this.getString(key, defValue);
        console.log("[*] SharedPreferences.getString key: " + key + ", value: " + result);
        return result;
    };
    SharedPreferences.putString.implementation = function (key, value) {
        console.log("[*] SharedPreferences.putString key: " + key + ", value: " + value);
        return this.putString(key, value);
    };
}); 