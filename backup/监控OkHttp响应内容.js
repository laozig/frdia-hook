// Hook OkHttp 的网络响应，监控所有响应内容
Java.perform(function () {
    var Response = Java.use('okhttp3.Response');
    var ResponseBody = Java.use('okhttp3.ResponseBody');
    ResponseBody.string.implementation = function () {
        var result = this.string();
        console.log("[*] OkHttp Response Body: " + result);
        return result;
    };
}); 