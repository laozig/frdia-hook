// Hook OkHttp 的网络请求，监控所有请求的 URL 和请求体
Java.perform(function () {
    var Request = Java.use('okhttp3.Request');
    var RealCall = Java.use('okhttp3.RealCall');
    RealCall.execute.implementation = function () {
        var request = this.request();
        console.log("[*] OkHttp Request URL: " + request.url().toString());
        var body = request.body();
        if (body) {
            try {
                var Buffer = Java.use('okio.Buffer');
                var buffer = Buffer.$new();
                body.writeTo(buffer);
                var charset = Java.use('java.nio.charset.Charset').forName('UTF-8');
                var content = buffer.readString(charset);
                console.log("[*] OkHttp Request Body: " + content);
            } catch (e) {
                console.log("[*] OkHttp Request Body: <error reading body>");
            }
        }
        return this.execute();
    };
}); 