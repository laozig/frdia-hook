// 监控HttpURLConnection网络请求
Java.perform(function () {
    var HttpURLConnection = Java.use('java.net.HttpURLConnection');
    HttpURLConnection.connect.implementation = function () {
        console.log('[*] HttpURLConnection 连接: ' + this.getURL());
        return this.connect();
    };
    HttpURLConnection.getInputStream.implementation = function () {
        console.log('[*] HttpURLConnection 获取输入流: ' + this.getURL());
        return this.getInputStream();
    };
}); 