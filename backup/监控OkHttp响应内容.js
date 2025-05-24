/*
 * 脚本名称：监控OkHttp响应内容.js
 * 功能描述：监控Android应用中使用OkHttp库发起的网络请求和响应内容
 * 
 * 适用场景：
 *   - 分析应用与服务器通信数据
 *   - 调试API接口和数据格式
 *   - 提取加密传输的数据内容
 *   - 抓取无法使用代理工具捕获的HTTPS流量
 *   - 分析OkHttp框架的请求处理流程
 *
 * 使用方法：
 *   1. frida -U -f 目标应用包名 -l 监控OkHttp响应内容.js --no-pause
 *   2. 或者 frida -U --attach-pid 目标进程PID -l 监控OkHttp响应内容.js
 *   3. 操作应用，触发网络请求，观察控制台输出的请求和响应数据
 *
 * 启动方式说明：
 *   - -U: 使用USB连接的设备
 *   - -f: 指定以spawn方式启动的应用包名
 *   - --attach-pid: 附加到已运行的进程
 *   - --no-pause: 注入后不暂停应用执行
 *
 * 工作原理：
 *   Hook OkHttp框架的Response对象中的body()方法，该方法返回响应正文的ResponseBody对象。
 *   然后通过调用ResponseBody的string()方法获取完整响应内容，并记录请求URL和响应数据。
 *   通过这种方式可以获取应用网络通信的原始数据，包括已解密的HTTPS内容。
 *
 * 注意事项：
 *   - 此脚本专用于使用OkHttp库的应用，不适用于其他网络库
 *   - 对于大型响应体，可能会影响应用性能
 *   - 某些版本的OkHttp可能需要调整类路径
 *   - ResponseBody只能读取一次，注意在读取后进行恢复
 *   - 不同OkHttp版本可能需要调整Hook点
 */

// 监控 OkHttp 的网络请求响应内容
// 作用：获取应用使用OkHttp库发起的网络请求和响应内容，便于分析API数据。
Java.perform(function () {
    try {
        var Response = Java.use('okhttp3.Response');
        
        // Hook Response对象的body()方法
        Response.body.implementation = function () {
            var responseBody = this.body();
            if (responseBody) {
                try {
                    // 获取请求URL
                    var request = this.request();
                    var url = request.url().toString();
                    
                    console.log("\n[*] OkHttp请求URL:");
                    console.log("    " + url);
                    
                    // 克隆ResponseBody，因为它只能被消费一次
                    var bodyString = responseBody.string();
                    var responseContentType = responseBody.contentType();
                    
                    console.log("[*] OkHttp响应内容:");
                    console.log(bodyString);
                    
                    // 重新创建一个ResponseBody返回，避免原始数据被消费导致应用异常
                    var MediaType = Java.use('okhttp3.MediaType');
                    var ResponseBody = Java.use('okhttp3.ResponseBody');
                    var Buffer = Java.use('okio.Buffer');
                    var ByteString = Java.use('okio.ByteString');
                    
                    // 构建新的ResponseBody
                    var newBody = ResponseBody.create(
                        responseContentType, 
                        ByteString.of(Java.array('byte', bodyString.getBytes())));
                        
                    return newBody;
                } catch (e) {
                    console.log("[!] 读取响应体错误: " + e);
                    return responseBody; // 出错时返回原始responseBody
                }
            }
            return responseBody;
        };
        
        console.log("[*] OkHttp响应监控已启动");
        console.log("[*] 等待网络请求...");
    } catch (e) {
        console.log("[!] Hook OkHttp失败: " + e);
    }
}); 