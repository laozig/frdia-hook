/*
 * 脚本名称：network_monitor.js
 * 功能描述：全面监控Android应用的网络通信，包括HTTP/HTTPS请求、WebSocket通信等
 * 
 * 适用场景：
 *   - 分析应用的API通信内容和格式
 *   - 监控应用发送的敏感数据
 *   - 检查应用的请求和响应安全性
 *   - 调试网络相关问题
 *   - 分析应用与服务器的交互逻辑
 *   - 审查应用的数据传输加密方式
 *   - 辅助逆向分析应用的API接口规范
 *
 * 使用方法：
 *   1. 可通过frida_master.js主入口文件加载(推荐)
 *   2. 也可单独使用: frida -U -f 目标应用包名 -l network_monitor.js --no-pause
 *   3. 或者 frida -U --attach-pid 目标进程PID -l network_monitor.js
 *
 * 启动方式说明：
 *   - -U: 使用USB连接的设备
 *   - -f: 指定以spawn方式启动的应用包名
 *   - --attach-pid: 附加到已运行的进程
 *   - --no-pause: 注入后不暂停应用执行
 *
 * 工作原理：
 *   本脚本监控多种网络通信渠道：
 *
 *   1. HTTP/HTTPS库监控：
 *      - OkHttp(2.x/3.x): 监控请求创建和执行
 *      - HttpURLConnection: 监控连接创建和输入/输出流
 *      - Volley: 监控请求队列和响应处理
 *
 *   2. WebView监控：
 *      - 监控WebView的URL加载
 *      - 拦截WebView的JavaScript交互
 *      - 记录WebView中的表单提交
 *
 *   3. WebSocket监控：
 *      - 监控WebSocket连接建立
 *      - 记录发送和接收的消息
 *
 *   4. 原生Socket监控：
 *      - 跟踪Socket连接创建
 *      - 监控Socket数据输入和输出
 *
 *   对于每个网络请求，脚本记录：
 *   - 完整URL和HTTP方法
 *   - 请求头和响应头
 *   - 请求体和响应体内容
 *   - 响应状态码
 *   - 请求和响应的时间戳
 *
 * 注意事项：
 *   - 与SSL证书绕过脚本配合使用可监控HTTPS流量
 *   - 大型响应体可能被截断以避免内存占用过高
 *   - 使用自定义网络库的应用可能需要额外定制
 *   - 二进制数据传输可能无法正确显示为文本
 *   - 与通杀绕过SSL Pinning.js配合使用效果最佳
 */

module.exports = function(config, logger, utils) {
    var tag = "NETWORK";
    logger.info(tag, "网络监控模块初始化");
    
    // 存储网络请求
    var networkRequests = {
        count: 0,
        requests: {},
        addRequest: function(id, url, method, headers, body) {
            this.count++;
            this.requests[id] = {
                url: url,
                method: method,
                headers: headers,
                requestBody: body,
                timestamp: new Date(),
                response: null
            };
            
            logger.info(tag, "请求 [" + id + "]: " + method + " " + url);
            if (headers) {
                logger.debug(tag, "请求头: " + JSON.stringify(headers));
            }
            if (body) {
                logger.debug(tag, "请求体: " + body);
            }
        },
        addResponse: function(id, code, headers, body) {
            if (!this.requests[id]) {
                logger.warn(tag, "未找到请求ID: " + id);
                return;
            }
            
            this.requests[id].response = {
                code: code,
                headers: headers,
                body: body,
                timestamp: new Date()
            };
            
            logger.info(tag, "响应 [" + id + "]: " + code);
            if (headers) {
                logger.debug(tag, "响应头: " + JSON.stringify(headers));
            }
            if (body) {
                logger.debug(tag, "响应体: " + body);
            }
        },
        generateId: function() {
            return "req_" + this.count;
        }
    };
    
    // 开始Hook网络相关API
    Java.perform(function() {
        // 1. OkHttp3
        hookOkHttp3();
        
        // 2. HttpURLConnection
        hookHttpURLConnection();
        
        // 3. WebView
        hookWebView();
        
        // 4. Volley
        hookVolley();
        
        // 5. WebSocket
        hookWebSocket();
        
        // 6. Socket (原生Socket)
        hookSocket();
    });
    
    // Hook OkHttp3
    function hookOkHttp3() {
        try {
            // 检测是否使用了OkHttp3
            var OkHttpClient = Java.use("okhttp3.OkHttpClient");
            var Request = Java.use("okhttp3.Request");
            var RequestBody = Java.use("okhttp3.RequestBody");
            var Response = Java.use("okhttp3.Response");
            var ResponseBody = Java.use("okhttp3.ResponseBody");
            var Buffer = Java.use("okio.Buffer");
            var Charset = Java.use("java.nio.charset.Charset");
            var UTF8 = Charset.forName("UTF-8");
            
            // Hook OkHttpClient.newCall方法
            OkHttpClient.newCall.implementation = function(request) {
                var call = this.newCall(request);
                
                // 获取请求信息
                var requestId = networkRequests.generateId();
                var url = request.url().toString();
                var method = request.method();
                
                // 获取请求头
                var headers = {};
                var headerNames = request.headers().names().toArray();
                for (var i = 0; i < headerNames.length; i++) {
                    var name = headerNames[i];
                    headers[name] = request.header(name);
                }
                
                // 获取请求体
                var requestBody = null;
                var body = request.body();
                if (body) {
                    try {
                        var buffer = Buffer.$new();
                        body.writeTo(buffer);
                        requestBody = buffer.readString(UTF8);
                    } catch (e) {
                        requestBody = "<无法读取请求体>";
                    }
                }
                
                networkRequests.addRequest(requestId, url, method, headers, requestBody);
                
                // 创建新的Call对象，拦截响应
                var originalCall = call;
                
                // Hook Call.execute方法
                try {
                    var RealCall = Java.use("okhttp3.RealCall");
                    var originalExecute = RealCall.execute;
                    
                    RealCall.execute.implementation = function() {
                        var response = originalExecute.call(this);
                        
                        try {
                            // 获取响应信息
                            var code = response.code();
                            
                            // 获取响应头
                            var responseHeaders = {};
                            var respHeaderNames = response.headers().names().toArray();
                            for (var i = 0; i < respHeaderNames.length; i++) {
                                var name = respHeaderNames[i];
                                responseHeaders[name] = response.header(name);
                            }
                            
                            // 获取响应体
                            var responseBodyString = null;
                            var respBody = response.body();
                            if (respBody) {
                                try {
                                    // 不能直接读取响应体，因为它只能被消费一次
                                    // 创建一个克隆的响应体
                                    var source = respBody.source();
                                    source.request(Long.MAX_VALUE); // 缓冲整个body
                                    var bodyString = source.buffer().clone().readString(UTF8);
                                    responseBodyString = bodyString;
                                } catch (e) {
                                    responseBodyString = "<无法读取响应体: " + e + ">";
                                }
                            }
                            
                            networkRequests.addResponse(requestId, code, responseHeaders, responseBodyString);
                        } catch (e) {
                            logger.error(tag, "处理OkHttp响应时出错: " + e);
                        }
                        
                        return response;
                    };
                } catch (e) {
                    logger.error(tag, "Hook OkHttp3.RealCall.execute失败: " + e);
                }
                
                return call;
            };
            
            logger.info(tag, "已Hook OkHttp3");
        } catch (e) {
            logger.debug(tag, "Hook OkHttp3失败，应用可能未使用此库: " + e);
        }
    }
    
    // Hook HttpURLConnection
    function hookHttpURLConnection() {
        try {
            var URL = Java.use("java.net.URL");
            var HttpURLConnection = Java.use("java.net.HttpURLConnection");
            var InputStream = Java.use("java.io.InputStream");
            var BufferedReader = Java.use("java.io.BufferedReader");
            var InputStreamReader = Java.use("java.io.InputStreamReader");
            var StringBuilder = Java.use("java.lang.StringBuilder");
            
            // Hook URL.openConnection
            URL.openConnection.overload().implementation = function() {
                var connection = this.openConnection();
                
                if (connection.$className.indexOf("HttpURLConnection") >= 0) {
                    var requestId = networkRequests.generateId();
                    var url = this.toString();
                    
                    // 保存URL信息
                    Java.retain(connection);
                    connection.requestId = requestId;
                    connection.urlString = url;
                    
                    // Hook connect方法
                    if (connection.connect) {
                        var originalConnect = connection.connect;
                        connection.connect.implementation = function() {
                            var method = this.getRequestMethod();
                            
                            // 获取请求头
                            var headers = {};
                            var headerFields = this.getRequestProperties();
                            var keys = headerFields.keySet().toArray();
                            for (var i = 0; i < keys.length; i++) {
                                var key = keys[i];
                                headers[key] = headerFields.get(key).toString();
                            }
                            
                            networkRequests.addRequest(requestId, url, method, headers, null);
                            
                            return originalConnect.call(this);
                        };
                    }
                    
                    // Hook getInputStream方法
                    if (connection.getInputStream) {
                        var originalGetInputStream = connection.getInputStream;
                        connection.getInputStream.implementation = function() {
                            var responseCode = this.getResponseCode();
                            
                            // 获取响应头
                            var headers = {};
                            var headerFields = this.getHeaderFields();
                            var keys = headerFields.keySet().toArray();
                            for (var i = 0; i < keys.length; i++) {
                                var key = keys[i];
                                if (key !== null) { // 跳过状态行
                                    headers[key] = headerFields.get(key).toString();
                                }
                            }
                            
                            var inputStream = originalGetInputStream.call(this);
                            
                            try {
                                // 读取响应体
                                var reader = BufferedReader.$new(InputStreamReader.$new(inputStream));
                                var sb = StringBuilder.$new();
                                var line;
                                while ((line = reader.readLine()) !== null) {
                                    sb.append(line);
                                }
                                var responseBody = sb.toString();
                                
                                networkRequests.addResponse(requestId, responseCode, headers, responseBody);
                                
                                // 重新创建InputStream
                                var bytes = responseBody.getBytes();
                                var byteArrayInputStream = Java.use("java.io.ByteArrayInputStream").$new(bytes);
                                return byteArrayInputStream;
                            } catch (e) {
                                logger.error(tag, "处理HttpURLConnection响应时出错: " + e);
                                return inputStream;
                            }
                        };
                    }
                }
                
                return connection;
            };
            
            logger.info(tag, "已Hook HttpURLConnection");
        } catch (e) {
            logger.error(tag, "Hook HttpURLConnection失败: " + e);
        }
    }
    
    // Hook WebView
    function hookWebView() {
        try {
            var WebView = Java.use("android.webkit.WebView");
            
            // Hook loadUrl
            WebView.loadUrl.overload('java.lang.String').implementation = function(url) {
                var requestId = networkRequests.generateId();
                networkRequests.addRequest(requestId, url, "GET", null, null);
                return this.loadUrl(url);
            };
            
            // Hook loadData
            WebView.loadData.implementation = function(data, mimeType, encoding) {
                var requestId = networkRequests.generateId();
                networkRequests.addRequest(requestId, "data://" + mimeType, "LOAD_DATA", null, data);
                return this.loadData(data, mimeType, encoding);
            };
            
            // Hook loadDataWithBaseURL
            WebView.loadDataWithBaseURL.implementation = function(baseUrl, data, mimeType, encoding, historyUrl) {
                var requestId = networkRequests.generateId();
                networkRequests.addRequest(requestId, baseUrl, "LOAD_DATA_WITH_BASE_URL", null, data);
                return this.loadDataWithBaseURL(baseUrl, data, mimeType, encoding, historyUrl);
            };
            
            // Hook postUrl
            WebView.postUrl.implementation = function(url, postData) {
                var requestId = networkRequests.generateId();
                var postDataStr = null;
                try {
                    postDataStr = Java.use("java.lang.String").$new(postData, "UTF-8");
                } catch (e) {
                    postDataStr = "<无法解析的二进制数据>";
                }
                networkRequests.addRequest(requestId, url, "POST", null, postDataStr);
                return this.postUrl(url, postData);
            };
            
            logger.info(tag, "已Hook WebView");
        } catch (e) {
            logger.error(tag, "Hook WebView失败: " + e);
        }
    }
    
    // Hook Volley
    function hookVolley() {
        try {
            // 尝试Hook Volley的RequestQueue
            var RequestQueue = Java.use("com.android.volley.RequestQueue");
            if (RequestQueue) {
                RequestQueue.add.overload('com.android.volley.Request').implementation = function(request) {
                    var requestId = networkRequests.generateId();
                    
                    var url = request.getUrl();
                    var method = request.getMethod();
                    var methodStr = "";
                    
                    // 转换数字方法为字符串
                    switch (method) {
                        case 0: methodStr = "GET"; break;
                        case 1: methodStr = "POST"; break;
                        case 2: methodStr = "PUT"; break;
                        case 3: methodStr = "DELETE"; break;
                        case 4: methodStr = "HEAD"; break;
                        case 5: methodStr = "OPTIONS"; break;
                        case 6: methodStr = "TRACE"; break;
                        case 7: methodStr = "PATCH"; break;
                        default: methodStr = "UNKNOWN";
                    }
                    
                    // 获取请求头
                    var headers = {};
                    try {
                        var headerMap = request.getHeaders();
                        if (headerMap) {
                            var keys = headerMap.keySet().toArray();
                            for (var i = 0; i < keys.length; i++) {
                                var key = keys[i];
                                headers[key] = headerMap.get(key);
                            }
                        }
                    } catch (e) {
                        logger.debug(tag, "获取Volley请求头失败: " + e);
                    }
                    
                    // 获取请求体
                    var body = null;
                    try {
                        body = request.getBody();
                        if (body) {
                            body = Java.use("java.lang.String").$new(body, "UTF-8");
                        }
                    } catch (e) {
                        logger.debug(tag, "获取Volley请求体失败: " + e);
                    }
                    
                    networkRequests.addRequest(requestId, url, methodStr, headers, body);
                    
                    // 监听响应
                    try {
                        var originalDeliverResponse = request.deliverResponse;
                        request.deliverResponse.implementation = function(response) {
                            try {
                                var responseBody = null;
                                if (response) {
                                    if (typeof response === 'string') {
                                        responseBody = response;
                                    } else if (response.data) {
                                        responseBody = response.data.toString();
                                    }
                                }
                                
                                networkRequests.addResponse(requestId, 200, null, responseBody);
                            } catch (e) {
                                logger.error(tag, "处理Volley响应时出错: " + e);
                            }
                            
                            return originalDeliverResponse.call(this, response);
                        };
                    } catch (e) {
                        logger.debug(tag, "Hook Volley响应失败: " + e);
                    }
                    
                    return this.add(request);
                };
                
                logger.info(tag, "已Hook Volley");
            }
        } catch (e) {
            logger.debug(tag, "Hook Volley失败，应用可能未使用此库: " + e);
        }
    }
    
    // Hook WebSocket
    function hookWebSocket() {
        try {
            // 尝试Hook OkHttp的WebSocket
            var WebSocket = Java.use("okhttp3.WebSocket");
            if (WebSocket) {
                WebSocket.send.overload('java.lang.String').implementation = function(text) {
                    var requestId = networkRequests.generateId();
                    networkRequests.addRequest(requestId, "WebSocket", "SEND_TEXT", null, text);
                    return this.send(text);
                };
                
                WebSocket.send.overload('okio.ByteString').implementation = function(bytes) {
                    var requestId = networkRequests.generateId();
                    networkRequests.addRequest(requestId, "WebSocket", "SEND_BYTES", null, "<二进制数据>");
                    return this.send(bytes);
                };
                
                logger.info(tag, "已Hook OkHttp WebSocket");
            }
        } catch (e) {
            logger.debug(tag, "Hook WebSocket失败，应用可能未使用此库: " + e);
        }
        
        try {
            // 尝试Hook标准WebSocket
            var StandardWebSocket = Java.use("javax.websocket.WebSocket");
            if (StandardWebSocket) {
                StandardWebSocket.sendText.implementation = function(text) {
                    var requestId = networkRequests.generateId();
                    networkRequests.addRequest(requestId, "StandardWebSocket", "SEND_TEXT", null, text);
                    return this.sendText(text);
                };
                
                StandardWebSocket.sendBinary.implementation = function(data) {
                    var requestId = networkRequests.generateId();
                    networkRequests.addRequest(requestId, "StandardWebSocket", "SEND_BINARY", null, "<二进制数据>");
                    return this.sendBinary(data);
                };
                
                logger.info(tag, "已Hook 标准WebSocket");
            }
        } catch (e) {
            logger.debug(tag, "Hook 标准WebSocket失败，应用可能未使用此库: " + e);
        }
    }
    
    // Hook Socket
    function hookSocket() {
        try {
            var Socket = Java.use("java.net.Socket");
            var OutputStream = Java.use("java.io.OutputStream");
            var InputStream = Java.use("java.io.InputStream");
            
            // Hook Socket.getOutputStream
            Socket.getOutputStream.implementation = function() {
                var host = this.getInetAddress().getHostAddress();
                var port = this.getPort();
                var outputStream = this.getOutputStream();
                
                // 创建代理OutputStream
                var originalWrite = outputStream.write;
                outputStream.write.overload('[B', 'int', 'int').implementation = function(buffer, offset, count) {
                    var data = Java.array('byte', buffer);
                    var requestId = networkRequests.generateId();
                    var dataStr = null;
                    try {
                        dataStr = Java.use("java.lang.String").$new(data, offset, count, "UTF-8");
                    } catch (e) {
                        dataStr = "<无法解析的二进制数据>";
                    }
                    networkRequests.addRequest(requestId, "socket://" + host + ":" + port, "SOCKET_WRITE", null, dataStr);
                    return originalWrite.call(this, buffer, offset, count);
                };
                
                return outputStream;
            };
            
            // Hook Socket.getInputStream
            Socket.getInputStream.implementation = function() {
                var host = this.getInetAddress().getHostAddress();
                var port = this.getPort();
                var inputStream = this.getInputStream();
                
                // 创建代理InputStream
                var originalRead = inputStream.read;
                inputStream.read.overload('[B', 'int', 'int').implementation = function(buffer, offset, count) {
                    var result = originalRead.call(this, buffer, offset, count);
                    if (result > 0) {
                        var data = Java.array('byte', buffer);
                        var requestId = networkRequests.generateId();
                        var dataStr = null;
                        try {
                            dataStr = Java.use("java.lang.String").$new(data, offset, result, "UTF-8");
                        } catch (e) {
                            dataStr = "<无法解析的二进制数据>";
                        }
                        networkRequests.addResponse(requestId, 200, null, dataStr);
                    }
                    return result;
                };
                
                return inputStream;
            };
            
            logger.info(tag, "已Hook Socket");
        } catch (e) {
            logger.error(tag, "Hook Socket失败: " + e);
        }
    }
    
    logger.info(tag, "网络监控模块加载完成");
    return {
        networkRequests: networkRequests
    };
}; 