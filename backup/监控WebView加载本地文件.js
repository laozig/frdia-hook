/*
 * 脚本名称：监控WebView加载本地文件.js
 * 功能：自动监控应用中WebView组件加载本地文件的操作
 * 适用场景：WebView安全检测、本地文件访问分析、隐藏功能发现、隐私数据分析
 * 使用方法：
 *   1. frida -U -f 包名 -l 监控WebView加载本地文件.js --no-pause
 *   2. 查看控制台输出，获取WebView加载信息
 * 启动方式说明：
 *   - -U 代表使用USB连接的设备
 *   - -f 代表以spawn方式启动目标应用
 *   - --no-pause 指示Frida不要暂停应用执行，保证App正常运行
 *   - 也可使用 -F 以attach方式附加到已运行的进程
 * 参数说明：
 *   - 包名：目标应用的包名，如com.example.app
 * 监控函数说明：
 *   - WebView.loadUrl(): 加载URL，可能是本地文件路径
 *   - WebView.loadData(): 加载HTML字符串内容
 *   - WebView.loadDataWithBaseURL(): 带基础URL加载HTML内容
 *   - WebView.loadRequest(): Android 11新增API
 *   - WebViewClient相关回调方法: 常用于URL拦截和SSL错误处理
 *   - WebChromeClient.onJsAlert/onJsPrompt: JavaScript交互
 * WebView安全风险：
 *   - 本地文件访问可能导致敏感文件泄露
 *   - File协议可能被用于跨域攻击
 *   - 不安全的JavaScript交互可能导致远程代码执行
 *   - 忽略SSL错误可能导致中间人攻击
 * 输出内容：
 *   - 加载URL: WebView请求的URL或本地文件路径
 *   - HTML内容: 动态加载的HTML代码
 *   - JavaScript交互: JS桥接口和方法调用
 *   - 调用位置: 发起请求的代码位置
 * 实际应用场景：
 *   - 发现本地隐藏功能入口
 *   - 分析WebView文件访问安全
 *   - 检测JavaScript桥安全问题
 *   - 查找潜在的XSS和文件访问漏洞
 * 注意事项：
 *   - 某些加固应用需配合反检测脚本
 *   - Android 9+限制了file://方案的使用
 *   - 监控大型应用可能产生大量日志输出
 */

// 监控WebView加载本地文件
Java.perform(function () {
    // 辅助函数：获取简短调用堆栈
    function getStackShort() {
        return Java.use("android.util.Log").getStackTraceString(
            Java.use("java.lang.Exception").$new()).split('\n').slice(2, 5).join('\n    ');
    }
    
    // 辅助函数: 检查URL是否为本地文件
    function isLocalFileUrl(url) {
        if (!url) return false;
        return url.startsWith('file://') || 
               url.startsWith('/sdcard/') || 
               url.startsWith('/data/') ||
               url.indexOf('content://') !== -1;
    }
    
    //===== WebView基本加载方法监控 =====
    var WebView = Java.use('android.webkit.WebView');
    
    // 监控WebView.loadUrl方法
    WebView.loadUrl.overload('java.lang.String').implementation = function (url) {
        console.log('[*] WebView.loadUrl: ' + url);
        
        // 检查是否为本地文件
        if (isLocalFileUrl(url)) {
            console.log('    [!] 警告: WebView加载本地文件');
            console.log('    调用堆栈: \n    ' + getStackShort());
        }
        
        // 检查是否为自定义协议
        if (url && !url.startsWith('http://') && !url.startsWith('https://') && 
            !url.startsWith('file://') && !url.startsWith('about:')) {
            console.log('    [!] 注意: 使用自定义URL协议: ' + url.split(':')[0]);
        }
        
        return this.loadUrl(url);
    };
    
    // 监控带headers的loadUrl重载
    WebView.loadUrl.overload('java.lang.String', 'java.util.Map').implementation = function (url, headers) {
        console.log('[*] WebView.loadUrl: ' + url + ' (带自定义headers)');
        
        // 检查特殊Headers
        try {
            var headerSet = headers.keySet();
            var iterator = headerSet.iterator();
            while (iterator.hasNext()) {
                var key = iterator.next();
                var value = headers.get(key);
                console.log('    Header: ' + key + ' = ' + value);
            }
        } catch (e) {}
        
        // 检查是否为本地文件
        if (isLocalFileUrl(url)) {
            console.log('    [!] 警告: WebView加载本地文件');
            console.log('    调用堆栈: \n    ' + getStackShort());
        }
        
        return this.loadUrl(url, headers);
    };
    
    // 监控WebView.loadData方法
    WebView.loadData.implementation = function (data, mimeType, encoding) {
        console.log('[*] WebView.loadData');
        console.log('    MIME类型: ' + mimeType);
        console.log('    编码: ' + encoding);
        
        // 显示加载的数据内容 (可能很长，只显示一部分)
        if (data) {
            var previewLen = Math.min(data.length, 200);
            console.log('    数据预览: ' + data.substring(0, previewLen) + 
                       (data.length > previewLen ? '...' : ''));
            
            // 查找敏感内容
            if (data.indexOf('javascript:') !== -1) {
                console.log('    [!] 注意: 包含JavaScript代码');
            }
            if (data.indexOf('<iframe') !== -1) {
                console.log('    [!] 注意: 包含iframe标签');
            }
            if (data.indexOf('eval(') !== -1) {
                console.log('    [!] 警告: 包含eval调用，可能存在安全风险');
            }
            if (data.indexOf('localStorage') !== -1 || data.indexOf('sessionStorage') !== -1) {
                console.log('    [!] 注意: 使用了Web存储API');
            }
        }
        
        return this.loadData(data, mimeType, encoding);
    };
    
    // 监控WebView.loadDataWithBaseURL方法
    WebView.loadDataWithBaseURL.implementation = function (baseUrl, data, mimeType, encoding, historyUrl) {
        console.log('[*] WebView.loadDataWithBaseURL');
        console.log('    基础URL: ' + baseUrl);
        console.log('    MIME类型: ' + mimeType);
        console.log('    编码: ' + encoding);
        console.log('    历史URL: ' + historyUrl);
        
        // 检查是否使用本地文件作为基础URL
        if (isLocalFileUrl(baseUrl)) {
            console.log('    [!] 警告: 使用本地文件作为基础URL');
            console.log('    调用堆栈: \n    ' + getStackShort());
        }
        
        // 显示加载的数据内容 (可能很长，只显示一部分)
        if (data) {
            var previewLen = Math.min(data.length, 200);
            console.log('    数据预览: ' + data.substring(0, previewLen) + 
                       (data.length > previewLen ? '...' : ''));
            
            // 查找敏感内容
            if (data.indexOf('javascript:') !== -1) {
                console.log('    [!] 注意: 包含JavaScript代码');
            }
            if (data.indexOf('<iframe') !== -1) {
                console.log('    [!] 注意: 包含iframe标签');
            }
        }
        
        return this.loadDataWithBaseURL(baseUrl, data, mimeType, encoding, historyUrl);
    };
    
    // 尝试监控Android 11+新增的WebView.loadRequest方法
    try {
        var WebResourceRequest = Java.use('android.webkit.WebResourceRequest');
        if (WebView.loadRequest) {
            WebView.loadRequest.implementation = function (request) {
                try {
                    var url = request.getUrl().toString();
                    console.log('[*] WebView.loadRequest: ' + url);
                    
                    // 检查是否为本地文件
                    if (isLocalFileUrl(url)) {
                        console.log('    [!] 警告: WebView加载本地文件');
                        console.log('    调用堆栈: \n    ' + getStackShort());
                    }
                    
                    // 输出请求头
                    try {
                        var headerNames = request.getRequestHeaders().keySet();
                        var iterator = headerNames.iterator();
                        while(iterator.hasNext()) {
                            var headerName = iterator.next();
                            console.log('    Header: ' + headerName + ' = ' + 
                                      request.getRequestHeaders().get(headerName));
                        }
                    } catch (e) {}
                    
                } catch (e) {
                    console.log('    无法获取请求详情: ' + e);
                }
                
                return this.loadRequest(request);
            };
        }
    } catch (e) {}
    
    //===== WebViewClient监控 =====
    try {
        var WebViewClient = Java.use('android.webkit.WebViewClient');
        
        // 监控shouldOverrideUrlLoading方法 (URL拦截)
        WebViewClient.shouldOverrideUrlLoading.overload('android.webkit.WebView', 'java.lang.String').implementation = function (webView, url) {
            console.log('[*] WebViewClient.shouldOverrideUrlLoading: ' + url);
            
            // 检查是否为本地文件
            if (isLocalFileUrl(url)) {
                console.log('    [!] 警告: 拦截本地文件URL');
                console.log('    调用堆栈: \n    ' + getStackShort());
            }
            
            // 检查是否是自定义协议
            if (url && !url.startsWith('http://') && !url.startsWith('https://') && 
                !url.startsWith('file://') && !url.startsWith('about:')) {
                console.log('    [!] 注意: 自定义URL协议: ' + url.split(':')[0]);
            }
            
            return this.shouldOverrideUrlLoading(webView, url);
        };
        
        // 监控新版本的shouldOverrideUrlLoading
        try {
            WebViewClient.shouldOverrideUrlLoading.overload('android.webkit.WebView', 'android.webkit.WebResourceRequest').implementation = function (webView, request) {
                var url = request.getUrl().toString();
                console.log('[*] WebViewClient.shouldOverrideUrlLoading(WebResourceRequest): ' + url);
                
                // 检查是否为本地文件
                if (isLocalFileUrl(url)) {
                    console.log('    [!] 警告: 拦截本地文件URL');
                    console.log('    调用堆栈: \n    ' + getStackShort());
                }
                
                return this.shouldOverrideUrlLoading(webView, request);
            };
        } catch (e) {}
        
        // 监控onReceivedSslError (SSL错误处理)
        WebViewClient.onReceivedSslError.implementation = function (webView, sslErrorHandler, sslError) {
            console.log('[*] WebViewClient.onReceivedSslError');
            console.log('    SSL错误: ' + sslError.toString());
            
            // 获取出现SSL错误的URL
            try {
                var url = sslError.getUrl();
                console.log('    URL: ' + url);
            } catch (e) {}
            
            console.log('    [!] 警告: SSL错误处理可能影响安全性');
            console.log('    调用堆栈: \n    ' + getStackShort());
            
            // 检查是否在方法中调用了proceed()，表示忽略SSL错误
            var isProceeding = false;
            try {
                // 获取此方法的实现源码（仅Android 9+可能支持）
                var methodImpl = this.onReceivedSslError.toString();
                isProceeding = methodImpl.indexOf("proceed") !== -1;
            } catch (e) {}
            
            if (isProceeding) {
                console.log('    [!] 严重警告: 应用忽略了SSL错误 (调用了sslErrorHandler.proceed())');
            }
            
            return this.onReceivedSslError(webView, sslErrorHandler, sslError);
        };
        
    } catch (e) {
        console.log("[-] WebViewClient Hook失败: " + e);
    }
    
    //===== WebChromeClient监控 (JavaScript交互) =====
    try {
        var WebChromeClient = Java.use('android.webkit.WebChromeClient');
        
        // 监控JavaScript警告框
        WebChromeClient.onJsAlert.overload('android.webkit.WebView', 'java.lang.String', 'java.lang.String', 'android.webkit.JsResult').implementation = function (webView, url, message, result) {
            console.log('[*] WebChromeClient.onJsAlert');
            console.log('    URL: ' + url);
            console.log('    消息: ' + message);
            return this.onJsAlert(webView, url, message, result);
        };
        
        // 监控JavaScript确认框
        WebChromeClient.onJsConfirm.implementation = function (webView, url, message, result) {
            console.log('[*] WebChromeClient.onJsConfirm');
            console.log('    URL: ' + url);
            console.log('    消息: ' + message);
            return this.onJsConfirm(webView, url, message, result);
        };
        
        // 监控JavaScript提示框 (常被用作JavaScript桥)
        WebChromeClient.onJsPrompt.implementation = function (webView, url, message, defaultValue, result) {
            console.log('[*] WebChromeClient.onJsPrompt');
            console.log('    URL: ' + url);
            console.log('    消息: ' + message);
            console.log('    默认值: ' + defaultValue);
            
            // 检查是否为JavaScript桥调用
            if (message && message.indexOf(':') !== -1) {
                console.log('    [!] 可能的JavaScript桥调用: ' + message);
            }
            
            return this.onJsPrompt(webView, url, message, defaultValue, result);
        };
    } catch (e) {
        console.log("[-] WebChromeClient Hook失败: " + e);
    }
    
    //===== 监控JavaScript接口 =====
    try {
        WebView.addJavascriptInterface.implementation = function (object, name) {
            console.log('[*] WebView.addJavascriptInterface');
            console.log('    接口名: ' + name);
            console.log('    接口对象: ' + object.getClass().getName());
            
            // 输出接口中的方法
            try {
                var methods = object.getClass().getDeclaredMethods();
                console.log('    导出的方法:');
                for (var i = 0; i < methods.length; i++) {
                    var method = methods[i];
                    console.log('      - ' + method.getName());
                    
                    // 检查是否有@JavascriptInterface注解
                    var annotations = method.getAnnotations();
                    var hasJsAnnotation = false;
                    for (var j = 0; j < annotations.length; j++) {
                        if (annotations[j].toString().indexOf('JavascriptInterface') !== -1) {
                            hasJsAnnotation = true;
                            break;
                        }
                    }
                    
                    if (!hasJsAnnotation) {
                        console.log('        [!] 警告: 方法缺少@JavascriptInterface注解');
                    }
                }
            } catch (e) {
                console.log('    无法获取方法列表: ' + e);
            }
            
            console.log('    调用堆栈: \n    ' + getStackShort());
            return this.addJavascriptInterface(object, name);
        };
    } catch (e) {
        console.log("[-] JavaScript接口监控失败: " + e);
    }
    
    //===== 监控WebSettings =====
    try {
        var WebSettings = Java.use('android.webkit.WebSettings');
        
        // 监控JavaScript启用状态
        WebSettings.setJavaScriptEnabled.implementation = function (flag) {
            console.log('[*] WebSettings.setJavaScriptEnabled: ' + flag);
            if (flag) {
                console.log('    [!] 注意: JavaScript已启用');
                console.log('    调用堆栈: \n    ' + getStackShort());
            }
            return this.setJavaScriptEnabled(flag);
        };
        
        // 监控文件访问权限
        WebSettings.setAllowFileAccess.implementation = function (flag) {
            console.log('[*] WebSettings.setAllowFileAccess: ' + flag);
            if (flag) {
                console.log('    [!] 警告: 允许WebView访问文件系统');
                console.log('    调用堆栈: \n    ' + getStackShort());
            }
            return this.setAllowFileAccess(flag);
        };
        
        // 监控文件URL访问权限
        if (WebSettings.setAllowFileAccessFromFileURLs) {
            WebSettings.setAllowFileAccessFromFileURLs.implementation = function (flag) {
                console.log('[*] WebSettings.setAllowFileAccessFromFileURLs: ' + flag);
                if (flag) {
                    console.log('    [!] 严重警告: 允许通过file://协议访问其他文件');
                    console.log('    调用堆栈: \n    ' + getStackShort());
                }
                return this.setAllowFileAccessFromFileURLs(flag);
            };
        }
        
        // 监控通用URL访问权限
        if (WebSettings.setAllowUniversalAccessFromFileURLs) {
            WebSettings.setAllowUniversalAccessFromFileURLs.implementation = function (flag) {
                console.log('[*] WebSettings.setAllowUniversalAccessFromFileURLs: ' + flag);
                if (flag) {
                    console.log('    [!] 严重警告: 允许file://协议访问任何源');
                    console.log('    调用堆栈: \n    ' + getStackShort());
                }
                return this.setAllowUniversalAccessFromFileURLs(flag);
            };
        }
    } catch (e) {
        console.log("[-] WebSettings监控失败: " + e);
    }
    
    console.log("[*] WebView监控已启动");
    console.log("[*] 监控范围: loadUrl, loadData, WebViewClient, JavaScript接口, 安全设置");
}); 