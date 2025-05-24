/**
 * WebView注入脚本
 * 
 * 功能：向Android应用中的WebView注入JavaScript代码
 * 作用：监控和修改WebView中的网页内容，拦截JavaScript调用，分析混合应用
 * 适用：分析混合开发应用，WebView安全测试，JavaScript接口分析
 */

// 等待Java虚拟机加载完成
Java.perform(function() {
    console.log("[*] WebView注入脚本已启动");

    /**
     * 工具函数：获取调用堆栈
     */
    function getStackTrace() {
        var Exception = Java.use("java.lang.Exception");
        var exception = Exception.$new();
        var stackTrace = exception.getStackTrace();
        exception.$dispose();
        
        var stack = [];
        for (var i = 0; i < stackTrace.length; i++) {
            var element = stackTrace[i];
            var className = element.getClassName();
            var methodName = element.getMethodName();
            var fileName = element.getFileName();
            var lineNumber = element.getLineNumber();
            
            // 过滤掉Frida相关的堆栈
            if (className.indexOf("com.frida") === -1) {
                stack.push(className + "." + methodName + "(" + fileName + ":" + lineNumber + ")");
            }
            
            // 只获取前10个堆栈元素
            if (stack.length >= 10) break;
        }
        
        return stack.join("\n    ");
    }

    /**
     * 一、拦截WebView创建和加载
     */
    var WebView = Java.use("android.webkit.WebView");
    
    // 拦截构造函数
    WebView.$init.overload("android.content.Context").implementation = function(context) {
        console.log("\n[+] WebView创建");
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        // 调用原始构造函数
        var webView = this.$init(context);
        return webView;
    };
    
    // 拦截loadUrl方法
    WebView.loadUrl.overload("java.lang.String").implementation = function(url) {
        console.log("\n[+] WebView.loadUrl: " + url);
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        // 调用原始方法
        return this.loadUrl(url);
    };
    
    // 拦截loadData方法
    WebView.loadData.implementation = function(data, mimeType, encoding) {
        console.log("\n[+] WebView.loadData");
        console.log("    MIME类型: " + mimeType);
        console.log("    编码: " + encoding);
        console.log("    数据: " + data.substring(0, Math.min(data.length, 1000)) + (data.length > 1000 ? "..." : ""));
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        // 调用原始方法
        return this.loadData(data, mimeType, encoding);
    };
    
    // 拦截loadDataWithBaseURL方法
    WebView.loadDataWithBaseURL.implementation = function(baseUrl, data, mimeType, encoding, historyUrl) {
        console.log("\n[+] WebView.loadDataWithBaseURL");
        console.log("    基础URL: " + baseUrl);
        console.log("    历史URL: " + historyUrl);
        console.log("    MIME类型: " + mimeType);
        console.log("    编码: " + encoding);
        console.log("    数据: " + data.substring(0, Math.min(data.length, 1000)) + (data.length > 1000 ? "..." : ""));
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        // 调用原始方法
        return this.loadDataWithBaseURL(baseUrl, data, mimeType, encoding, historyUrl);
    };

    /**
     * 二、拦截WebView设置
     */
    
    // 拦截setJavaScriptEnabled方法
    var WebSettings = Java.use("android.webkit.WebSettings");
    WebSettings.setJavaScriptEnabled.implementation = function(flag) {
        console.log("\n[+] WebView.setJavaScriptEnabled: " + flag);
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        // 调用原始方法
        return this.setJavaScriptEnabled(flag);
    };
    
    // 拦截setAllowFileAccess方法
    WebSettings.setAllowFileAccess.implementation = function(flag) {
        console.log("\n[+] WebView.setAllowFileAccess: " + flag);
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        // 调用原始方法
        return this.setAllowFileAccess(flag);
    };
    
    // 拦截setAllowContentAccess方法
    WebSettings.setAllowContentAccess.implementation = function(flag) {
        console.log("\n[+] WebView.setAllowContentAccess: " + flag);
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        // 调用原始方法
        return this.setAllowContentAccess(flag);
    };
    
    // 拦截setAllowFileAccessFromFileURLs方法
    WebSettings.setAllowFileAccessFromFileURLs.implementation = function(flag) {
        console.log("\n[+] WebView.setAllowFileAccessFromFileURLs: " + flag);
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        // 调用原始方法
        return this.setAllowFileAccessFromFileURLs(flag);
    };
    
    // 拦截setAllowUniversalAccessFromFileURLs方法
    WebSettings.setAllowUniversalAccessFromFileURLs.implementation = function(flag) {
        console.log("\n[+] WebView.setAllowUniversalAccessFromFileURLs: " + flag);
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        // 调用原始方法
        return this.setAllowUniversalAccessFromFileURLs(flag);
    };

    /**
     * 三、拦截JavaScript接口
     */
    
    // 拦截addJavascriptInterface方法
    WebView.addJavascriptInterface.implementation = function(obj, name) {
        console.log("\n[+] WebView.addJavascriptInterface");
        console.log("    接口名称: " + name);
        console.log("    接口对象: " + obj.getClass().getName());
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        // 打印接口方法
        try {
            var methods = obj.getClass().getDeclaredMethods();
            console.log("    接口方法:");
            for (var i = 0; i < methods.length; i++) {
                var method = methods[i];
                console.log("      - " + method.getName());
            }
        } catch (e) {
            console.log("    无法获取接口方法: " + e);
        }
        
        // 调用原始方法
        return this.addJavascriptInterface(obj, name);
    };
    
    // 拦截evaluateJavascript方法
    WebView.evaluateJavascript.implementation = function(script, resultCallback) {
        console.log("\n[+] WebView.evaluateJavascript");
        console.log("    脚本: " + script);
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        // 调用原始方法
        return this.evaluateJavascript(script, resultCallback);
    };

    /**
     * 四、拦截WebViewClient
     */
    var WebViewClient = Java.use("android.webkit.WebViewClient");
    
    // 拦截shouldOverrideUrlLoading方法
    WebViewClient.shouldOverrideUrlLoading.overload("android.webkit.WebView", "java.lang.String").implementation = function(webView, url) {
        console.log("\n[+] WebViewClient.shouldOverrideUrlLoading");
        console.log("    URL: " + url);
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        // 调用原始方法
        return this.shouldOverrideUrlLoading(webView, url);
    };
    
    // 拦截onPageStarted方法
    WebViewClient.onPageStarted.implementation = function(webView, url, favicon) {
        console.log("\n[+] WebViewClient.onPageStarted");
        console.log("    URL: " + url);
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        // 调用原始方法
        this.onPageStarted(webView, url, favicon);
        
        // 在页面加载时注入JavaScript代码
        setTimeout(function() {
            // 注入JavaScript监控代码
            var injectionCode = `
            (function() {
                // 保存原始的XMLHttpRequest
                var originalXHR = window.XMLHttpRequest;
                
                // 创建新的XMLHttpRequest构造函数
                window.XMLHttpRequest = function() {
                    var xhr = new originalXHR();
                    
                    // 保存原始的open方法
                    var originalOpen = xhr.open;
                    
                    // 替换open方法
                    xhr.open = function(method, url) {
                        console.log('[XHR] Open: ' + method + ' ' + url);
                        return originalOpen.apply(this, arguments);
                    };
                    
                    // 保存原始的send方法
                    var originalSend = xhr.send;
                    
                    // 替换send方法
                    xhr.send = function(data) {
                        console.log('[XHR] Send: ' + (data ? data : ''));
                        return originalSend.apply(this, arguments);
                    };
                    
                    // 监听readystatechange事件
                    xhr.addEventListener('readystatechange', function() {
                        if (xhr.readyState === 4) {
                            console.log('[XHR] Response: ' + xhr.responseText.substring(0, 1000));
                        }
                    });
                    
                    return xhr;
                };
                
                // 监控fetch API
                var originalFetch = window.fetch;
                window.fetch = function() {
                    console.log('[Fetch] Request: ' + arguments[0]);
                    return originalFetch.apply(this, arguments).then(function(response) {
                        console.log('[Fetch] Response status: ' + response.status);
                        return response;
                    });
                };
                
                // 监控localStorage
                var originalSetItem = Storage.prototype.setItem;
                Storage.prototype.setItem = function(key, value) {
                    console.log('[localStorage] setItem: ' + key + ' = ' + value);
                    return originalSetItem.apply(this, arguments);
                };
                
                var originalGetItem = Storage.prototype.getItem;
                Storage.prototype.getItem = function(key) {
                    var value = originalGetItem.apply(this, arguments);
                    console.log('[localStorage] getItem: ' + key + ' = ' + value);
                    return value;
                };
                
                // 监控sessionStorage
                var originalSessionSetItem = sessionStorage.setItem;
                sessionStorage.setItem = function(key, value) {
                    console.log('[sessionStorage] setItem: ' + key + ' = ' + value);
                    return originalSessionSetItem.apply(this, arguments);
                };
                
                var originalSessionGetItem = sessionStorage.getItem;
                sessionStorage.getItem = function(key) {
                    var value = originalSessionGetItem.apply(this, arguments);
                    console.log('[sessionStorage] getItem: ' + key + ' = ' + value);
                    return value;
                };
                
                // 监控Cookie
                var originalCookie = Object.getOwnPropertyDescriptor(Document.prototype, 'cookie');
                Object.defineProperty(document, 'cookie', {
                    get: function() {
                        var value = originalCookie.get.call(this);
                        console.log('[Cookie] get: ' + value);
                        return value;
                    },
                    set: function(value) {
                        console.log('[Cookie] set: ' + value);
                        return originalCookie.set.call(this, value);
                    }
                });
                
                console.log('[Frida] JavaScript监控代码已注入');
            })();
            `;
            
            webView.evaluateJavascript(injectionCode, null);
            console.log("    [+] 注入JavaScript监控代码");
        }, 1000);
    };
    
    // 拦截onPageFinished方法
    WebViewClient.onPageFinished.implementation = function(webView, url) {
        console.log("\n[+] WebViewClient.onPageFinished");
        console.log("    URL: " + url);
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        // 调用原始方法
        this.onPageFinished(webView, url);
        
        // 页面加载完成后注入JavaScript代码
        var dumpDOMCode = `
        (function() {
            // 获取DOM结构
            var domInfo = {
                title: document.title,
                url: window.location.href,
                forms: []
            };
            
            // 获取表单信息
            var forms = document.forms;
            for (var i = 0; i < forms.length; i++) {
                var form = forms[i];
                var formInfo = {
                    id: form.id,
                    name: form.name,
                    method: form.method,
                    action: form.action,
                    elements: []
                };
                
                for (var j = 0; j < form.elements.length; j++) {
                    var element = form.elements[j];
                    formInfo.elements.push({
                        name: element.name,
                        id: element.id,
                        type: element.type,
                        value: element.value
                    });
                }
                
                domInfo.forms.push(formInfo);
            }
            
            // 获取所有链接
            var links = document.links;
            var linkInfo = [];
            for (var i = 0; i < links.length; i++) {
                linkInfo.push({
                    href: links[i].href,
                    text: links[i].text
                });
            }
            domInfo.links = linkInfo;
            
            console.log('[DOM] 页面信息: ' + JSON.stringify(domInfo));
            return JSON.stringify(domInfo);
        })();
        `;
        
        webView.evaluateJavascript(dumpDOMCode, new android.webkit.ValueCallback({
            onReceiveValue: function(value) {
                console.log("    [+] 页面DOM信息: " + value);
            }
        }));
        
        console.log("    [+] 注入DOM信息获取代码");
    };
    
    // 拦截onReceivedSslError方法
    WebViewClient.onReceivedSslError.implementation = function(webView, sslErrorHandler, sslError) {
        console.log("\n[+] WebViewClient.onReceivedSslError");
        console.log("    SSL错误: " + sslError.toString());
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        // 默认处理是取消加载，这里我们可以选择继续加载
        console.log("    [!] 忽略SSL错误，继续加载");
        sslErrorHandler.proceed();
    };

    /**
     * 五、拦截WebChromeClient
     */
    var WebChromeClient = Java.use("android.webkit.WebChromeClient");
    
    // 拦截onJsAlert方法
    WebChromeClient.onJsAlert.implementation = function(webView, url, message, result) {
        console.log("\n[+] WebChromeClient.onJsAlert");
        console.log("    URL: " + url);
        console.log("    消息: " + message);
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        // 调用原始方法
        return this.onJsAlert(webView, url, message, result);
    };
    
    // 拦截onJsConfirm方法
    WebChromeClient.onJsConfirm.implementation = function(webView, url, message, result) {
        console.log("\n[+] WebChromeClient.onJsConfirm");
        console.log("    URL: " + url);
        console.log("    消息: " + message);
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        // 调用原始方法
        return this.onJsConfirm(webView, url, message, result);
    };
    
    // 拦截onJsPrompt方法
    WebChromeClient.onJsPrompt.implementation = function(webView, url, message, defaultValue, result) {
        console.log("\n[+] WebChromeClient.onJsPrompt");
        console.log("    URL: " + url);
        console.log("    消息: " + message);
        console.log("    默认值: " + defaultValue);
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        // 调用原始方法
        return this.onJsPrompt(webView, url, message, defaultValue, result);
    };
    
    // 拦截onConsoleMessage方法
    WebChromeClient.onConsoleMessage.overload("android.webkit.ConsoleMessage").implementation = function(consoleMessage) {
        console.log("\n[+] WebChromeClient.onConsoleMessage");
        console.log("    消息: " + consoleMessage.message());
        console.log("    来源: " + consoleMessage.sourceId() + ":" + consoleMessage.lineNumber());
        console.log("    级别: " + consoleMessage.messageLevel());
        
        // 调用原始方法
        return this.onConsoleMessage(consoleMessage);
    };

    console.log("[*] WebView注入设置完成");
}); 