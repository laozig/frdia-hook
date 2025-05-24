/**
 * 界面元素监控脚本
 * 
 * 功能：监控和修改Android应用中的UI元素
 * 作用：分析应用界面结构，监控用户交互，修改UI元素属性
 * 适用：UI分析，界面操作自动化，界面安全测试
 */

// 等待Java虚拟机加载完成
Java.perform(function() {
    console.log("[*] 界面元素监控脚本已启动");

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
     * 工具函数：获取View的详细信息
     */
    function getViewInfo(view) {
        if (!view) return "null";
        
        try {
            var result = {
                "class": view.getClass().getName(),
                "id": "unknown"
            };
            
            // 获取View ID
            try {
                var id = view.getId();
                if (id !== -1) {
                    var context = view.getContext();
                    var resources = context.getResources();
                    result.id = resources.getResourceEntryName(id);
                }
            } catch (e) {
                result.id = "id: " + view.getId();
            }
            
            // 获取View文本（如果有）
            try {
                if (view.getText) {
                    var text = view.getText();
                    if (text) {
                        result.text = text.toString();
                    }
                }
            } catch (e) {}
            
            // 获取View提示文本（如果有）
            try {
                if (view.getHint) {
                    var hint = view.getHint();
                    if (hint) {
                        result.hint = hint.toString();
                    }
                }
            } catch (e) {}
            
            // 获取View标签（如果有）
            try {
                if (view.getTag) {
                    var tag = view.getTag();
                    if (tag) {
                        result.tag = tag.toString();
                    }
                }
            } catch (e) {}
            
            // 获取View可见性
            try {
                var visibility = view.getVisibility();
                result.visibility = visibility === 0 ? "VISIBLE" : visibility === 4 ? "INVISIBLE" : "GONE";
            } catch (e) {}
            
            // 获取View是否可点击
            try {
                result.clickable = view.isClickable();
            } catch (e) {}
            
            // 获取View是否可长按
            try {
                result.longClickable = view.isLongClickable();
            } catch (e) {}
            
            // 获取View是否可用
            try {
                result.enabled = view.isEnabled();
            } catch (e) {}
            
            // 获取View是否获取焦点
            try {
                result.focused = view.isFocused();
            } catch (e) {}
            
            return result;
        } catch (e) {
            return "获取View信息失败: " + e;
        }
    }

    /**
     * 工具函数：递归获取View层次结构
     */
    function dumpViewHierarchy(view, depth) {
        if (!view) return "";
        
        depth = depth || 0;
        var indent = "";
        for (var i = 0; i < depth; i++) indent += "  ";
        
        var result = indent + JSON.stringify(getViewInfo(view)) + "\n";
        
        try {
            if (view.getChildCount) {
                var childCount = view.getChildCount();
                for (var i = 0; i < childCount; i++) {
                    var child = view.getChildAt(i);
                    result += dumpViewHierarchy(child, depth + 1);
                }
            }
        } catch (e) {
            result += indent + "  获取子视图失败: " + e + "\n";
        }
        
        return result;
    }

    /**
     * 一、拦截Activity生命周期
     */
    var Activity = Java.use("android.app.Activity");
    
    // 拦截onCreate方法
    Activity.onCreate.overload("android.os.Bundle").implementation = function(bundle) {
        console.log("\n[+] Activity.onCreate: " + this.getClass().getName());
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        // 调用原始方法
        this.onCreate(bundle);
        
        // 延迟一段时间后获取界面结构，确保界面已经加载完成
        var activity = this;
        setTimeout(function() {
            try {
                var decorView = activity.getWindow().getDecorView();
                console.log("\n[+] Activity界面结构: " + activity.getClass().getName());
                console.log(dumpViewHierarchy(decorView));
            } catch (e) {
                console.log("    获取界面结构失败: " + e);
            }
        }, 1000);
    };
    
    // 拦截onResume方法
    Activity.onResume.implementation = function() {
        console.log("\n[+] Activity.onResume: " + this.getClass().getName());
        
        // 调用原始方法
        this.onResume();
        
        // 获取当前Activity的标题
        try {
            var title = this.getTitle();
            if (title) {
                console.log("    标题: " + title.toString());
            }
        } catch (e) {}
    };

    /**
     * 二、拦截View点击事件
     */
    var View = Java.use("android.view.View");
    
    // 拦截setOnClickListener方法
    View.setOnClickListener.implementation = function(listener) {
        var viewInfo = getViewInfo(this);
        console.log("\n[+] View.setOnClickListener");
        console.log("    View信息: " + JSON.stringify(viewInfo));
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        // 如果原始监听器不为空，我们创建一个代理监听器
        if (listener) {
            var ClickListenerProxy = Java.use("android.view.View$OnClickListener");
            var proxy = ClickListenerProxy.$new({
                onClick: function(v) {
                    console.log("\n[+] View.OnClickListener.onClick");
                    console.log("    View信息: " + JSON.stringify(getViewInfo(v)));
                    console.log("    调用堆栈:\n    " + getStackTrace());
                    
                    // 调用原始监听器
                    listener.onClick(v);
                }
            });
            
            // 调用原始方法，但使用我们的代理监听器
            return this.setOnClickListener(proxy);
        }
        
        // 如果原始监听器为空，直接调用原始方法
        return this.setOnClickListener(listener);
    };
    
    // 拦截setOnLongClickListener方法
    View.setOnLongClickListener.implementation = function(listener) {
        var viewInfo = getViewInfo(this);
        console.log("\n[+] View.setOnLongClickListener");
        console.log("    View信息: " + JSON.stringify(viewInfo));
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        // 如果原始监听器不为空，我们创建一个代理监听器
        if (listener) {
            var LongClickListenerProxy = Java.use("android.view.View$OnLongClickListener");
            var proxy = LongClickListenerProxy.$new({
                onLongClick: function(v) {
                    console.log("\n[+] View.OnLongClickListener.onLongClick");
                    console.log("    View信息: " + JSON.stringify(getViewInfo(v)));
                    console.log("    调用堆栈:\n    " + getStackTrace());
                    
                    // 调用原始监听器
                    return listener.onLongClick(v);
                }
            });
            
            // 调用原始方法，但使用我们的代理监听器
            return this.setOnLongClickListener(proxy);
        }
        
        // 如果原始监听器为空，直接调用原始方法
        return this.setOnLongClickListener(listener);
    };

    /**
     * 三、拦截EditText输入
     */
    var EditText = Java.use("android.widget.EditText");
    
    // 拦截setText方法
    EditText.setText.overload("java.lang.CharSequence").implementation = function(text) {
        var viewInfo = getViewInfo(this);
        console.log("\n[+] EditText.setText");
        console.log("    View信息: " + JSON.stringify(viewInfo));
        console.log("    文本: " + text);
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        // 调用原始方法
        return this.setText(text);
    };
    
    // 拦截addTextChangedListener方法
    EditText.addTextChangedListener.implementation = function(watcher) {
        var viewInfo = getViewInfo(this);
        console.log("\n[+] EditText.addTextChangedListener");
        console.log("    View信息: " + JSON.stringify(viewInfo));
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        // 如果原始监听器不为空，我们创建一个代理监听器
        if (watcher) {
            var TextWatcher = Java.use("android.text.TextWatcher");
            var proxy = Java.registerClass({
                name: "com.frida.TextWatcherProxy",
                implements: [TextWatcher],
                methods: {
                    beforeTextChanged: function(s, start, count, after) {
                        console.log("\n[+] TextWatcher.beforeTextChanged");
                        console.log("    文本: " + s);
                        console.log("    start: " + start + ", count: " + count + ", after: " + after);
                        
                        // 调用原始方法
                        watcher.beforeTextChanged(s, start, count, after);
                    },
                    onTextChanged: function(s, start, before, count) {
                        console.log("\n[+] TextWatcher.onTextChanged");
                        console.log("    文本: " + s);
                        console.log("    start: " + start + ", before: " + before + ", count: " + count);
                        
                        // 调用原始方法
                        watcher.onTextChanged(s, start, before, count);
                    },
                    afterTextChanged: function(s) {
                        console.log("\n[+] TextWatcher.afterTextChanged");
                        console.log("    文本: " + s);
                        
                        // 调用原始方法
                        watcher.afterTextChanged(s);
                    }
                }
            }).$new();
            
            // 调用原始方法，但使用我们的代理监听器
            return this.addTextChangedListener(proxy);
        }
        
        // 如果原始监听器为空，直接调用原始方法
        return this.addTextChangedListener(watcher);
    };

    /**
     * 四、拦截Button操作
     */
    var Button = Java.use("android.widget.Button");
    
    // 拦截Button构造函数
    Button.$init.overload("android.content.Context").implementation = function(context) {
        var button = this.$init(context);
        console.log("\n[+] 创建Button");
        console.log("    调用堆栈:\n    " + getStackTrace());
        return button;
    };
    
    // 拦截Button构造函数（带属性）
    Button.$init.overload("android.content.Context", "android.util.AttributeSet").implementation = function(context, attrs) {
        var button = this.$init(context, attrs);
        console.log("\n[+] 创建Button（带属性）");
        console.log("    调用堆栈:\n    " + getStackTrace());
        return button;
    };

    /**
     * 五、拦截Fragment操作
     */
    try {
        var Fragment = Java.use("androidx.fragment.app.Fragment");
        
        // 拦截onCreateView方法
        Fragment.onCreateView.implementation = function(inflater, container, savedInstanceState) {
            console.log("\n[+] Fragment.onCreateView: " + this.getClass().getName());
            console.log("    调用堆栈:\n    " + getStackTrace());
            
            // 调用原始方法
            var view = this.onCreateView(inflater, container, savedInstanceState);
            
            // 延迟一段时间后获取Fragment的视图结构
            if (view) {
                var fragment = this;
                setTimeout(function() {
                    try {
                        console.log("\n[+] Fragment视图结构: " + fragment.getClass().getName());
                        console.log(dumpViewHierarchy(view));
                    } catch (e) {
                        console.log("    获取Fragment视图结构失败: " + e);
                    }
                }, 500);
            }
            
            return view;
        };
        
        console.log("[+] Fragment拦截设置完成");
    } catch (e) {
        console.log("[-] Fragment拦截设置失败: " + e);
        
        // 尝试拦截旧版Fragment
        try {
            var LegacyFragment = Java.use("android.app.Fragment");
            
            // 拦截onCreateView方法
            LegacyFragment.onCreateView.implementation = function(inflater, container, savedInstanceState) {
                console.log("\n[+] Legacy Fragment.onCreateView: " + this.getClass().getName());
                console.log("    调用堆栈:\n    " + getStackTrace());
                
                // 调用原始方法
                var view = this.onCreateView(inflater, container, savedInstanceState);
                
                // 延迟一段时间后获取Fragment的视图结构
                if (view) {
                    var fragment = this;
                    setTimeout(function() {
                        try {
                            console.log("\n[+] Legacy Fragment视图结构: " + fragment.getClass().getName());
                            console.log(dumpViewHierarchy(view));
                        } catch (e) {
                            console.log("    获取Legacy Fragment视图结构失败: " + e);
                        }
                    }, 500);
                }
                
                return view;
            };
            
            console.log("[+] Legacy Fragment拦截设置完成");
        } catch (e) {
            console.log("[-] Legacy Fragment拦截设置失败: " + e);
        }
    }

    /**
     * 六、拦截Dialog操作
     */
    var Dialog = Java.use("android.app.Dialog");
    
    // 拦截show方法
    Dialog.show.implementation = function() {
        console.log("\n[+] Dialog.show: " + this.getClass().getName());
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        // 调用原始方法
        this.show();
        
        // 延迟一段时间后获取Dialog的视图结构
        var dialog = this;
        setTimeout(function() {
            try {
                var decorView = dialog.getWindow().getDecorView();
                console.log("\n[+] Dialog视图结构: " + dialog.getClass().getName());
                console.log(dumpViewHierarchy(decorView));
            } catch (e) {
                console.log("    获取Dialog视图结构失败: " + e);
            }
        }, 500);
    };
    
    // 拦截dismiss方法
    Dialog.dismiss.implementation = function() {
        console.log("\n[+] Dialog.dismiss: " + this.getClass().getName());
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        // 调用原始方法
        this.dismiss();
    };

    /**
     * 七、拦截AlertDialog操作
     */
    try {
        var AlertDialog = Java.use("android.app.AlertDialog$Builder");
        
        // 拦截setTitle方法
        AlertDialog.setTitle.implementation = function(title) {
            console.log("\n[+] AlertDialog.setTitle: " + title);
            console.log("    调用堆栈:\n    " + getStackTrace());
            
            // 调用原始方法
            return this.setTitle(title);
        };
        
        // 拦截setMessage方法
        AlertDialog.setMessage.implementation = function(message) {
            console.log("\n[+] AlertDialog.setMessage: " + message);
            console.log("    调用堆栈:\n    " + getStackTrace());
            
            // 调用原始方法
            return this.setMessage(message);
        };
        
        // 拦截setPositiveButton方法
        AlertDialog.setPositiveButton.overload("java.lang.CharSequence", "android.content.DialogInterface$OnClickListener").implementation = function(text, listener) {
            console.log("\n[+] AlertDialog.setPositiveButton: " + text);
            console.log("    调用堆栈:\n    " + getStackTrace());
            
            // 如果原始监听器不为空，我们创建一个代理监听器
            if (listener) {
                var DialogInterface = Java.use("android.content.DialogInterface");
                var OnClickListener = Java.use("android.content.DialogInterface$OnClickListener");
                
                var proxy = OnClickListener.$new({
                    onClick: function(dialog, which) {
                        console.log("\n[+] AlertDialog.PositiveButton.onClick");
                        console.log("    按钮文本: " + text);
                        console.log("    which: " + which);
                        
                        // 调用原始监听器
                        listener.onClick(dialog, which);
                    }
                });
                
                // 调用原始方法，但使用我们的代理监听器
                return this.setPositiveButton(text, proxy);
            }
            
            // 如果原始监听器为空，直接调用原始方法
            return this.setPositiveButton(text, listener);
        };
        
        // 拦截setNegativeButton方法
        AlertDialog.setNegativeButton.overload("java.lang.CharSequence", "android.content.DialogInterface$OnClickListener").implementation = function(text, listener) {
            console.log("\n[+] AlertDialog.setNegativeButton: " + text);
            console.log("    调用堆栈:\n    " + getStackTrace());
            
            // 如果原始监听器不为空，我们创建一个代理监听器
            if (listener) {
                var DialogInterface = Java.use("android.content.DialogInterface");
                var OnClickListener = Java.use("android.content.DialogInterface$OnClickListener");
                
                var proxy = OnClickListener.$new({
                    onClick: function(dialog, which) {
                        console.log("\n[+] AlertDialog.NegativeButton.onClick");
                        console.log("    按钮文本: " + text);
                        console.log("    which: " + which);
                        
                        // 调用原始监听器
                        listener.onClick(dialog, which);
                    }
                });
                
                // 调用原始方法，但使用我们的代理监听器
                return this.setNegativeButton(text, proxy);
            }
            
            // 如果原始监听器为空，直接调用原始方法
            return this.setNegativeButton(text, listener);
        };
        
        console.log("[+] AlertDialog拦截设置完成");
    } catch (e) {
        console.log("[-] AlertDialog拦截设置失败: " + e);
    }

    /**
     * 八、拦截Toast操作
     */
    var Toast = Java.use("android.widget.Toast");
    
    // 拦截makeText方法
    Toast.makeText.overload("android.content.Context", "java.lang.CharSequence", "int").implementation = function(context, text, duration) {
        console.log("\n[+] Toast.makeText: " + text);
        console.log("    持续时间: " + (duration === 0 ? "SHORT" : "LONG"));
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        // 调用原始方法
        return this.makeText(context, text, duration);
    };
    
    // 拦截show方法
    Toast.show.implementation = function() {
        try {
            var text = this.getText();
            console.log("\n[+] Toast.show: " + text);
        } catch (e) {
            console.log("\n[+] Toast.show");
        }
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        // 调用原始方法
        this.show();
    };

    /**
     * 九、拦截PopupWindow操作
     */
    var PopupWindow = Java.use("android.widget.PopupWindow");
    
    // 拦截showAtLocation方法
    PopupWindow.showAtLocation.implementation = function(parent, gravity, x, y) {
        console.log("\n[+] PopupWindow.showAtLocation");
        console.log("    gravity: " + gravity + ", x: " + x + ", y: " + y);
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        // 调用原始方法
        this.showAtLocation(parent, gravity, x, y);
        
        // 延迟一段时间后获取PopupWindow的视图结构
        var popupWindow = this;
        setTimeout(function() {
            try {
                var contentView = popupWindow.getContentView();
                console.log("\n[+] PopupWindow视图结构:");
                console.log(dumpViewHierarchy(contentView));
            } catch (e) {
                console.log("    获取PopupWindow视图结构失败: " + e);
            }
        }, 500);
    };
    
    // 拦截showAsDropDown方法
    PopupWindow.showAsDropDown.overload("android.view.View").implementation = function(anchor) {
        console.log("\n[+] PopupWindow.showAsDropDown");
        console.log("    锚点View: " + JSON.stringify(getViewInfo(anchor)));
        console.log("    调用堆栈:\n    " + getStackTrace());
        
        // 调用原始方法
        this.showAsDropDown(anchor);
        
        // 延迟一段时间后获取PopupWindow的视图结构
        var popupWindow = this;
        setTimeout(function() {
            try {
                var contentView = popupWindow.getContentView();
                console.log("\n[+] PopupWindow视图结构:");
                console.log(dumpViewHierarchy(contentView));
            } catch (e) {
                console.log("    获取PopupWindow视图结构失败: " + e);
            }
        }, 500);
    };

    console.log("[*] 界面元素监控设置完成");
}); 