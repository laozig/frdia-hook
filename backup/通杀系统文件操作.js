/*
 * 脚本名称：通杀系统文件操作.js
 * 功能：自动监控open/read/write/close等系统文件操作，辅助分析文件读写、数据落盘
 * 适用场景：文件加密、数据落盘、反检测、so逆向
 * 使用方法：
 *   1. frida -U -f 包名 -l 通杀系统文件操作.js --no-pause
 *   2. 查看控制台输出，获取文件操作信息
 * 启动方式说明：
 *   - -U 代表使用USB连接的设备
 *   - -f 代表以spawn方式启动目标应用（推荐，可以捕获启动阶段的文件操作）
 *   - --no-pause 指示Frida不要暂停应用执行，保证App正常运行
 *   - 也可使用 -F 以attach方式附加到已运行的进程
 * 参数说明：
 *   - 包名：目标应用的包名，如com.example.app
 * 监控函数说明：
 *   - open(): 打开或创建文件，返回文件描述符
 *   - read(): 从文件描述符读取数据
 *   - write(): 向文件描述符写入数据
 *   - close(): 关闭文件描述符
 *   - fopen(): C标准库打开文件，返回FILE指针
 *   - fread(): 从FILE指针读取数据
 *   - fwrite(): 向FILE指针写入数据
 *   - fclose(): 关闭FILE指针
 * 函数参数与返回值详解：
 *   - open(const char *pathname, int flags, mode_t mode):
 *     - pathname: 文件路径
 *     - flags: 打开模式(O_RDONLY=只读, O_WRONLY=只写, O_RDWR=读写, O_CREAT=不存在则创建)
 *     - mode: 创建文件时的权限(0666表示可读写)
 *     - 返回: >=0表示文件描述符，-1表示错误
 *   - read(int fd, void *buf, size_t count):
 *     - fd: 文件描述符
 *     - buf: 存储读取数据的缓冲区
 *     - count: 请求读取的字节数
 *     - 返回: 实际读取的字节数，0表示EOF，-1表示错误
 *   - write(int fd, const void *buf, size_t count):
 *     - fd: 文件描述符
 *     - buf: 要写入的数据缓冲区
 *     - count: 要写入的字节数
 *     - 返回: 实际写入的字节数，-1表示错误
 * 实际应用场景：
 *   - 监控应用数据存储和加载过程
 *   - 捕获应用配置文件的读写操作
 *   - 分析敏感数据的本地存储方式
 *   - 发现隐藏文件或临时文件的使用
 *   - 跟踪SO库的加载和动态链接过程
 * 注意事项：
 *   - 某些加固应用需配合反检测脚本
 *   - 系统会产生大量文件操作，建议添加过滤条件减少输出
 *   - 在高IO场景下可能会显著影响应用性能
 *   - 应用可能使用mmap等内存映射方式操作文件，不会触发这些函数
 */

// 通杀系统文件操作
// 定义要监控的函数列表，包括低级文件描述符API和高级FILE*流API
['open', 'read', 'write', 'close', 'fopen', 'fread', 'fwrite', 'fclose'].forEach(function (func) {
    try {
        // 在libc.so库中查找导出的目标函数地址
        // libc.so是C标准库，包含了文件操作的核心函数
        var addr = Module.findExportByName('libc.so', func);
        if (addr) {
            // 如果找到函数地址，则附加拦截器
            Interceptor.attach(addr, {
                // 在函数调用前执行的回调
                onEnter: function (args) {
                    // this.path用于保存文件路径，以便在onLeave中使用
                    this.path = null;
                    
                    // 根据不同函数进行不同处理
                    if (func === 'open') {
                        // 读取第一个参数：文件路径
                        var path = Memory.readUtf8String(args[0]);
                        var flags = args[1].toInt32();
                        
                        // 保存路径以便在onLeave中使用
                        this.path = path;
                        
                        // 解析打开模式标志
                        var flagsDesc = [];
                        if (flags & 0x0000) flagsDesc.push("O_RDONLY(只读)");
                        if (flags & 0x0001) flagsDesc.push("O_WRONLY(只写)");
                        if (flags & 0x0002) flagsDesc.push("O_RDWR(读写)");
                        if (flags & 0x0040) flagsDesc.push("O_CREAT(创建)");
                        if (flags & 0x0200) flagsDesc.push("O_TRUNC(清空)");
                        if (flags & 0x0400) flagsDesc.push("O_APPEND(追加)");
                        
                        console.log('[*] open 调用:');
                        console.log('    路径: ' + path);
                        console.log('    模式: 0x' + flags.toString(16) + ' (' + flagsDesc.join('|') + ')');
                    }
                    else if (func === 'read') {
                        // 读取参数：文件描述符、缓冲区、长度
                        var fd = args[0].toInt32();
                        var bufPtr = args[1];
                        var count = args[2].toInt32();
                        
                        // 保存参数以便在onLeave中使用
                        this.fd = fd;
                        this.bufPtr = bufPtr;
                        this.count = count;
                        
                        console.log('[*] read 调用:');
                        console.log('    文件描述符: ' + fd);
                        console.log('    请求读取: ' + count + ' 字节');
                    }
                    else if (func === 'write') {
                        // 读取参数：文件描述符、缓冲区、长度
                        var fd = args[0].toInt32();
                        var bufPtr = args[1];
                        var count = args[2].toInt32();
                        
                        // 尝试读取缓冲区内容(最多显示128字节)
                        var preview = "";
                        try {
                            var bytes = Memory.readByteArray(bufPtr, Math.min(count, 128));
                            
                            // 创建十六进制表示
                            var hex = '';
                            var displayable = true;
                            for (var i = 0; i < bytes.byteLength; i++) {
                                if (bytes[i] < 32 || bytes[i] > 126) {
                                    displayable = false;
                                }
                                var b = bytes[i].toString(16);
                                if (b.length == 1) hex += '0';
                                hex += b;
                                if (i < 16) hex += ' '; // 仅显示前16个字节的空格分隔
                            }
                            
                            if (displayable) {
                                var str = Memory.readUtf8String(bufPtr, Math.min(count, 128));
                                preview = "文本: " + str + (count > 128 ? "..." : "");
                            } else {
                                preview = "HEX: " + hex + (count > 16 ? "..." : "");
                            }
                        } catch (e) {
                            preview = "<无法读取数据>";
                        }
                        
                        console.log('[*] write 调用:');
                        console.log('    文件描述符: ' + fd);
                        console.log('    写入数据: ' + preview);
                        console.log('    写入长度: ' + count + ' 字节');
                    }
                    else if (func === 'close') {
                        // 读取参数：文件描述符
                        var fd = args[0].toInt32();
                        
                        console.log('[*] close 调用:');
                        console.log('    文件描述符: ' + fd);
                    }
                    else if (func === 'fopen') {
                        // 读取参数：文件路径、模式
                        var path = Memory.readUtf8String(args[0]);
                        var mode = Memory.readUtf8String(args[1]);
                        
                        // 保存路径以便在onLeave中使用
                        this.path = path;
                        
                        console.log('[*] fopen 调用:');
                        console.log('    路径: ' + path);
                        console.log('    模式: ' + mode);
                        console.log('    模式说明:');
                        console.log('      r: 只读');
                        console.log('      w: 只写，不存在则创建，存在则清空');
                        console.log('      a: 追加，不存在则创建');
                        console.log('      r+: 读写，文件必须存在');
                        console.log('      w+: 读写，不存在则创建，存在则清空');
                        console.log('      a+: 读写，不存在则创建，写入追加到末尾');
                    }
                    else if (func === 'fread' || func === 'fwrite') {
                        // 读取参数：元素大小、元素个数、文件指针
                        var size = args[0].toInt32();
                        var nmemb = args[1].toInt32();
                        var stream = args[2];
                        
                        console.log('[*] ' + func + ' 调用:');
                        console.log('    元素大小: ' + size + ' 字节');
                        console.log('    元素个数: ' + nmemb);
                        console.log('    总字节数: ' + (size * nmemb));
                        console.log('    文件指针: ' + stream);
                    }
                    else if (func === 'fclose') {
                        // 读取参数：文件指针
                        var stream = args[0];
                        
                        console.log('[*] fclose 调用:');
                        console.log('    文件指针: ' + stream);
                    }
                    else {
                        // 通用参数输出
                        console.log('[*] ' + func + ' 调用, 参数: ' + args[0]);
                    }
                    
                    // 在特定场景下打印调用堆栈
                    // 例如，针对特定文件操作或敏感路径
                    if (this.path && (this.path.indexOf("/data/data/") >= 0 || this.path.indexOf("/sdcard/") >= 0)) {
                        console.log('    调用堆栈: ');
                        console.log('    ' + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n    '));
                    }
                },
                
                // 在函数返回时执行的回调
                onLeave: function (retval) {
                    var result = retval.toInt32();
                    
                    if (func === 'open') {
                        if (result >= 0) {
                            console.log('[*] open 成功: 文件描述符=' + result);
                            // 可以在此维护一个文件描述符到路径的映射表
                        } else {
                            console.log('[*] open 失败: 错误码=' + (-result));
                        }
                    }
                    else if (func === 'read') {
                        if (result > 0) {
                            // 尝试读取实际读取的数据内容
                            var preview = "";
                            try {
                                var bytes = Memory.readByteArray(this.bufPtr, Math.min(result, 128));
                                
                                // 创建十六进制表示
                                var hex = '';
                                var displayable = true;
                                for (var i = 0; i < bytes.byteLength; i++) {
                                    if (bytes[i] < 32 || bytes[i] > 126) {
                                        displayable = false;
                                    }
                                    var b = bytes[i].toString(16);
                                    if (b.length == 1) hex += '0';
                                    hex += b;
                                    if (i < 16) hex += ' ';
                                }
                                
                                if (displayable) {
                                    var str = Memory.readUtf8String(this.bufPtr, Math.min(result, 128));
                                    preview = "文本: " + str + (result > 128 ? "..." : "");
                                } else {
                                    preview = "HEX: " + hex + (result > 16 ? "..." : "");
                                }
                            } catch (e) {
                                preview = "<无法读取数据>";
                            }
                            
                            console.log('[*] read 成功: 读取 ' + result + ' 字节');
                            console.log('    数据: ' + preview);
                        } else if (result === 0) {
                            console.log('[*] read 到达文件末尾(EOF)');
                        } else {
                            console.log('[*] read 失败: 错误码=' + (-result));
                        }
                    }
                    else if (func === 'write') {
                        if (result >= 0) {
                            console.log('[*] write 成功: 写入 ' + result + ' 字节');
                        } else {
                            console.log('[*] write 失败: 错误码=' + (-result));
                        }
                    }
                    else if (func === 'fopen') {
                        if (!result.isNull()) {
                            console.log('[*] fopen 成功: 文件指针=' + result);
                        } else {
                            console.log('[*] fopen 失败: NULL');
                        }
                    }
                    else if (func === 'fread' || func === 'fwrite') {
                        console.log('[*] ' + func + ' 返回: 操作元素数=' + result);
                    }
                    else {
                        // 其他函数通用处理
                        console.log('[*] ' + func + ' 返回: ' + result);
                    }
                }
            });
            
            console.log('[+] 成功Hook ' + func + ' 函数');
        }
    } catch (e) {
        console.log('[-] Hook ' + func + ' 时发生错误: ' + e);
    }
});

console.log("[*] 文件操作监控已启动");

// 注：更完整的实现应该还包括：
// 1. 维护文件描述符到路径的映射表，以便于跟踪文件操作
// 2. 监控mmap等内存映射函数
// 3. 监控rename, unlink等文件管理函数
// 4. 监控目录操作如opendir, readdir
// 5. 过滤机制，如忽略特定目录或只关注特定文件类型
// 6. 监控Java层的文件操作API如File, FileInputStream等 