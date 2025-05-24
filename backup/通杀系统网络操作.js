/*
 * 脚本名称：通杀系统网络操作.js
 * 功能：自动监控socket/connect/send/recv等系统网络操作，辅助分析网络通信、协议明文
 * 适用场景：网络加密、协议分析、反检测、so逆向
 * 使用方法：
 *   1. frida -U -f 包名 -l 通杀系统网络操作.js --no-pause
 *   2. 查看控制台输出，获取网络操作信息
 * 启动方式说明：
 *   - -U 代表使用USB连接的设备
 *   - -f 代表以spawn方式启动目标应用（推荐，可以捕获启动阶段的网络连接）
 *   - --no-pause 指示Frida不要暂停应用执行，保证App正常运行
 *   - 也可使用 -F 以attach方式附加到已运行的进程
 * 参数说明：
 *   - 包名：目标应用的包名，如com.example.app
 * 监控函数说明：
 *   - socket(): 创建套接字，返回套接字描述符
 *   - connect(): 建立与远程服务器的连接
 *   - send()/recv(): 通过套接字发送/接收数据
 *   - sendto()/recvfrom(): 用于UDP协议的数据发送/接收
 * 函数参数与返回值详解：
 *   - socket(int domain, int type, int protocol): 
 *     - domain: 协议族(AF_INET=IPv4, AF_INET6=IPv6)
 *     - type: 套接字类型(SOCK_STREAM=TCP, SOCK_DGRAM=UDP)
 *     - protocol: 协议(通常为0)
 *     - 返回: 套接字文件描述符或-1(错误)
 *   - connect(int sockfd, struct sockaddr *addr, socklen_t addrlen):
 *     - sockfd: 套接字描述符
 *     - addr: 包含目标地址和端口的结构体
 *     - addrlen: addr结构体的长度
 *     - 返回: 0(成功)或-1(错误)
 *   - send(int sockfd, const void *buf, size_t len, int flags):
 *     - sockfd: 套接字描述符
 *     - buf: 待发送数据的缓冲区
 *     - len: 要发送的字节数
 *     - flags: 标志位(通常为0)
 *     - 返回: 实际发送的字节数或-1(错误)
 * 实际应用场景：
 *   - 分析应用的网络通信协议
 *   - 拦截未加密的敏感数据传输
 *   - 调试网络相关问题
 *   - 检测隐蔽的网络连接和数据传输
 * 注意事项：
 *   - 某些加固应用需配合反检测脚本
 *   - HTTPS/TLS加密的数据在socket层是加密的，需结合SSL hook才能查看明文
 *   - 大量网络操作会产生大量日志，建议针对特定IP或端口进行过滤
 *   - 应用可能使用自定义网络库或NDK实现网络功能
 */

// 通杀系统网络操作
// 创建辅助函数，将数据格式化为可读形式
function formatBuffer(buffer, length) {
    // 尝试显示为字符串和十六进制格式
    try {
        // 复制内存数据到JavaScript可操作的缓冲区
        var bytes = Memory.readByteArray(buffer, length);
        
        // 创建十六进制表示
        var hex = '';
        for (var i = 0; i < Math.min(bytes.byteLength, 32); i++) {
            var b = bytes[i].toString(16);
            if (b.length == 1) hex += '0';
            hex += b;
            if ((i + 1) % 4 === 0) hex += ' ';
        }
        if (bytes.byteLength > 32) hex += '...';
        
        // 尝试创建UTF-8字符串表示，仅显示可打印字符
        var str = '';
        var isPrintable = true;
        for (var i = 0; i < Math.min(bytes.byteLength, 32); i++) {
            if (bytes[i] >= 32 && bytes[i] <= 126) {
                str += String.fromCharCode(bytes[i]);
            } else {
                isPrintable = false;
                break;
            }
        }
        if (bytes.byteLength > 32) str += '...';
        
        return {
            hex: hex,
            string: isPrintable ? str : '<二进制数据>',
            length: bytes.byteLength
        };
    } catch (e) {
        return { hex: '<无法读取>', string: '<无法读取>', length: length };
    }
}

// 将IP地址结构体转换为可读字符串
function formatSockaddr(sockaddr) {
    try {
        // 读取协议族(family)
        var family = Memory.readU16(sockaddr);
        
        // 如果是IPv4地址(AF_INET = 2)
        if (family === 2) {
            // 端口：大端序存储，需要交换字节顺序
            var port = ((Memory.readU8(sockaddr.add(2)) << 8) | Memory.readU8(sockaddr.add(3)));
            
            // IP地址：读取4个字节
            var ip = Memory.readU8(sockaddr.add(4)) + "." +
                     Memory.readU8(sockaddr.add(5)) + "." +
                     Memory.readU8(sockaddr.add(6)) + "." +
                     Memory.readU8(sockaddr.add(7));
                     
            return ip + ":" + port;
        }
        // IPv6地址(AF_INET6 = 10)处理可以类似实现
        
        return "<未知地址格式>";
    } catch (e) {
        return "<解析地址失败>";
    }
}

// 创建套接字类型与协议族映射
var socketTypes = {
    1: "SOCK_STREAM (TCP)",
    2: "SOCK_DGRAM (UDP)",
    3: "SOCK_RAW"
};

var socketFamilies = {
    2: "AF_INET (IPv4)",
    10: "AF_INET6 (IPv6)",
    1: "AF_UNIX (本地)"
};

// Hook网络相关系统调用
['socket', 'connect', 'send', 'recv', 'sendto', 'recvfrom'].forEach(function (func) {
    try {
        // 在libc.so库中查找目标函数
        var addr = Module.findExportByName('libc.so', func);
        if (addr) {
            Interceptor.attach(addr, {
                onEnter: function (args) {
                    // 保存参数以在onLeave中使用
                    this.args = args;
                    
                    // 根据不同函数进行不同处理
                    if (func === 'socket') {
                        // 解析并记录socket调用参数
                        var domain = args[0].toInt32();
                        var type = args[1].toInt32();
                        var protocol = args[2].toInt32();
                        
                        console.log('[*] socket 调用:');
                        console.log('    协议族: ' + (socketFamilies[domain] || domain));
                        console.log('    套接字类型: ' + (socketTypes[type & 0xFF] || type));
                        console.log('    协议: ' + protocol);
                    }
                    else if (func === 'connect') {
                        // 解析并记录connect调用参数
                        var sockfd = args[0].toInt32();
                        var addr = args[1];
                        var addrlen = args[2].toUInt32();
                        
                        console.log('[*] connect 调用:');
                        console.log('    套接字: ' + sockfd);
                        console.log('    目标地址: ' + formatSockaddr(addr));
                    }
                    else if (func === 'send') {
                        // 解析并记录send调用参数
                        var sockfd = args[0].toInt32();
                        var buf = args[1];
                        var len = args[2].toUInt32();
                        var flags = args[3].toInt32();
                        
                        var data = formatBuffer(buf, len);
                        
                        console.log('[*] send 调用:');
                        console.log('    套接字: ' + sockfd);
                        console.log('    数据长度: ' + data.length + ' 字节');
                        console.log('    数据(HEX): ' + data.hex);
                        console.log('    数据(STR): ' + data.string);
                        console.log('    标志位: ' + flags);
                    }
                    else if (func === 'recv') {
                        // 记录接收数据的初始信息
                        var sockfd = args[0].toInt32();
                        var bufPtr = args[1];
                        var len = args[2].toUInt32();
                        var flags = args[3].toInt32();
                        
                        this.sockfd = sockfd;
                        this.bufPtr = bufPtr;
                        
                        console.log('[*] recv 调用:');
                        console.log('    套接字: ' + sockfd);
                        console.log('    请求接收最大: ' + len + ' 字节');
                        console.log('    标志位: ' + flags);
                    }
                    else if (func === 'sendto' || func === 'recvfrom') {
                        // UDP发送和接收的参数比TCP多了目标地址
                        var sockfd = args[0].toInt32();
                        console.log('[*] ' + func + ' 调用: 套接字=' + sockfd);
                    }
                },
                onLeave: function (retval) {
                    var result = retval.toInt32();
                    
                    if (func === 'socket') {
                        if (result >= 0) {
                            console.log('[*] socket 创建成功: 文件描述符=' + result);
                        } else {
                            console.log('[*] socket 创建失败: 错误码=' + (-result));
                        }
                    }
                    else if (func === 'connect') {
                        if (result === 0) {
                            console.log('[*] connect 连接成功');
                        } else {
                            console.log('[*] connect 连接失败: 错误码=' + (-result));
                        }
                    }
                    else if (func === 'send') {
                        if (result >= 0) {
                            console.log('[*] send 发送成功: ' + result + ' 字节');
                        } else {
                            console.log('[*] send 发送失败: 错误码=' + (-result));
                        }
                    }
                    else if (func === 'recv') {
                        if (result > 0) {
                            // 实际收到的数据，需要在onLeave中处理
                            var data = formatBuffer(this.bufPtr, result);
                            
                            console.log('[*] recv 接收成功: ' + result + ' 字节');
                            console.log('    数据(HEX): ' + data.hex);
                            console.log('    数据(STR): ' + data.string);
                        } else if (result === 0) {
                            console.log('[*] recv 连接已关闭');
                        } else {
                            console.log('[*] recv 接收失败: 错误码=' + (-result));
                        }
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

console.log("[*] 网络操作监控已启动");

// 注：更完整的实现应该还包括：
// 1. 监控Java层的网络API如HttpURLConnection、OkHttp、Volley等
// 2. 监控SSL/TLS握手过程和密钥协商
// 3. 提供过滤机制，如仅监控特定IP或端口
// 4. 提供数据保存功能，将截获的数据保存到文件
// 5. 监控accept()用于服务器端监听连接 