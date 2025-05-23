// 监控剪贴板内容的读取和写入
Java.perform(function () {
    var ClipboardManager = Java.use('android.content.ClipboardManager');
    ClipboardManager.getPrimaryClip.implementation = function () {
        var clip = this.getPrimaryClip();
        if (clip) {
            var item = clip.getItemAt(0);
            if (item) {
                console.log('[*] 读取剪贴板内容: ' + item.getText());
            }
        }
        return clip;
    };
    ClipboardManager.setPrimaryClip.implementation = function (clip) {
        if (clip) {
            var item = clip.getItemAt(0);
            if (item) {
                console.log('[*] 写入剪贴板内容: ' + item.getText());
            }
        }
        return this.setPrimaryClip(clip);
    };
}); 