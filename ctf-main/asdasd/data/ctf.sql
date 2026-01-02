-- 清空旧数据（可选）
DELETE FROM challenges;

-- 添加题目
INSERT INTO `challenges` VALUES
(1, 'Web签到题', 'Web', '欢迎来到SDHGCTF！\n\n这是一道简单的签到题，flag就在网页源代码中。\n\n**提示**：按F12打开开发者工具查看。', 'flag{welcome_to_sdhgctf_2025}', 50, 'easy', 1, '2025-12-29 10:00:00'),

(2, 'SQL注入入门', 'Web', '这是一个存在SQL注入漏洞的登录页面。\n\n尝试绕过登录验证获取flag。\n\n**提示**：万能密码 admin'' or ''1''=''1', 'flag{sql_injection_master}', 100, 'medium', 1, '2025-12-29 10:00:00'),

(3, 'Base64编码', 'Misc', '解码下面这段Base64编码的文本：\n\n```\nZmxhZ3tiYXNlNjRfZGVjb2RlX21hc3Rlcn0=\n```\n\n**提示**：使用在线Base64解码工具', 'flag{base64_decode_master}', 50, 'easy', 1, '2025-12-29 10:00:00'),

(4, '文件上传绕过', 'Web', '网站的文件上传功能存在安全漏洞。\n\n尝试上传PHP文件并执行。\n\n**限制**：只允许上传图片文件(.jpg, .png)\n\n**提示**：双写后缀、MIME类型伪造', 'flag{file_upload_bypass_success}', 150, 'medium', 1, '2025-12-29 10:00:00'),

(5, 'XSS跨站脚本', 'Web', '网站留言板存在XSS漏洞。\n\n构造XSS payload获取管理员cookie。\n\n**目标**：在留言中插入JavaScript代码\n\n**提示**：<script>alert(document.cookie)</script>', 'flag{xss_cookie_steal_success}', 120, 'medium', 1, '2025-12-29 10:00:00'),

(6, 'Caesar密码', 'Crypto', '这是一道经典的凯撒密码题。\n\n密文：synt{frnfne_pvcure_vf_rnfl}\n\n**提示**：ROT13偏移', 'flag{caesar_cipher_is_easy}', 80, 'easy', 1, '2025-12-29 10:00:00'),

(7, '逆向工程入门', 'Reverse', '分析这个简单的二进制程序。\n\n使用IDA Pro或Ghidra进行静态分析。\n\n**下载地址**：[点击下载](http://example.com/file.exe)\n\n**提示**：flag在明文字符串中', 'flag{reverse_engineering_101}', 200, 'hard', 1, '2025-12-29 10:00:00'),

(8, 'Wireshark流量分析', 'Misc', '分析提供的pcap数据包文件。\n\n在HTTP POST请求中找到flag。\n\n**下载地址**：[点击下载](http://example.com/traffic.pcap)\n\n**提示**：使用Wireshark的Follow HTTP Stream功能', 'flag{wireshark_packet_found}', 100, 'medium', 1, '2025-12-29 10:00:00'),

(9, '命令注入', 'Web', '系统存在命令注入漏洞。\n\n尝试通过ping命令读取服务器上的flag文件。\n\n**目标文件**：/home/ctf/flag.txt\n\n**提示**：使用管道符 | 或分号 ; 连接命令', 'flag{command_injection_rce}', 180, 'hard', 1, '2025-12-29 10:00:00'),

(10, 'Zip伪加密', 'Misc', '下载的zip文件显示需要密码，但其实是伪加密。\n\n**下载地址**：[点击下载](http://example.com/secret.zip)\n\n**提示**：使用十六进制编辑器修改zip头部', 'flag{fake_zip_encryption}', 90, 'easy', 1, '2025-12-29 10:00:00');


INSERT INTO challenges VALUES
(1, 'Web题目1', 'Web',
'题目描述...\n\n**附件下载**：[点击下载](144)',
'flag{test1}', 100, 'easy', 1, '2025-12-29 10:00:00');