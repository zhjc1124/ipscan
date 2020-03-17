import sys
import re
import argparse
import time
import socket
from multiprocessing.dummy import Pool as ThreadPool
from multiprocessing.dummy import Lock
try:
    import requests
    import urllib3
    import IPy
    import gevent
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
except ModuleNotFoundError as e:
    print(e)
    print('请先在命令行运行pip install IPy gevent requests')
    sys.exit(1)

TIMEOUT = 1
pattern = re.compile('<title>(.*?)</title>')
charset_p = re.compile('utf-8|gbk|gb2312', re.I)
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class Scanner(object):
    def __init__(self, target, threads):
        self.target = target
        self.ips = []
        self.time = time.time()
        self.threads = threads
        self.lock = Lock()
        self.get_ip_addr()
        
    def get_ip_addr(self):
        ip_C = '.'.join(self.target.split('.')[:-1])
        self.ips = list(map(lambda x: ip_C+'.'+str(x), range(1, 256)))
        
    def check_port(self, ip, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(TIMEOUT)
        try:
            s.connect((ip, port))
        except:
            return False
        else:
            self.get_title(ip, port)        
        
    def get_title(self, ip, port):
        url = 'http://{}:{}'.format(ip, port)
        headers = {'User-Agent': 'Mozilla/5.0 (compatible, MSIE 11, Windows NT 6.3)'}
        try:
            response = requests.get(url, verify=False, headers=headers, timeout=TIMEOUT, allow_redirects=True)
        except:
            result = 'Error to read title'
        else:
            content_type = response.headers['Content-Type']
            charset = charset_p.findall(content_type)
            response.encoding = charset
            server = response.headers['Server'] if 'Server' in str(response.headers) else ''
            title = pattern.findall(response.text)[0] if pattern.findall(response.text) else ''
            result = '{} {} {}'.format(server, response.status_code, title)
        self.lock.acquire()
        print('{}:{}'.format(ip, port).ljust(24), end = '     Open     ')
        print(result)
        self.lock.release()

    def start(self, port):
        gevents = []
        for ip in self.ips:
            gevents.append(gevent.spawn(self.check_port, ip, port))
        gevent.joinall(gevents)
    
    def run(self):
        try:
            pool = ThreadPool(processes=self.threads)
            print('程序开始')
            pool.map_async(self.start, list(range(1, 65535))).get(0xffff)
            pool.close()
            pool.join()
        except KeyboardInterrupt:
            print('用户停止')
            sys.exit(1)
        except Exception as e:
            print(e)

def main():
    parser = argparse.ArgumentParser(description='Example: python {} [ip|domain] [-t 50] '.format(sys.argv[0]))
    parser.add_argument('target', help=u'扫描ip')
    parser.add_argument('-t', type=int, default=50, dest='threads', help=u'线程数(默认50)')
    args = parser.parse_args()
    scanner = Scanner(args.target, args.threads)
    scanner.run()
    
if __name__ == '__main__':
    main()

            
