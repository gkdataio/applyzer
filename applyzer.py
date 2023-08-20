from concurrent.futures import ThreadPoolExecutor as Executor  # pip install futures
from Wappalyzer import Wappalyzer, WebPage  # pip install python-Wappalyzer
import urllib3, argparse, warnings

warnings.filterwarnings("ignore", category=UserWarning)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)  # disable Python SSL warnings!

pastel_green = "\033[38;5;120m"
pastel_blue = "\033[38;5;81m"
pastel_purple = "\033[38;5;99m"
bold = "\033[1m"
end = "\033[0m"

wappalyzer = Wappalyzer.latest()

print(pastel_blue + """
                 _                 
  __ _ _ __ _ __| |_  _ ______ _ _ 
 / _` | '_ \ '_ \ | || |_ / -_) '_|
 \__,_| .__/ .__/_|\_, /__\___|_|  
      |_|  |_|     |__/   @gkdata        
	""" + end)

def check(out, ig, url):
    if not url.startswith('https'):
        url = 'https://' + url
    try:
        webpage = WebPage.new_from_url(url)
        tech = wappalyzer.analyze(webpage)
        print(f"{pastel_green}[+]{end} {url} | {pastel_blue}{bold}{' - '.join(tech)}{end}")
        if out != 'None':
            with open(out, 'a') as f:
                f.write(f"{url} | {' - '.join(tech)}\n")
    except Exception as e:
        if ig == 'True':
            pass
        else:
            print(f"{pastel_purple}Error:{end} [ {bold}{url}{end} ] > {str(e)}")

parser = argparse.ArgumentParser()
parser.add_argument("-d", "--domain", help="Single domain to analyze", type=str)
parser.add_argument("-f", "--file", help="File containing list of domains to analyze", type=str)
parser.add_argument("-t", "--thread", help="Threads Number - (Default: 1)", type=int, default=1)
parser.add_argument("-i", "--ignore", help="To Ignore The Errors", action='store_true')
parser.add_argument("-o", "--output", help="Save The Results To a File", type=str)

args = parser.parse_args()

threads = args.thread
ig = str(args.ignore)
out = str(args.output)
domains = []

# Read from file if provided
if args.file:
    with open(args.file, 'r') as file:
        domains = [line.strip() for line in file]
elif args.domain:
    domains.append(args.domain)
else:
    print("Please provide a domain or a file containing domains.")
    exit(1)

print(f"{pastel_green}[+]{end} Output: {out}")
print(f"{pastel_green}[+]{end} Threads: {threads}")
print(f"{pastel_green}[+]{end} Ignore: {ig}")

print(f"\n{pastel_purple}[+]{end} Results:\n")

with Executor(max_workers=int(threads)) as exe:
    for domain in domains:
        print(f"{pastel_green}[+]{end} Domain: {domain}")
        exe.submit(check, out, ig, domain)
