import argparse
import concurrent.futures
import re
import requests
from termcolor import colored

parser = argparse.ArgumentParser()
parser.add_argument("input_path", help="caminho do arquivo de entrada contendo os IPs", type=str)
parser.add_argument("regex_path", help="caminho do arquivo de regex", type=str)
parser.add_argument("--output_path","-o", help="caminho do arquivo de saída", type=str, default="output.txt")
args = parser.parse_args()

with open(args.input_path) as file:
    ips = file.readlines()

with open(args.regex_path) as file:
    regexes = file.readlines()

for ip in ips:
    ip = ip.strip()
    print(colored(ip, "white"))
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(lambda: requests.get(ip)) for _ in range(1)]

        results = [f.result().text for f in futures]

        for regex in regexes:
            regex = regex.strip()
            matches = re.finditer(regex, str(results), re.MULTILINE)
            for matchNum, match in enumerate(matches, start=1):
                print(colored("Regex: ", "green"), regex)
                print(colored("Match {matchNum} was found at: {match}".format(matchNum=matchNum, start=match.start(), end=match.end(), match=match.group()), "red"), '\n')
                with open(args.output_path, "a") as out_file:
                    out_file.write(f"{ip}\nRegex: {regex}\nMatch {matchNum} was found at : {match}\n\n")
    except requests.exceptions.RequestException as e:
        print("Error: {}".format(e))
