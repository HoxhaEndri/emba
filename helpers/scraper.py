import os
import re
import sys
import requests

base_url = "https://security.snyk.io/vuln/"

def extract_links(results):
    ret=[]
    for link in results:
        ret.append(base_url+link["href"][5:])
    return ret
    
def generate_links_file(list):
    with open('links.txt', 'w') as f:
        for line in list:
            f.write(f"{line}\n")

def bool_to_str(bool):
    if bool:
        return "yes"
    else:
        return "no"

def name_from_url(url):
    return url.split("vuln/")[1].strip()
            
def check_snyk(vuln_url):
    ret = ""
    PoC=False
    Github=False
    Curl=False
    Xml=False
    cves = list()

    vuln_url = vuln_url.strip()

    if vuln_url.startswith("https://"):
        try:
            page = requests.get(vuln_url)
            #https://www.cve.org/CVERecord?id=CVE-2024-5585
            cves = list(set(re.findall("id\=CVE-[0-9]{4}-[0-9]+",page.content.decode())))

            if len(cves) > 0:
                x = re.search("\bPoC\b",page.content.decode())
    
                if x != None:
                    PoC=True

                tmp = re.search("GitHub PoC", page.content.decode())

                if tmp != None:
                    Github=True

                tmp = re.search("curl http", page.content.decode())

                if tmp != None:
                    Curl=True

                tmp = re.search("For example the below code contains", page.content.decode())

                if tmp != None:
                    Xml=True

                if PoC or Github or Curl or Xml:
                    for cve in cves:
                        ret += cve[3:] + ";" + name_from_url(vuln_url) + ";" + vuln_url[:-1] + ";" + bool_to_str(PoC) + ";" + bool_to_str(Github) + ";" + bool_to_str(Curl) + ";" + bool_to_str(Xml) + ";" + "\n"
        except ConnectionError:
            print("Failed to open this url: "+vuln_url)
    return ret

def main():

    result = "CVE;advisory name;advisory URL;unknown PoC;Github PoC;Curl PoC;XML PoC;\n"
    with open(sys.argv[1]) as links:
        for link in links:
            temp = check_snyk(link)
            result += temp

    with open(sys.argv[2], "w") as filetowrite:
        filetowrite.write(result)


if __name__ == "__main__":
    main()
