<h1 align="center">
  <br>
  <a href="https://github.com/system00-security/pwnthings"><img src="https://i.ibb.co/NpTQHX6/S-T-T-2.png" width="200px" alt="Pwnthings"></a>
</h1>

<h2 align="center">PwnThings</h2>
<p align="center">
<a href="https://github.com/joyghoshs/pwnthings/issues"><img src="https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat"></a>
<a href="https://twitter.com/0xjoyghosh"><img src="https://img.shields.io/twitter/follow/0xjoyghosh.svg?logo=twitter"></a>
<a href="https://github.com/joyghoshs/security-testing-toolkit"><img src="https://img.shields.io/crates/l/security"></a>
<a href="https://system00-security.github.io"><img src="https://img.shields.io/badge/Under_Devlopment-Project-orange"></a>

  </p>
  
PwnThings is an swiss army knife for pentester and ctf player,Its Purely created and crafted with python3,some of its module needs to be run onlinux,its a single script so you can just move it to /bin in your linux distro and use it from anywhere.it doesnt need any user interaction to install it dependency it detects missing dependency and install those.

## Modules
**Description about some of its module.**
* [Base64 encode/decode](#base64base32rot13)
* [Base32 encode/decode](#base64base32rot13)
* [rot13  encode/decode](#base64base32rot13)
* [google search from shell](#google-search)
* [gtfobin search from shell](#gtfobin)
* [lolbas search from shell](#lolbas)
* [exploit.shodan.io search from shell](#shodan-exploit)
* [leakix search from shell](#leakix)
* [spyse cve search from shell](#spyse-cve)
* [url to favihash generator](#favico-hash)
* [ip2location](#ip2location)
* [subdomain enumerator](#subdomain-enumerator)
* [generate php simple cmd shell](#php-cmd-shell)
* [connector for php simple cmd shell](#php-cmd-shell)
* [host2ip](#host2ip)
* [asnlookup with company name](#asnlookup)
* [find cve exploit by cve number from github](#git-cve)
* [filter ip from stdin](#filter)
* [filter url from stdin](#filter)
* [filter email from stdin](#filter)
* [listner and generator for simple python backdoor](#pyBackdoor)
* [temporary email address from shell](#tempmail)
* [generate ip address from given iprange](#iprange)
* [apktool decryptor/compiler](#apktool)
* [random proxy generator](#random-proxy)
* [encrypted pdf cracker](#pdf-cracker)

## Base64/base32/rot13
**encrypt/decrypt base64 with pwnthings**</br>

As a Script<br/>
**Encode**<br/>
![base64 encode](https://i.ibb.co/GWH7h0w/pwnthingsbase64.png)<br/>
**Decode**<br/>
![base64 encode](https://i.ibb.co/jG7ShfQ/pwnthingsbase64d-png.png)

```bash
python3 pwnthings.py -base64e string #encrypt a plain text string to base64
python3 pwnthings.py -base64d base64_string #decrypt base64 string
python3 pwnthings.py -base32e string #encrypt a plain text string to base32
python3 pwnthings.py -base32d base32_string #decrypt base32 string
python3 pwnthings.py -rot13e string #encrypt a plain text string to rot13
python3 pwnthings.py -base32d rot13_string #decrypt rot13 string
```

As api for your own python3 script
```python
from pwnthings import *
base64_encode('yourstring') #to encrypt a regular readable string to base64
base64_decode('yourstring') #to decrypt a base64 string
base32_encode('yourstring') #to encrypt a regular readable string to base32
base32_decode('yourstring') #to decrypt a base32 string
rot13_encode('yourstring') #to encrypt a regular readable string to rot13
rot13_decode('yourstring') #to decrypt a rot13 string
```

## google-search
As a Script<br/>
![google-search](https://i.ibb.co/fXsmb0L/pwnthingsgoogle.png)<br/>
```bash
python3 pwnthings.py -gsearch "Your_search"
```
As api for your own python3 script
```python
from pwnthings import *
google_search('your_query')
```

## gtfobin
As a script<br/>
![gtfobin](https://imgur.com/4iPmh4x.png)

```bash
python3 pwnthings.py -gtfobin 'bin_name'
```

As Api for your own python3 script
```python3
from pwnthings import *
gtfobin_search('bin_name')
```


## lolbas
As a script<br/>
![lolbas](https://imgur.com/4SWnrBJ.png)

```bash
python3 pwnthings.py -lobas 'bin_name'
```

As Api for your own python3 script
```python3
from pwnthings import *
lolbas_search('bin_name')
```
## shodan-exploit
As a script<br/>
![shodan-exploit](https://imgur.com/5QVbkcG.png)

```bash
python3 pwnthings.py -expshodan 'software name'
```

As Api for your own python3 script
```python3
from pwnthings import *
exploit_shodan('software name')
```
## leakix
As a script<br/>
![leakix](https://imgur.com/st4D1y4.png)

```bash
python3 pwnthings.py -leakix target_ip
```

As Api for your own python3 script
```python3
from pwnthings import *
leakix_search('ipaddress')
```
## spyse-cve
As a script<br/>
![spyse](https://imgur.com/2RZ1RYT.png)

```bash
python3 pwnthings.py -spyse target_website
```

As Api for your own python3 script
```python3
from pwnthings import *
spyse_cve('ipaddress')
```
## favico-hash
As a script<br/>
![favico](https://imgur.com/Y2sXK3h.png)

```bash
python3 pwnthings.py -favicohash https://target.com
```

As Api for your own python3 script
```python3
from pwnthings import *
favico_hash('https://target.com')
```

## ip2location
As a script<br/>
![ip2location](https://imgur.com/wa6fxBW.png)

```bash
python3 pwnthings.py -ip2location yourtarget_ip
```

As Api for your own python3 script
```python3
from pwnthings import *
ip2location('yourtargetip')
```

## Subdomain_enumerator
As a script<br/>
![subdomain-enum](https://imgur.com/y16w75y.png)

```bash
python3 pwnthings.py -subdomain target.com
```

As Api for your own python3 script
```python3
from pwnthings import *
passive_subdomain('target.com')
```
## asnlookup
As a script<br/>
![asnlookup](https://imgur.com/EGtcGAg.png)

```bash
python3 pwnthings.py -asnlookup company_name
```

As Api for your own python3 script
```python3
from pwnthings import *
asnlookup('company_name')
```
## tempmail
As a script<br/>
![tempmail](https://imgur.com/BvXn1pi.png)

```bash
python3 pwnthings.py -tempmail yourusername
```

As Api for your own python3 script
```python3
from pwnthings import *
temp_mail('username')
```

## random-proxy
As a script<br/>
![random-proxy](https://imgur.com/zfLEdwe.png)

```bash
python3 pwnthings.py -randomproxy proxytype[socks/http/https]
```

As Api for your own python3 script
```python3
from pwnthings import *
random_proxy('socks/http/https')
```
## pdf-cracker
As a script<br/>
![pdf-crack](https://imgur.com/CHv2WN6.png)

```bash
python3 pwnthings.py -pdfcrack pdf_file_name//wordlist
```

As Api for your own python3 script
```python3
from pwnthings import *
pdf_crack('filename.pdf','wordlist.txt')
```
