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
* google search from shell
* gtfobin search from shell
* lolbas search from shell
* exploit.shodan.io search from shell
* leakix search from shell
* spyse cve search from shell
* url to favihash generator
* ip2location
* subdomain enumerator
* generate php simple cmd shell
* connector for php simple cmd shell
* host2ip
* asnlookup with company name
* find cve exploit by cve number from github
* filter ip from stdin
* filter url from stdin
* filter email from stdin
* listner and generator for simple python backdoor
* temporary email address from shell
* generate ip address from given iprange
* apktool decryptor/compiler
* random proxy generator
* encrypted pdf cracker

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
![base64 encode](https://i.ibb.co/fXsmb0L/pwnthingsgoogle.png)<br/>
```bash
python3 pwnthings.py -gsearch "Your_search"
```
As api for your own python3 script
```python
from pwnthings import *
google_search('your_query')
```


