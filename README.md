# HashID
powerfull hash identifier tool powered with rust performs, Find up to **`400+`** different hash types

# Intallation
**First of all**, you need *rust* already installed in your device.
then run the following command in your terminal:
```bash
git clone https://github.com/MASTAR-LAST/HashID.git && cd HashID/src
```

## Just use it
### exp:
```bash
cargo run -q main.rs ab56b4d92b40713acc5af89985d4b786
```
### results:
```
Possible hash types: 
        [+] NTLM
        [+] MD5
        [+] MD4
        [+] Double MD5
        [+] LM
        [+] RIPEMD-128
        [+] Haval-128
        [+] Tiger-128
        [+] Skein-256(128)
        [+] Skein-512(128)
        [+] Lotus Notes/Domino 5
        [+] Skype
        [+] ZipMonster
        [+] PrestaShop
        [+] md5(md5(md5($pass)))
        [+] md5(strtoupper(md5($pass)))
        [+] md5(sha1($pass))
        [+] md5($pass.$salt)
        [+] md5($salt.$pass)
        [+] md5(unicode($pass.$salt)
        [+] md5($salt.unicode($pass))
        [+] HMAC-MD5 (key = $pass)
        [+] HMAC-MD5 (key = $salt)
        [+] md5(md5($salt.$pass)
        [+] md5($salt.md5($pass))
        [+] md5($pass.md5($salt))
        [+] md5($salt.$pass.$salt)
        [+] md5(md5($pass.md5($salt))
        [+] md5($salt.md5($salt.$pass))
        [+] md5($salt.md5($pass.$salt))
        [+] md5($username.0.$pass)
        [+] DNSSEC(NSEC3)
        [+] MD2
        [+] Domain Cached Credentials 2
        [+] Snefru-128
        [+] Domain Cached Credentials
        [+] RAdmin v2.x
        [+] Cisco Type 7
        [+] BigCrypt
```

## Note
this is my first project in rust so, it will not be the best,also this is a not-complited project yet.