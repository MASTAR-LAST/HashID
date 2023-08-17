use regex::Regex;
use std::{
    collections::HashMap,
    env::args,
    // io::{stdin, stdout, Write},
};

// Aother: Muhammed Alkohawaldeh
// github: https://github.com/MASTAR-LAST/HashID

fn main() {
    // TODO: Improve the Hashmap speed and memory useg
    let mut hash_patterns: HashMap<&str, Vec<&str>> = HashMap::new();
    hash_patterns.insert(r"^[a-f0-9]{4}$", vec!["CRC-16", "CRC-16-CCITT", "FCS-16"]);

    hash_patterns.insert(
        r"^[a-f0-9]{8}$",
        vec![
            "Adler-32",
            "CRC-32B",
            "FCS-32",
            "GHash-32-3",
            "GHash-32-5",
            "FNV-132",
            "Fletcher-32",
            "Joaat",
            "ELF-32",
            "XOR-32",
        ],
    );

    hash_patterns.insert(r"^[a-f0-9]{6}$", vec!["CRC-24"]);

    hash_patterns.insert(r"^(\$crc32\$[a-f0-9]{8}.)?[a-f0-9]{8}$", vec!["CRC-32"]);

    hash_patterns.insert(r"^\+[a-z0-9/.]{12}$", vec!["Eggdrop IRC Bot"]);

    hash_patterns.insert(
        r"^[a-z0-9/.]{13}$",
        vec!["DES(Unix)", "Traditional DES", "DEScrypt"],
    );

    hash_patterns.insert(
        r"^[a-f0-9]{16}$",
        vec![
            "MySQL323",
            "DES(Oracle)",
            "Half MD5",
            "Oracle 7-10g",
            "FNV-164",
            "CRC-64",
        ],
    );

    hash_patterns.insert(r"^[a-z0-9/.]{16}$", vec!["Cisco-PIX(MD5)"]);

    hash_patterns.insert(r"^\([a-z0-9/+]{20}\)$", vec!["Lotus Notes/Domino 6"]);

    hash_patterns.insert(r"^_[a-z0-9/.]{19}$", vec!["BSDi Crypt"]);

    hash_patterns.insert(r"^[a-f0-9]{24}$", vec!["CRC-96(ZIP)"]);

    hash_patterns.insert(r"^[a-z0-9/.]{24}$", vec!["Crypt16"]);

    hash_patterns.insert(r"^(\$md2\$)?[a-f0-9]{32}$", vec!["MD2"]);

    hash_patterns.insert(
        r"^[a-f0-9]{32}(:.+)?$",
        vec![
            "MD5",
            "MD4",
            "Double MD5",
            "LM",
            "RIPEMD-128",
            "Haval-128",
            "Tiger-128",
            "Skein-256(128)",
            "Skein-512(128)",
            "Lotus Notes/Domino 5",
            "Skype",
            "ZipMonster",
            "PrestaShop",
            "md5(md5(md5($pass)))",
            "md5(strtoupper(md5($pass)))",
            "md5(sha1($pass))",
            "md5($pass.$salt)",
            "md5($salt.$pass)",
            "md5(unicode($pass.$salt)",
            "md5($salt.unicode($pass))",
            "HMAC-MD5 (key = $pass)",
            "HMAC-MD5 (key = $salt)",
            "md5(md5($salt.$pass)",
            "md5($salt.md5($pass))",
            "md5($pass.md5($salt))",
            "md5($salt.$pass.$salt)",
            "md5(md5($pass.md5($salt))",
            "md5($salt.md5($salt.$pass))",
            "md5($salt.md5($pass.$salt))",
            "md5($username.0.$pass)",
        ],
    );

    hash_patterns.insert(r"^(\$snefru\$)?[a-f0-9]{32}$", vec!["Snefru-128"]);

    hash_patterns.insert(r"^(\$NT\$)?[a-f0-9]{32}$", vec!["NTLM"]);

    hash_patterns.insert(
        r"^([^\\/:*?<>|]{1,20}:)?[a-f0-9]{32}(:[^\\/:*?<>|]{1,20})?$",
        vec!["Domain Cached Credentials"],
    );

    hash_patterns.insert(
        r"^([^\\/:*?<>|]{1,20}:)?(\$DCC2\$10240#[^\\/:*?<>|]{1,20}#)?[a-f0-9]{32}$",
        vec!["Domain Cached Credentials 2"],
    );

    hash_patterns.insert(
        r"^[a-z0-9/+]{27}=$",
        vec!["SHA-1(Base64)", "Netscape LDAP SHA"],
    );

    hash_patterns.insert(
        r"^\$1\$[a-z0-9/.]{0,8}\$[a-z0-9/.]{22}(:.*)?$",
        vec!["MD5 Crypt", "Cisco-IOS(MD5)", "FreeBSD MD5"],
    );

    hash_patterns.insert(r"^0x[a-f0-9]{32}$", vec!["Lineage II C4"]);

    hash_patterns.insert(
        r"^\$H\$[a-z0-9/.]{31}$",
        vec![
            "phpBB v3.x",
            "Wordpress v2.6.0/2.6.1",
            "PHPass' Portable Hash",
        ],
    );

    hash_patterns.insert(
        r"^\$P\$[a-z0-9/.]{31}$",
        vec![
            "Wordpress ≥ v2.6.2",
            "Joomla ≥ v2.5.18",
            "PHPass' Portable Hash",
        ],
    );

    hash_patterns.insert(
        r"^[a-f0-9]{32}:[a-z0-9]{2}$",
        vec!["osCommerce", "xt:Commerce"],
    );

    hash_patterns.insert(
        r"^\$apr1\$[a-z0-9/.]{0,8}\$[a-z0-9/.]{22}$",
        vec!["MD5(APR)", "Apache MD5", "md5apr1"],
    );

    hash_patterns.insert(r"^[a-z0-9$/.]{31}$", vec!["AIX(smd5)"]);

    hash_patterns.insert(r"^[a-f0-9]{32}:[a-f0-9]{32}$", vec!["WebEdition CMS"]);

    hash_patterns.insert(r"^[a-f0-9]{32}:.{5}$", vec!["IP.Board ≥ v2+"]);

    hash_patterns.insert(r"^[a-f0-9]{32}:.{8}$", vec!["MyBB ≥ v1.2+"]);

    hash_patterns.insert(r"^[a-z0-9]{34}$", vec!["CryptoCurrency(Adress)"]);

    hash_patterns.insert(
        r"^[a-f0-9]{40}(:.+)?$",
        vec![
            "SHA-1",
            "Double SHA-1",
            "RIPEMD-160",
            "Haval-160",
            "Tiger-160",
            "HAS-160",
            "LinkedIn",
            "Skein-256(160)",
            "Skein-512(160)",
            "MangosWeb Enhanced CMS",
            "sha1(sha1(sha1($pass)))",
            "sha1(md5($pass))",
            "sha1($pass.$salt)",
            "sha1($salt.$pass)",
            "sha1(unicode($pass.$salt)",
            "sha1($salt.unicode($pass))",
            "HMAC-SHA1 (key = $pass)",
            "HMAC-SHA1 (key = $salt)",
            "sha1($salt.$pass.$salt)",
        ],
    );

    hash_patterns.insert(r"^\*[a-f0-9]{40}$", vec!["MySQL5.x", "MySQL4.1"]);

    hash_patterns.insert(r"^[a-z0-9]{43}$", vec!["Cisco-IOS(SHA-256)"]);

    hash_patterns.insert(
        r"^[a-z0-9/+]{38}==$",
        vec!["SSHA-1(Base64)", "Netscape LDAP SSHA", "nsldaps"],
    );

    hash_patterns.insert(r"^[a-z0-9=]{47}$", vec!["Fortigate(FortiOS)"]);

    hash_patterns.insert(
        r"^[a-f0-9]{48}$",
        vec![
            "Haval-192",
            "Tiger-192",
            "SHA-1(Oracle)",
            "OSX v10.4",
            "OSX v10.5",
            "OSX v10.6",
        ],
    );

    hash_patterns.insert(r"^[a-f0-9]{51}$", vec!["Palshop CMS"]);

    hash_patterns.insert(r"^[a-z0-9]{51}$", vec!["CryptoCurrency(PrivateKey)"]);

    hash_patterns.insert(r"^[0-9]{2}\$[a-z0-9$/.]{44}$", vec!["AIX(ssha1)"]);

    hash_patterns.insert(r"^0x0100[a-f0-9]{48}$", vec!["MSSQL(2005)", "MSSQL(2008)"]);

    hash_patterns.insert(r"^(\$md5,rounds=[0-9]+\$|\$md5\$rounds=[0-9]+\$|\$md5\$)[a-z0-9/.]{0,16}(\$|\$\$)[a-z0-9/.]{22}$", vec!["Sun MD5 Crypt"]);

    hash_patterns.insert(
        r"^[a-f0-9]{56}$",
        vec![
            "SHA-224",
            "Haval-224",
            "SHA3-224",
            "Skein-256(224)",
            "Skein-512(224)",
        ],
    );

    hash_patterns.insert(
        r"^(\$2[axy]|\$2)\$[0-9]{2}\$[a-z0-9/.]{53}$",
        vec!["Blowfish(OpenBSD)", "Woltlab Burning Board 4.x", "bcrypt"],
    );

    hash_patterns.insert(r"^[a-f0-9]{40}:[a-f0-9]{16}$", vec!["Android PIN"]);

    hash_patterns.insert(
        r"^(S:)?[a-f0-9]{40}(:)?[a-f0-9]{20}$",
        vec!["Oracle 11g/12c"],
    );

    hash_patterns.insert(
        r"^\$bcrypt-sha256\$(2[axy]|2)\,[0-9]+\$[a-z0-9/.]{22}\$[a-z0-9/.]{31}$",
        vec!["bcrypt(SHA-256)"],
    );

    hash_patterns.insert(r"^[a-f0-9]{32}:.{3}$", vec!["vBulletin < v3.8.5"]);

    hash_patterns.insert(r"^[a-f0-9]{32}:.{30}$", vec!["vBulletin ≥ v3.8.5"]);

    hash_patterns.insert(r"^(\$snefru\$)?[a-f0-9]{64}$", vec!["Snefru-256"]);

    hash_patterns.insert(
        r"^[a-f0-9]{64}(:.+)?$",
        vec![
            "SHA-256",
            "RIPEMD-256",
            "Haval-256",
            "GOST R 34.11-94",
            "GOST CryptoPro S-Box",
            "SHA3-256",
            "Skein-256",
            "Skein-512(256)",
            "Ventrilo",
            "sha256($pass.$salt)",
            "sha256($salt.$pass)",
            "sha256(unicode($pass.$salt)",
            "sha256($salt.unicode($pass))",
            "HMAC-SHA256 (key = $pass)",
            "HMAC-SHA256 (key = $salt)",
        ],
    );

    hash_patterns.insert(r"^[a-f0-9]{32}:[a-z0-9]{32}$", vec!["Joomla < v2.5.18"]);

    hash_patterns.insert(
        r"^[a-f-0-9]{32}:[a-f-0-9]{32}$",
        vec!["SAM(LM_Hash:NT_Hash)"],
    );

    hash_patterns.insert(
        r"^(\$chap\$0\*)?[a-f0-9]{32}[\*:][a-f0-9]{32}(:[0-9]{2})?$",
        vec!["MD5(Chap)", "iSCSI CHAP Authentication"],
    );

    hash_patterns.insert(
        r"^\$episerver\$\*0\*[a-z0-9/=+]+\*[a-z0-9/=+]{27,28}$",
        vec!["EPiServer 6.x < v4"],
    );

    hash_patterns.insert(r"^[0-9]{2}\$[a-z0-9$/.]{60}$", vec!["AIX(ssha256)"]);

    hash_patterns.insert(r"^[a-f0-9]{80}$", vec!["RIPEMD-320"]);

    hash_patterns.insert(
        r"^\$episerver\$\*1\*[a-z0-9/=+]+\*[a-z0-9/=+]{42,43}$",
        vec!["EPiServer 6.x ≥ v4"],
    );

    hash_patterns.insert(r"^0x0100[a-f0-9]{88}$", vec!["MSSQL(2000)"]);

    hash_patterns.insert(
        r"^[a-f0-9]{96}$",
        vec!["SHA-384", "SHA3-384", "Skein-512(384)", "Skein-1024(384)"],
    );

    hash_patterns.insert(
        r"^[a-z0-9/+]{96}$",
        vec!["SSHA-512(Base64)", "LDAP(SSHA-512)"],
    );

    hash_patterns.insert(
        r"^[0-9]{2}\$[a-z0-9/.]{16,48}\$[a-z0-9/.]{86}$",
        vec!["AIX(ssha512)"],
    );

    hash_patterns.insert(
        r"^[a-f0-9]{128}(:.+)?$",
        vec![
            "SHA-512",
            "Whirlpool",
            "Salsa10",
            "Salsa20",
            "SHA3-512",
            "Skein-512",
            "Skein-1024(512)",
            "sha512($pass.$salt)",
            "sha512($salt.$pass)",
            "sha512(unicode($pass.$salt)",
            "sha512($salt.unicode($pass))",
            "HMAC-SHA512 (key = $pass)",
            "HMAC-SHA512 (key = $salt)",
        ],
    );

    hash_patterns.insert(r"^[a-f0-9]{136}$", vec!["OSX v10.7"]);

    hash_patterns.insert(r"^0x0200[a-f0-9]{136}$", vec!["MSSQL(2012)", "MSSQL(2014)"]);

    hash_patterns.insert(
        r"^\$ml\$[0-9]+\$[a-f0-9]{64}\$[a-f0-9]{128}$",
        vec!["OSX v10.8", "OSX v10.9"],
    );

    hash_patterns.insert(r"^[a-f0-9]{256}$", vec!["Skein-1024"]);

    hash_patterns.insert(
        r"^grub\.pbkdf2\.sha512\.[0-9]+\.([a-f0-9]{128,2048}\.|[0-9]+\.)?[a-f0-9]{128}$",
        vec!["GRUB 2"],
    );

    hash_patterns.insert(r"^sha1\$[a-z0-9]+\$[a-f0-9]{40}$", vec!["Django(SHA-1)"]);

    hash_patterns.insert(r"^[a-f0-9]{49}$", vec!["Citrix Netscaler"]);

    hash_patterns.insert(r"^\$S\$[a-z0-9/.]{52}$", vec!["Drupal > v7.x"]);

    hash_patterns.insert(
        r"^\$5\$(rounds=[0-9]+\$)?[a-z0-9/.]{0,16}\$[a-z0-9/.]{43}$",
        vec!["SHA-256 Crypt"],
    );

    hash_patterns.insert(
        r"^0x[a-f0-9]{4}[a-f0-9]{16}[a-f0-9]{64}$",
        vec!["Sybase ASE"],
    );

    hash_patterns.insert(
        r"^\$6\$(rounds=[0-9]+\$)?[a-z0-9/.]{0,16}\$[a-z0-9/.]{86}$",
        vec!["SHA-512 Crypt"],
    );

    hash_patterns.insert(r"^\$sha\$[a-z0-9]{1,16}\$([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|[a-f0-9]{128}|[a-f0-9]{140})$", vec!["Minecraft(AuthMe Reloaded)"]);

    hash_patterns.insert(
        r"^sha256\$[a-z0-9]+\$[a-f0-9]{64}$",
        vec!["Django(SHA-256)"],
    );

    hash_patterns.insert(
        r"^sha384\$[a-z0-9]+\$[a-f0-9]{96}$",
        vec!["Django(SHA-384)"],
    );

    hash_patterns.insert(
        r"^crypt1:[a-z0-9+=]{12}:[a-z0-9+=]{12}$",
        vec!["Clavister Secure Gateway"],
    );

    hash_patterns.insert(r"^[a-f0-9]{112}$", vec!["Cisco VPN Client(PCF-File)"]);

    hash_patterns.insert(r"^[a-f0-9]{1329}$", vec!["Microsoft MSTSC(RDP-File)"]);

    hash_patterns.insert(
        r"^[^\\/:*?<>|]{1,20}[:]{2,3}([^\\/:*?<>|]{1,20})?:[a-f0-9]{48}:[a-f0-9]{48}:[a-f0-9]{16}$",
        vec!["NetNTLMv1-VANILLA / NetNTLMv1+ESS"],
    );

    hash_patterns.insert(r"^([^\\/:*?<>|]{1,20}\\)?[^\\/:*?<>|]{1,20}[:]{2,3}([^\\/:*?<>|]{1,20}:)?[^\\/:*?<>|]{1,20}:[a-f0-9]{32}:[a-f0-9]+$", vec!["NetNTLMv2"]);

    hash_patterns.insert(
        r"^\$(krb5pa|mskrb5)\$([0-9]{2})?\$.+\$[a-f0-9]{1,}$",
        vec!["Kerberos 5 AS-REQ Pre-Auth"],
    );

    hash_patterns.insert(r"^\$scram\$[0-9]+\$[a-z0-9/.]{16}\$sha-1=[a-z0-9/.]{27},sha-256=[a-z0-9/.]{43},sha-512=[a-z0-9/.]{86}$", vec!["SCRAM Hash"]);

    hash_patterns.insert(
        r"^[a-f0-9]{40}:[a-f0-9]{0,32}$",
        vec!["Redmine Project Management Web App"],
    );

    hash_patterns.insert(r"^(.+)?\$[a-f0-9]{16}$", vec!["SAP CODVN B (BCODE)"]);

    hash_patterns.insert(r"^(.+)?\$[a-f0-9]{40}$", vec!["SAP CODVN F/G (PASSCODE)"]);

    hash_patterns.insert(
        r"^(.+\$)?[a-z0-9/.+]{30}(:.+)?$",
        vec!["Juniper Netscreen/SSG(ScreenOS)"],
    );

    hash_patterns.insert(r"^0x[a-f0-9]{60}\s0x[a-f0-9]{40}$", vec!["EPi"]);

    hash_patterns.insert(r"^[a-f0-9]{40}:[^*]{1,25}$", vec!["SMF ≥ v1.1"]);

    hash_patterns.insert(
        r"^(\$wbb3\$\*1\*)?[a-f0-9]{40}[:*][a-f0-9]{40}$",
        vec!["Woltlab Burning Board 3.x"],
    );

    hash_patterns.insert(
        r"^[a-f0-9]{130}(:[a-f0-9]{40})?$",
        vec!["IPMI2 RAKP HMAC-SHA1"],
    );

    hash_patterns.insert(
        r"^[a-f0-9]{32}:[0-9]+:[a-z0-9_.+-]+@[a-z0-9-]+\.[a-z0-9-.]+$",
        vec!["Lastpass"],
    );

    hash_patterns.insert(r"^[a-z0-9/.]{16}([:$].{1,})?$", vec!["Cisco-ASA(MD5)"]);

    hash_patterns.insert(r"^\$vnc\$\*[a-f0-9]{32}\*[a-f0-9]{32}$", vec!["VNC"]);

    hash_patterns.insert(
        r"^[a-z0-9]{32}(:([a-z0-9-]+\.)?[a-z0-9-.]+\.[a-z]{2,7}:.+:[0-9]+)?$",
        vec!["DNSSEC(NSEC3)"],
    );

    hash_patterns.insert(r"^(user-.+:)?\$racf\$\*.+\*[a-f0-9]{16}$", vec!["RACF"]);

    hash_patterns.insert(r"^\$3\$\$[a-f0-9]{32}$", vec!["NTHash(FreeBSD Variant)"]);

    hash_patterns.insert(
        r"^\$sha1\$[0-9]+\$[a-z0-9/.]{0,64}\$[a-z0-9/.]{28}$",
        vec!["SHA-1 Crypt"],
    );

    hash_patterns.insert(r"^[a-f0-9]{70}$", vec!["hMailServer"]);

    hash_patterns.insert(
        r"^[:\$][AB][:\$]([a-f0-9]{1,8}[:\$])?[a-f0-9]{32}$",
        vec!["MediaWiki"],
    );

    hash_patterns.insert(r"^[a-f0-9]{140}$", vec!["Minecraft(xAuth)"]);

    hash_patterns.insert(
        r"^\$pbkdf2(-sha1)?\$[0-9]+\$[a-z0-9/.]+\$[a-z0-9/.]{27}$",
        vec!["PBKDF2-SHA1(Generic)"],
    );

    hash_patterns.insert(
        r"^\$pbkdf2-sha256\$[0-9]+\$[a-z0-9/.]+\$[a-z0-9/.]{43}$",
        vec!["PBKDF2-SHA256(Generic)"],
    );

    hash_patterns.insert(
        r"^\$pbkdf2-sha512\$[0-9]+\$[a-z0-9/.]+\$[a-z0-9/.]{86}$",
        vec!["PBKDF2-SHA512(Generic)"],
    );

    hash_patterns.insert(
        r"^\$p5k2\$[0-9]+\$[a-z0-9/+=-]+\$[a-z0-9/+-]{27}=$",
        vec!["PBKDF2(Cryptacular)"],
    );

    hash_patterns.insert(
        r"^\$p5k2\$[0-9]+\$[a-z0-9/.]+\$[a-z0-9/.]{32}$",
        vec!["PBKDF2(Dwayne Litzenberger)"],
    );

    hash_patterns.insert(
        r"^FSHP[0123]\|[0-9]+\|[0-9]+[a-z0-9/+=]+$",
        vec!["Fairly Secure Hashed Password"],
    );

    hash_patterns.insert(r"^\$PHPS\$.+\$[a-f0-9]{32}$", vec!["PHPS"]);

    hash_patterns.insert(
        r"^[0-9]{4}:[a-f0-9]{16}:[a-f0-9]{2080}$",
        vec!["1Password(Agile Keychain)"],
    );

    hash_patterns.insert(
        r"^[a-f0-9]{64}:[a-f0-9]{32}:[0-9]{5}:[a-f0-9]{608}$",
        vec!["1Password(Cloud Keychain)"],
    );

    hash_patterns.insert(r"^[a-f0-9]{256}:[a-f0-9]{256}:[a-f0-9]{16}:[a-f0-9]{16}:[a-f0-9]{320}:[a-f0-9]{16}:[a-f0-9]{40}:[a-f0-9]{40}:[a-f0-9]{32}$", vec!["IKE-PSK MD5"]);

    hash_patterns.insert(r"^[a-f0-9]{256}:[a-f0-9]{256}:[a-f0-9]{16}:[a-f0-9]{16}:[a-f0-9]{320}:[a-f0-9]{16}:[a-f0-9]{40}:[a-f0-9]{40}:[a-f0-9]{40}$", vec!["IKE-PSK SHA1"]);

    hash_patterns.insert(r"^[a-z0-9/+]{27}=$", vec!["PeopleSoft"]);

    hash_patterns.insert(
        r"^crypt\$[a-f0-9]{5}\$[a-z0-9/.]{13}$",
        vec!["Django(DES Crypt Wrapper)"],
    );

    hash_patterns.insert(
        r"^(\$django\$\*1\*)?pbkdf2_sha256\$[0-9]+\$[a-z0-9]+\$[a-z0-9/+=]{44}$",
        vec!["Django(PBKDF2-HMAC-SHA256)"],
    );

    hash_patterns.insert(
        r"^pbkdf2_sha1\$[0-9]+\$[a-z0-9]+\$[a-z0-9/+=]{28}$",
        vec!["Django(PBKDF2-HMAC-SHA1)"],
    );

    hash_patterns.insert(
        r"^bcrypt(\$2[axy]|\$2)\$[0-9]{2}\$[a-z0-9/.]{53}$",
        vec!["Django(bcrypt)"],
    );

    hash_patterns.insert(r"^md5\$[a-f0-9]+\$[a-f0-9]{32}$", vec!["Django(MD5)"]);

    hash_patterns.insert(r"^\{PKCS5S2\}[a-z0-9/+]{64}$", vec!["PBKDF2(Atlassian)"]);

    hash_patterns.insert(r"^md5[a-f0-9]{32}$", vec!["PostgreSQL MD5"]);

    hash_patterns.insert(r"^\([a-z0-9/+]{49}\)$", vec!["Lotus Notes/Domino 8"]);

    hash_patterns.insert(
        r"^SCRYPT:[0-9]{1,}:[0-9]{1}:[0-9]{1}:[a-z0-9:/+=]{1,}$",
        vec!["scrypt"],
    );

    hash_patterns.insert(
        r"^\$8\$[a-z0-9/.]{14}\$[a-z0-9/.]{43}$",
        vec!["Cisco Type 8"],
    );

    hash_patterns.insert(
        r"^\$9\$[a-z0-9/.]{14}\$[a-z0-9/.]{43}$",
        vec!["Cisco Type 9"],
    );

    hash_patterns.insert(r"^\$office\$\*2007\*[0-9]{2}\*[0-9]{3}\*[0-9]{2}\*[a-z0-9]{32}\*[a-z0-9]{32}\*[a-z0-9]{40}$", vec!["Microsoft Office 2007"]);

    hash_patterns.insert(r"^\$office\$\*2010\*[0-9]{6}\*[0-9]{3}\*[0-9]{2}\*[a-z0-9]{32}\*[a-z0-9]{32}\*[a-z0-9]{64}$", vec!["Microsoft Office 2010"]);

    hash_patterns.insert(r"^\$office\$\*2013\*[0-9]{6}\*[0-9]{3}\*[0-9]{2}\*[a-z0-9]{32}\*[a-z0-9]{32}\*[a-z0-9]{64}$", vec!["Microsoft Office 2013"]);

    hash_patterns.insert(
        r"^\$fde\$[0-9]{2}\$[a-f0-9]{32}\$[0-9]{2}\$[a-f0-9]{32}\$[a-f0-9]{3072}$",
        vec!["Android FDE ≤ 4.3"],
    );

    hash_patterns.insert(
        r"^\$oldoffice\$[01]\*[a-f0-9]{32}\*[a-f0-9]{32}\*[a-f0-9]{32}$",
        vec![
            "Microsoft Office ≤ 2003 (MD5+RC4)",
            "Microsoft Office ≤ 2003 (MD5+RC4) collider-mode #1",
            "Microsoft Office ≤ 2003 (MD5+RC4) collider-mode #2",
        ],
    );

    hash_patterns.insert(
        r"^\$oldoffice\$[34]\*[a-f0-9]{32}\*[a-f0-9]{32}\*[a-f0-9]{40}$",
        vec![
            "Microsoft Office ≤ 2003 (SHA1+RC4)",
            "Microsoft Office ≤ 2003 (SHA1+RC4) collider-mode #1",
            "Microsoft Office ≤ 2003 (SHA1+RC4) collider-mode #2",
        ],
    );

    hash_patterns.insert(r"^(\$radmin2\$)?[a-f0-9]{32}$", vec!["RAdmin v2.x"]);

    hash_patterns.insert(
        r"^\s[0-9]{4}[a-z0-9/+=]+$",
        vec!["SAP CODVN H (PWDSALTEDHASH) iSSHA-1"],
    );

    hash_patterns.insert(
        r"^\$cram_md5\$[a-z0-9/+=-]+\$[a-z0-9/+=-]{52}$",
        vec!["CRAM-MD5"],
    );

    hash_patterns.insert(r"^[a-f0-9]{16}:2:4:[a-f0-9]{32}$", vec!["SipHash"]);

    hash_patterns.insert(r"^[a-f0-9]{4,}$", vec!["Cisco Type 7"]);

    hash_patterns.insert(r"^[a-z0-9/.]{13,}$", vec!["BigCrypt"]);

    hash_patterns.insert(r"^(\$cisco4\$)?[a-z0-9/.]{43}$", vec!["Cisco Type 4"]);

    hash_patterns.insert(
        r"^bcrypt_sha256\$\$(2[axy]|2)\$[0-9]+\$[a-z0-9/.]{53}$",
        vec!["Django(bcrypt-SHA256)"],
    );

    hash_patterns.insert(
        r"^\$postgres\$.[^\*]+[*:][a-f0-9]{1,32}[*:][a-f0-9]{32}$",
        vec!["PostgreSQL Challenge-Response Authentication (MD5)"],
    );

    hash_patterns.insert(
        r"^\$siemens-s7\$\$[0-9]{1}\$[a-f0-9]{40}\$[a-f0-9]{40}$",
        vec!["Siemens-S7"],
    );

    hash_patterns.insert(r"^(\$pst\$)?[a-f0-9]{8}$", vec!["Microsoft Outlook PST"]);

    hash_patterns.insert(
        r"^sha256[:$][0-9]+[:$][a-z0-9/+]+[:$][a-z0-9/+]{32,128}$",
        vec!["PBKDF2-HMAC-SHA256(PHP)"],
    );

    hash_patterns.insert(r"^(\$dahua\$)?[a-z0-9]{8}$", vec!["Dahua"]);

    hash_patterns.insert(
        r"^\$mysqlna\$[a-f0-9]{40}[:*][a-f0-9]{40}$",
        vec!["MySQL Challenge-Response Authentication (SHA1)"],
    );

    hash_patterns.insert(r"^\$pdf\$[24]\*[34]\*128\*[0-9-]{1,5}\*1\*(16|32)\*[a-f0-9]{32,64}\*32\*[a-f0-9]{64}\*(8|16|32)\*[a-f0-9]{16,64}$", vec!["PDF 1.4 - 1.6 (Acrobat 5 - 8)"]);

    // get the hash from user *start*
    let args: Vec<String> = args().collect();
    let hash: String = if args.len() > 2 {
        args[2].clone()
    } else {
        "Nothing".to_string()
    };
    // get the hash from user *end*

    if hash == "Nothing".to_string() {
        println!("No hash was found at all.");
        return
    }
    let mut hashs_count: u8 = 0;
    // let hash_length: u16 = hash.len() as u16;
    // TODO: use the the hash length the to improve the results accurse

    println!("\nPossible hash types: ");
    for (pattern, names) in &hash_patterns {
        let regex: Regex = Regex::new(pattern).expect("Regex matching faild, \x1b[37;3mplease report at \x1b[0mhttps://github.com/MASTAR-LAST/HashID/issues");
        if regex.is_match(hash.as_str()) {
            for name in names {
                println!("\t[+] {}", name);
                hashs_count += 1
            }
        }
    }

    if hashs_count == 0 {
        println!("\n\x1b[41m\x1b[37;3mNo possible hashes found !\x1b[0m");
    }
}
