---
layout: post
title: "Synack 2021 Open Invitational CTF Crypto Writeup"
mini_title: "Synack 2021 Open Invitational CTF Crypto Writeup"
date: 2021-11-08
category: crypto
comments: true
author: "Pepe Berba"
sub_categories: [crypto, rsa, ecdsa nonce reuse, hash collision]
summary: Writeup for the crypto challenges of the 2021 Synack Red Team Five Open Invitational CTF
description: Writeup for the crypto challenges of the 2021 Synack Red Team Five Open Invitational CTF
sub_categories: [crypto, rsa, ecdsa nonce reuse, hash collision]
header-img-direct: https://go.synack.com/rs/738-OEX-476/images/redteamfive-invitational-banner-02.png
---


### Introduction

Recently, I participated in 2021 Synack Red Team Five Open Invitational CTF . I was able to finish all 25 challenges and placed 14th out of 333 teams. 

It's a bummer I didn't get into the top 10 to get the HTB VIP subscriptions, but better luck next time. 

![](/assets/posts/20211108/00_results.png)

As of now, I'll only have time to have a writeup of the crypto challenges. For this CTF there are 4 challenges which:
- **Weak RSA (Super Easy):** Basic attacks when the modulo N has known factors
- **Leakeyd (Easy):** How to factor module N with private key of RSA (known expondents e and d)
- **Spy (Easy):** Classic meet-in-the-middle attack similar to Triple DES with some guessing/fuzzing needed to find the plaintext.
- **Suspicious Signing (Medium/Hard):** The server's ECDSA's nonce is based on the message's MD5 hash. Sending two messages with hash collision will trick the server into reusing a nonce. Which allows us to use the well known ECDSA nonce reuse attack. 

For raw files of the challenges, you can find them in [pberba/ctf-solutions]( https://github.com/pberba/ctf-solutions/tree/master/20211107-synack)


### Crypto Challenges

#### Weak RSA (225 points, 157 solves)

##### Problem

In this you are just given:
- `pubkey.pem`: RSA public key file
- `flag.enc`: an encrypted flag.

##### Solution

When these are all that is given in CTF competitions, it should be clear that it is really trying to "crack" the RSA public key to recover the private key. 

For these types of questions, always to use [RsaCtfTool](https://github.com/Ganapati/RsaCtfTool) which has a suite of well known attacks on weak RSA keys. If it fails, then we can start analyzing the problem deeper.

```
/opt/RsaCtfTool/RsaCtfTool.py --publickey "pubkey.pem" --uncipherfile flag.enc
```


#### leaky (440 points, 44 solves)

##### Problem

You are given the following source code

```python
from Crypto.Util.number import getPrime, bytes_to_long
from math import gcd

flag = open("flag.txt").read().strip().encode()

p = getPrime(1024)
q = getPrime(1024)
n = p * q
e1 = 0x10001
e2 = 0x13369

print(e1, e2)


assert gcd(p-1,e1) == 1 and gcd(q-1, e1) == 1 and gcd(p-1,e2) == 1 and gcd(q-1, e2) == 1

phi = (p-1) * (q-1)
d1 = pow(e1, -1, phi)
print(f"""Retrieved agent data:
n = {n}
e = {e1}
d = {d1}""")


ct = pow(bytes_to_long(flag), e2, n)
print(f"""Spy messages: 
e = {e2}
ct = {ct}""")
```

And the output of this message. 

```
Retrieved agent data:
n = 13382530295713917123015356265347321094256226566257623545889573061147938007171086142592829334764528434702825531635566369283255332692678671260069812638573184350572810970644394853227367978599113205187410151008372135364394060295976954722797560959041525038250922497629995447141186387045145641624575553004116393538045115640382007521177506372844356599515221123769808759792921557288910541261662071330605482964244218808384883839567178211155363863011452476524600201011039875767940325127282609196357565459539854467622590648672354346990722180911082058098493886116049202007545709584770864598362673608862923836981014279206273097017
e = 65537
d = 11569455444932772576648367415079245594982518040054082958680004127416877055866142769229969703359760929755598958930190874633423572023464427060332872186341753191857337442586174582207855332582641194737450361411604871225045984226459287130693565601375936121842940123452710408534497128602222588204605057938374149336484991344046184969452360503325068483025278799356513681880021469192847751113510298088839230617951595758843109007278029595681232283778797485901135862107038739149351060518772094867682593519162349240597142862357240797932956424470777291496596508787661226345849862222655652073745922761860271975329314656555016312713
Spy messages:
e = 78697
ct = 4461852328415864419743101452420387961651156933673863713694420947402421429869721670364426655092362407263142072234174378248471219392117855386367222894744130407609532370830178750575600387702022233241268782964579737764081573978397550577590335855096601816184948403341545535505335757184765869011562485472974997984468216491217981788679749360213892759733091674873206632032015518889157979003123181968736952658371579666643477038906444823824649861271863876401740198790710014620615022343576676868923683803704170440327497263852960257492740456717562069360762813846260931117680928543379201453514283942164106220549947266176556883803
```
##### Solution

For this, we have two RSA keys, `K1` and `K2` that have a common modulo `N`. We are given the private key of `K1` through the value of `d1` 

```python
d1 = pow(e1, -1, phi) # private key of K1 
```

It is important to realize that if you have the value of `e1`, `d1`, and `N`, it is enough to help you factorize `N` into `p` and `q`.  Of course, with `p` and `q`, finding the private key of `K2` (which also uses the same `N`, `p` and `q`) should be trivial.

If you do not know how to do this, you would need to google something like "RSA Prime Factorization with Private Key" which leads you to a [stackexchange forum post](https://math.stackexchange.com/questions/634862/rsa-prime-factorization-for-known-public-and-private-key). 

##### Review of RSA

Recall these three fundamental equations from RSA


$$ N = pq  \tag{1}$$  

$$ (p-1)(q-1) = \phi  \tag{2}$$  

$$ d_1 \equiv  e_1^{-1} \mod \phi  \tag{3} $$  


We express `(3)` as equality with some integer `k`

$$ d_1 \equiv  e_1^{-1} \mod \phi $$

$$ d_1 * e_1 \equiv  1 \mod \phi $$

$$ d_1 * e_1 =  1  + k * \phi $$  

$$ d_1 * e_1 - 1 =   k * \phi $$  

$$ d_1 * e_1 - 1 =   k * \phi $$  


$$ \frac{d_1 * e_1 - 1}{\phi} =   k \tag{4}$$  


How do we find `k` if `phi` is unknown? Well we know that since `p` and `q` are large, then


$$ (p-1)(q-1) \approx p * q $$
$$ \phi \approx N $$

Therefore we can approximate k from `(4)` using `N`, which we know,

$$ \frac{d_1 * e_1 - 1}{N} \approx   k \tag{5} $$  

Since `phi < N` then `K`, and if `N` is large enough, then K is most probably `ceil(d_1 * e_1 - 1 / N)`.


In python, we can find this using

```python
k = (e1*d1) // n + 1
assert (e1 * d1 - 1) % k == 0 # To check that we are correct
```


Now that we have `K`, `N`, `e1` and `e2`, we have a system of two equations with only two unknowns, `p` and `q`.

$$ N = pq  \tag{1}$$  

$$ d_1 * e_1 - 1 =   k * (p-1) * (q-1) $$  

Two equations and two unknowns? This is high school algebra.

Here are some of my scratch notes from this
```python
# First we find (p+q)
e1*d1 = (p-1)*(q-1) * k + 1
(e1 * d1 - 1) / k = (p-1)*(q-1)
(e1 * d1 - 1) / k = p*q - q - p + 1
(e1 * d1 - 1) / k = N - q - p + 1
(e1 * d1 - 1) / k - 1 - N  = - q - p
p + q = N + 1 - (e1 * d1 - 1) / k  = X

# Then we use isolate `p and substitute it in N = pq
p = X - q
n = q * (X - q)
0 = X*q - q*q - n
q*q - X*q + n = 0

# Quadratic equation
```
The python code to compute this is

```python
X = n + 1 - (e1*d1 - 1) // k
a = 1
b = X
c = n
p = -(-b + gmpy2.isqrt(b**2 - 4*a*c)) // (2*a)
q = n // p

# Always sense check values 
assert n % p == 0
assert (p*q) == n 
assert isPrime(p) 
assert isPrime(q)
```

With `p` and `q` you should be able to find the private key of `k2` and decrypt the flag.

##### Full Solution

```python
import gmpy2
from math import gcd

from Crypto.Util.number import isPrime, long_to_bytes, inverse

n = 13382530...
e1 = 65537
d1 = 115694...
e2 = 78697
ct = 4461852...

# Step 0 find k
k = (e1*d1) // n + 1
assert (e1 * d1 - 1) % k == 0

# Step 1 find p and q
X = n + 1 - (e1*d1 - 1) // k
a = 1
b = X
c = n
p = -(-b + gmpy2.isqrt(b**2 - 4*a*c)) // (2*a)
q = n // p


assert n % p == 0
assert (p*q) == n 
assert isPrime(p) 
assert isPrime(q)

# Step 2 decrypt flag
phi = (p-1)*(q-1)
pt = pow(ct, d2, n)
print(long_to_bytes(pt))


# HTB{tw4s_4-b3d_1d34_t0_us3-th4t_m0dulu5_4g41n-w45nt_1t...}
```

#### spy (475 points, 26 solves)

##### Problem 

Here is the source code given but I have removed some code to make it more readable.


Some things to look at:
- `keygen` function, how many bytes are truly random?
- In encryption, AES is doubled but is key strength doubled?

```python
from Crypto.Cipher import AES
import random
import time
import base64

BIT_SIZE = 256
BYTE_SIZE = 32

... 

def keygen():
    random.seed(BYTE_SIZE)
    h = random.getrandbits(BIT_SIZE)
    for i in range(BIT_SIZE):
        random.seed(time.time())
        h = h ^ random.getrandbits(2*BIT_SIZE/BYTE_SIZE)
    return hex(h)[2:-1]

def encrypt(data, key1, key2):
    cipher = AES.new(key1, mode=AES.MODE_ECB)
    ct = cipher.encrypt(pad(data))
    cipher = AES.new(key2, mode=AES.MODE_ECB)
    ct = cipher.encrypt(ct)
    return ct

...

if __name__ == "__main__":
   
    #message = [REDUCTED]
    #flag = [REDUCTED]

    key1 = keygen()
    key2 = keygen()
    
    key1 = key1.decode('hex')
    key2 = key2.decode('hex')

    ct_message = encrypt(message, key1, key2)
    ct_flag = encrypt(flag, key1, key2)
    with open('packet_6.txt.enc', 'w') as f:
        f.write(base64.b64encode(ct_message))

    with open('flag.txt.enc', 'w') as f:
        f.write(base64.b64encode(ct_flag))
```

You are given the ciphertext as well as sample plaintexts for the packets.

```
Plantext packet 3:
'''
Report Day 49:
    Mainframe: Secure
    Main Control Unit: Secure
    Internal Network: Secure
    Cryptographic Protocols: Secure
    
'''

Plantext packet 4:
'''
Report Day 50:
    Mainframe: Secure
    Main Control Unit: Secure
    Internal Network: Secure
    Cryptographic Protocols: Secure
    
''' 

Plantext packet 5:
'''
Report Day 51:
    Mainframe: Secure
    Main Control Unit: Secure
    Internal Network: Secure
    Cryptographic Protocols: Insecure
    
'''    
```

##### Key Generation

Look at the code for key generation

```python
def keygen():
    random.seed(BYTE_SIZE)
    h = random.getrandbits(BIT_SIZE)
    for i in range(BIT_SIZE):
        random.seed(time.time())
        h = h ^ random.getrandbits(2*BIT_SIZE/BYTE_SIZE)
    return hex(h)[2:-1]
```

Notice that the initial value of `h` is _not random_ since the seed is static.

```python
random.seed(BYTE_SIZE)
h = random.getrandbits(BIT_SIZE)
```

Also, notice that the code in the loop only modifies the last 16 bits of `h`

```python
h = h ^ random.getrandbits(2*BIT_SIZE/BYTE_SIZE) # only touches the last 16 bits of h
```

Therefore, we only have to brute force 16 bits per key.

##### Double AES / Triple DES

```python
def encrypt(data, key1, key2):
    cipher = AES.new(key1, mode=AES.MODE_ECB)
    ct = cipher.encrypt(pad(data))
    cipher = AES.new(key2, mode=AES.MODE_ECB)
    ct = cipher.encrypt(ct)
    return ct
```

This way of encrypting the plaintext twice does not double the strenght of the encryption. This is very similar to the classic [Triple DES](https://en.wikipedia.org/wiki/Triple_DES#Security).

This is vulnerable to the "meet in the middle attack" which is possible if we have known plaintext and ciphertext pair.

##### "Guessing" the plaintext

The example plaintexts is not really clear on the exact formating of the packet plaintext.  

```
'''
Report Day 51:
    Mainframe: Secure
    Main Control Unit: Secure
    Internal Network: Secure
    Cryptographic Protocols: Insecure
    
'''    
```

Do I include the ticks? Do I add a newline at the end? Etc...

In the end, I just created a template of the plaintexts and tried to iterate on the different guesses of the plaintex.

I used the following template and 
```python
msg = f"""{prefix}Report Day {day}:
    Mainframe: {s1}
    Main Control Unit: {s2}
    Internal Network: {s3}
    Cryptographic Protocols: {s4}
    {suffix}"""
```

So all in all, just brute force using meet-in-the-middle attack on the 16 random bits of key1 and key2, while guessing the proper plaintext  

##### Full Solution

Here is the full solution. The nested for-loops is an eyesore but it gets the job done.

```python
random.seed(BYTE_SIZE)
key = random.getrandbits(BIT_SIZE)

key_low = key - (key % (1<<16))
key_high = key_low + (1<<16)



ct = {}
for day in [52, 53, 54, 55]:
    for s1 in ['Insecure', 'Secure']:
        for s2 in ['Insecure', 'Secure']:
            for s3 in ['Insecure', 'Secure']:
                for s4 in ['Insecure', 'Secure']:
                    for prefix in ['', '\n']:
                       for suffix in ['', '\n']: 
                        msg = f"""\
{prefix}Report Day {day}:
    Mainframe: {s1}
    Main Control Unit: {s2}
    Internal Network: {s3}
    Cryptographic Protocols: {s4}
    {suffix}"""
                        msg = pad(msg).encode()
                        for k1 in range(key_low, key_high):
                            cipher = AES.new(long_to_bytes(k1), mode=AES.MODE_ECB)
                            _ct = cipher.encrypt(msg)
                            ct[_ct] = k1



with open('packet_6.txt.enc') as f:
    msg_ct = base64.b64decode(f.read())

for k2 in range(key_low, key_high):
    cipher = AES.new(long_to_bytes(k2), mode=AES.MODE_ECB)
    _ct = cipher.decrypt(msg_ct)
    if _ct in ct:
        print(ct[_ct], k2)
        k1 = ct[_ct]
        k2 = k2
        break

# k1, k2 = 27534775351079738483622454743638381042593424795345717535038924797978770229648, 27534775351079738483622454743638381042593424795345717535038924797978770265131


with open('flag.txt.enc') as f:
    ciphertext = base64.b64decode(f.read())

p1 = AES.new(long_to_bytes(k2), mode=AES.MODE_ECB).decrypt(ciphertext)
p2 = AES.new(long_to_bytes(k1), mode=AES.MODE_ECB).decrypt(p1)

print(p2)
```

#### Suspicious Signing (650 point, 21 solves)

##### Problem 

You are given the following source code and you would have to interact with a server to get the flag.

```python
from hashlib import md5
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from ecdsa import ellipticcurve
from ecdsa.ecdsa import curve_256, generator_256, Public_key, Private_key
from random import randint
from os import urandom

flag = open("flag.txt").read().strip().encode()
G = generator_256
order = G.order()

def genKey():
    d = randint(1,order-1)
    pubkey = Public_key(G, d*G)
    privkey = Private_key(pubkey, d)
    return pubkey, privkey
    
def ecdsa_sign(msg, privkey):
    hsh = md5(msg).digest()
    nonce = md5(hsh + long_to_bytes(privkey.secret_multiplier)).digest() * 2
    sig = privkey.sign(bytes_to_long(msg), bytes_to_long(nonce))
    return msg, sig.r, sig.s

def encryptFlag(privkey, flag):
    key = md5(long_to_bytes(privkey.secret_multiplier)).digest()
    iv = urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(flag, 16))
    return ciphertext, iv
    
pubkey, privkey = genKey()
ct, iv = encryptFlag(privkey, flag)
print(f"""Encrypted flag: {ct.hex()}
iv: {iv.hex()}""")
while True:
    msg = input("Enter your message in hex: ")
    try:
        msg = bytes.fromhex(msg)
        m, r, s = ecdsa_sign(msg, privkey)
        print(f"""Message: {m.hex()}
r: {hex(r)}
s: {hex(s)}""")
    except:
      print("An error occured when trying to sign your message.")
```

##### Initial Analysis

Notice that in the `encryptFlag` the AES key is generated from the secret exponent of the ECDSA key `privkey.secret_multiplier`. 

Therefore, the main objective is to try to somehow recover the private key of the ECDSA. 


A big clue here is that the `nonce` used in the encryption is not really a `nonce`. 


```python
def ecdsa_sign(msg, privkey):
    hsh = md5(msg).digest()
    nonce = md5(hsh + long_to_bytes(privkey.secret_multiplier)).digest() * 2
    ...
```

Problems like this are usually using [the famous attack on the playstation 3 crypto implementation](
https://arstechnica.com/gaming/2010/12/ps3-hacked-through-poor-implementation-of-cryptography/).   

These attacks are able to recover the private key if the nonce is reused for two different signatures.

This attack is well documented:
- http://koclab.cs.ucsb.edu/teaching/ecc/project/2015Projects/Schmid.pdf
- https://github.com/bytemare/ecdsa-keyrec

##### Hash Collision

This attack is not as straightforward because the nonce uses the hash of the message when being generated. 

You might think that since it is derived from the hash of the message, it should be random right? 

No. We can trick server into using the same hash for two messages by using hash collision.

Because the hash used is `MD5` which is part of a family of hashing that uses the [Merkle–Damgård construction](https://en.wikipedia.org/wiki/Merkle%E2%80%93Damg%C3%A5rd_construction) we can easily generate hash collisions by sending two messages with the same MD5 hash.

[Wikipedia even an example of hash collision that you can use for this problems](https://en.wikipedia.org/wiki/MD5#Collision_vulnerabilities). 

So get the signature for the message

```
d131dd02c5e6eec4 693d9a0698aff95c 2fcab58712467eab 4004583eb8fb7f89
55ad340609f4b302 83e488832571415a 085125e8f7cdc99f d91dbdf280373c5b
d8823e3156348f5b ae6dacd436c919c6 dd53e2b487da03fd 02396306d248cda0
e99f33420f577ee8 ce54b67080a80d1e c69821bcb6a88393 96f9652b6ff72a70
```

and then get the signature for 

```
d131dd02c5e6eec4 693d9a0698aff95c 2fcab50712467eab 4004583eb8fb7f89
55ad340609f4b302 83e4888325f1415a 085125e8f7cdc99f d91dbd7280373c5b
d8823e3156348f5b ae6dacd436c919c6 dd53e23487da03fd 02396306d248cda0
e99f33420f577ee8 ce54b67080280d1e c69821bcb6a88393 96f965ab6ff72a70
```

and validate the the nonce are the same.

The output of the server should be

```
Encrypted flag: 248005ebc638b16a0208f6c7949f1c68a147f906aa2e749985cdde5e51d230f87af2d19ec0ce1ddfb8808585dd54257bc86d456d4ca1cc8920667e792ad5c4f1
iv: d39a60befaeb2cb45ce8d2181371a387



Enter your message in hex: d131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f8955ad340609f4b30283e488832571415a085125e8f7cdc99fd91dbdf280373c5bd8823e3156348f5bae6dacd436c919c6dd53e2b487da03fd02396306d248cda0e99f33420f577ee8ce54b67080a80d1ec69821bcb6a8839396f9652b6ff72a70

Message: d131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f8955ad340609f4b30283e488832571415a085125e8f7cdc99fd91dbdf280373c5bd8823e3156348f5bae6dacd436c919c6dd53e2b487da03fd02396306d248cda0e99f33420f577ee8ce54b67080a80d1ec69821bcb6a8839396f9652b6ff72a70
r: 0x557a787642ece2fe307b7de417d7d3c7bfe92313020a58e49771be515c4cadc
s: 0x8d1c17fb248fb8b0af29d64365fae1b495c4eb6340ce027f9f3625564a945cda



Enter your message in hex: d131dd02c5e6eec4693d9a0698aff95c2fcab50712467eab4004583eb8fb7f8955ad340609f4b30283e4888325f1415a085125e8f7cdc99fd91dbd7280373c5bd8823e3156348f5bae6dacd436c919c6dd53e23487da03fd02396306d248cda0e99f33420f577ee8ce54b67080280d1ec69821bcb6a8839396f965ab6ff72a70

Message: d131dd02c5e6eec4693d9a0698aff95c2fcab50712467eab4004583eb8fb7f8955ad340609f4b30283e4888325f1415a085125e8f7cdc99fd91dbd7280373c5bd8823e3156348f5bae6dacd436c919c6dd53e23487da03fd02396306d248cda0e99f33420f577ee8ce54b67080280d1ec69821bcb6a8839396f965ab6ff72a70
r: 0x557a787642ece2fe307b7de417d7d3c7bfe92313020a58e49771be515c4cadc
s: 0xda91bba782f6e63aadd53f74bd989f194664a8273d431d4e104b55e01d355296
```

##### Recovering private key 

I just used the relevant code from  [bytemare/ecdsa-keyrec](https://github.com/bytemare/ecdsa-keyrec)


```python
def decryptFlag(secret_exponent, iv, flag):
    key = md5(long_to_bytes(secret_exponent)).digest()
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.decrypt(flag)

order = generator_256.order()

ciphertext = bytes.fromhex('248005ebc638b16a0208f6c7949f1c68a147f906aa2e749985cdde5e51d230f87af2d19ec0ce1ddfb8808585dd54257bc86d456d4ca1cc8920667e792ad5c4f1')
iv = bytes.fromhex('d39a60befaeb2cb45ce8d2181371a387')
m1 = bytes.fromhex('d131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f8955ad340609f4b30283e488832571415a085125e8f7cdc99fd91dbdf280373c5bd8823e3156348f5bae6dacd436c919c6dd53e2b487da03fd02396306d248cda0e99f33420f577ee8ce54b67080a80d1ec69821bcb6a8839396f9652b6ff72a70')
r1 = 0x557a787642ece2fe307b7de417d7d3c7bfe92313020a58e49771be515c4cadc
s1 = 0x8d1c17fb248fb8b0af29d64365fae1b495c4eb6340ce027f9f3625564a945cda
m2 = bytes.fromhex('d131dd02c5e6eec4693d9a0698aff95c2fcab50712467eab4004583eb8fb7f8955ad340609f4b30283e4888325f1415a085125e8f7cdc99fd91dbd7280373c5bd8823e3156348f5bae6dacd436c919c6dd53e23487da03fd02396306d248cda0e99f33420f577ee8ce54b67080280d1ec69821bcb6a8839396f965ab6ff72a70')
r2 = 0x557a787642ece2fe307b7de417d7d3c7bfe92313020a58e49771be515c4cadc
s2 = 0xda91bba782f6e63aadd53f74bd989f194664a8273d431d4e104b55e01d355296

# Validate the the nonce are the same for two different signatures
assert r1 == r2
assert s1 != s2

h1 = bytes_to_long(m1)
h2 = bytes_to_long(m2)


r = r1

r_inv = inverse_mod(r, order)
h = (h1 - h2) % order

for k_try in (s1 - s2,
              s1 + s2,
              -s1 - s2,
              -s1 + s2):

    k = (h * inverse_mod(k_try, order)) % order
    secexp = (((((s1 * k) % order) - h1) % order) * r_inv) % order
    print(decryptFlag(secexp, iv, ciphertext))

# b'HTB{r3u53d_n0nc35?n4h-w3_g0t_d3t3rm1n15t1c-n0nc3s!}\r\r\r\r\r\r\r\r\r\r\r\r\r'
```