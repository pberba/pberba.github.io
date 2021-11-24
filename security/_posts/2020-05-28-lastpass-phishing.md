---
layout: post
title: 'Bypassing LastPass’s “Advanced” YubiKey MFA: A MITM Phishing Attack'
date: 2020-05-28
category: security
sub_categories: [phishing, crypto]
comments: true
author: "Pepe Berba"
summary: How to deploy a phishing attack on LastPass users, even when they are protected with Yubikey physical keys, and why U2F helps us prevent phishing
description: How to deploy a phishing attack on LastPass users, even when they are protected with Yubikey physical keys. This is to appreciate what is U2F and why it is important. I will also give an overview of how LastPass encrypts and handles your vault
tags: [lastpass, u2f, security key, phishing, cyber security, 2fa, cryptography]
header-img-direct: https://cdn-images-1.medium.com/max/1200/1*ZuEG5yZkFwBjXBzoi6mFkQ.jpeg
---

<br/>

I’ll say it upfront for the techy people: (un)fortunately, **this is NOT a MITM attack of U2F**\*. LastPass doesn’t support U2F so this is disappointingly simple. It uses Yubico OTP, which is phishable.

In this article, I demonstrate how to deploy a phishing attack on LastPass users, even when they are protected with Yubikey physical keys. I hope that this helps you appreciate that YubiKey ≠ U2F. Aside from that, I will give an overview of: 
- what is U2F, and why it is important
- how LastPass encrypts and handles your vault

_\*U2F stands for “Universal 2nd Factor”. This is the protocol that is likely used whenever you hear about security keys. _

#### Use security keys to prevent phishing

![[Google’s transparency report](https://transparencyreport.google.com/safe-browsing/overview?unsafe=dataset:0;series:malwareDetected,phishingDetected;start:1148194800000;end:1587279600000&lu=unsafe) \[1\]](https://cdn-images-1.medium.com/max/800/1*8jei3TihbLKEG0vjuLGtew.png)
*[Google’s transparency report](https://transparencyreport.google.com/safe-browsing/overview?unsafe=dataset:0;series:malwareDetected,phishingDetected;start:1148194800000;end:1587279600000&lu=unsafe) \[1\]*

In recent years, phishing has proven to be one of the most effective ways of hacking people. Instead of using a fancy new exploit to steal a victim’s credentials, the hacker just asks the victims to hand their credentials over.

Moreover, with the new remote working conditions, we are more at risk of phishing attacks. This results in headlines such as ["Phishing Attacks Increase 350 Percent Amid COVID-19 Quarantine (2020)"](https://sea.pcmag.com/security/36691/phishing-attacks-increase-350-percent-amid-covid-19-quarantine) \[2\].

How do we combat this? Aside from educating employees on phishing attacks, security keys are an effective way to mitigate this increased risk. We see success stories such as (2018, [Google: Security Keys Neutralized Employee Phishing](https://krebsonsecurity.com/2018/07/google-security-keys-neutralized-employee-phishing/)):

> “We have had no reported or confirmed account takeovers since implementing security keys at Google” \[3\]

**In a phishing attack, the weak point is the human user.** The user has the responsibility to distinguishing legitimate vs malicious sites. **By using security keys and protocols such as U2F, you relieve some of this burden from the user.** Using U2F, authentication “magically” doesn’t work when it is a malicious site, even when the victim is tricked.

Below we see LastPass endorsing the use of YubiKeys. In the diagram, we see that YubiKey is more secure, easy to use, and not phishable.

![](https://cdn-images-1.medium.com/max/800/1*JBB9n3hJZxZoTYBqD_IP0w.png)

With that said, I recently got myself some Yubikeys. To use this “Advanced Multi-factor Option” with Lastpass, I needed a premium account. Being a long time user of Lastpass, I didn’t think twice and paid to upgrade to premium. 

Within minutes, I felt shortchanged. It quickly became obvious that using a Yubikey did not make my LastPass vault any more secure against phishing. 

Why? Lastpass’s integration with Yubico using **_Yubico OTP and not U2F. _**

Here’s a list of levels of auth from the _“the Hierarchy of Auth”_ [\[18\]](https://www.troyhunt.com/beyond-passwords-2fa-u2f-and-google-advanced-protection/) from least secure to most secure:

1.  Password alone
2.  Password and SMS
3.  Password and soft token (LastPass + Google Authenticator)
4.  Password and hard token (LastPass + Yubico OTP)
5.  **Password and U2F (Security Keys)**

(3) and (4) give similar protections against phishing. (5) mitigates phishing best. So although we are using a Yubikey, we aren’t using it as a security key\*.

_Is this important and is U2F really THAT more secure?_

Let me show you why this is important.

_\*Let’s reserve the term “security key” only when using U2F. So a YubiKey 5 can be used both in an OTP mode and security key mode._

### How to deploy phishing campaign

Let’s take a red team mindset to appreciate why phishing is so effective and how easy it is for us to fall for it. We use a reverse proxy to do a “man-in-the-middle” (MITM) attack to steal the credentials and bypass 2 Factor Authentication (2FA).

Here’s an overview of how a MITM attack works. 

![We’re nice people. We will log-in LastPass for you](https://cdn-images-1.medium.com/max/800/1*tBGvXDJ86Vgkm0QPKU_KDA.png)
*We’re nice people. We will log-in LastPass for you 😊*

Of course, phishing using MITM applies to many other sites. What makes LastPass unique is that it is the only site that I personally use that is still vulnerable to MITM even when using a Yubikey.

#### Information Gathering

Let’s say you have to target an individual or a company. You first try to get a small collection of email addresses from searching through LinkedIn, Github, Twitter, blogs, and other [OSINT sources.](https://osintframework.com/)

Now with these target emails, you explore the options available for your attack. The LastPass vault is a gold mine of credentials since one phishing attack can result in many credentials. Let’s see if these emails are possible LastPass users.

![google@gmail.com uses Lastpass?](https://cdn-images-1.medium.com/max/1200/1*oSRXFfUNTYvcO7-9wbnyuA.png)
*google@gmail.com uses Lastpass?*

Since the registration processes would check the availability of an email address, we can use it to gather more intel. If the email address is taken, then it is likely that the owner uses LastPass.

![](https://cdn-images-1.medium.com/max/1200/1*QwVGvFSvUVQlAYkvGcjKhw.png)

If you want to enumerate a small list of potential targets, then you can use this simple API which returns ok/no.

```
GET https://lastpass.com/create_account.php?check=avail&skipcontent=1&mistype=1&username=google%40gmail.com
```

For targeted attacks, this is an effective way to check whether or not you can be phished on LastPass. Broader random attacks would be unlikely if the availability endpoint is rate limited.

#### Getting the right domain

Having a legitimate-looking domain might make it easier to trick the victim. There are a lot of ways that we can gain a legitimate-looking domain. Maybe slight modifications of the spelling or explore other TLDs. We chose `lastpass.com.es`

![As of 2020/05/25](https://cdn-images-1.medium.com/max/800/1*_JWMEckSw6ijACvtwABIKA.png)
*As of 2020/05/25*

Here are other examples of possible phishing domains for LastPass.

![As of 2020/05/25](https://cdn-images-1.medium.com/max/800/1*BgDfnRnQ8PF6UY3W-gdkiA.png)
*As of 2020/05/25*

These are domains that are affordable for a red team and individual hackers. 

I hope you realize that in cases such as this one, a domain like `lastpass.com.es` is as suspicious as `lastpaazz.com` and `lastpass.club`.

#### Setting up the servers

To set up our phishing site I’ve prepared a [fork of evilginx2](https://github.com/pberba/evilginx2), which has some additional logic to steal the credentials from LastPass.

This is a golang application, so you would need to install golang and run the following commands:

<script src="https://gist.github.com/pberba/fe7bba9dcd5bfbaceed0ef36a79a9509.js"></script>

It is surprising how mature the phishing tools are. The development of this only took around just a day. It is easy to set up phishing sites for your bank, or company website, complete with domain and SSL.

![](https://cdn-images-1.medium.com/max/800/1*E0EMVroZkVYm9dbRNTSIgQ.png)

You can set this up on your favorite cloud hosting provider. After setting up the binaries of _evilginx2._ You run it and then configure the LastPass phishlet.

```bash
$ sudo ./bin/evilginx -p ./phishlets/ -developer

> config ip 127.0.0.1  
> config domain lastpass.com.es

> phishlets hostname lastpass lastpass.com.es  
> phishlets enable lastpass
```

And then you create the link you want to bait them. The `redirect_url` is the page you want the victim to end up once you get all the necessary credentials.

``` bash
> lures create lastpass  
> lures edit redirect_url 0 [https://www.youtube.com/watch?v=dQw4w9WgXcQ](https://www.youtube.com/watch?v=dQw4w9WgXcQ)  
> lures get-url 0
```

![](https://cdn-images-1.medium.com/max/800/1*8m8tlF4QxxiU87_jYXdPpQ.png)

In our case, we want our victim to go `https://lastpass[.]com[.]es/QBFlGqJy`

Note: For this to work locally you might need to add the following to `/etc/hosts`

```bash
127.0.0.1 lastpass.com.es  
127.0.0.1 lp-cdn.lastpass.com.es  
127.0.0.1 www.lastpass.com.es
```

#### Sending the Phishing Email

Assuming that you use an existing phishlet, then we have to make a phishing email. This is really where a lot of the work comes in. You have to somehow trick the user into clicking the link. Crafting a good phishing email is an art.

![](https://cdn-images-1.medium.com/max/800/1*ssc1naUhYfA6kPC6G_QonA.png)

In this case, we say that we have revoked trusted devices so that hopefully, he won’t be surprised just in case he gets alerts of new log-ins.

#### Waiting for the credentials

When the victim clicks on the link, he will be redirected to the fake LastPass login.

![Notice lastpass.com.es](https://cdn-images-1.medium.com/max/800/1*Sn7hQ739Z9T4wthlcBymUg.png)
*Notice lastpass.com.es*

And when LastPass requires 2FA, then the fake website will ask the victim to provide the second factor.

![](https://cdn-images-1.medium.com/max/800/1*oEpo4ztAWvEFgoCbZOgEJg.png)

As [previous work](https://versprite.com/blog/application-security/reverse-proxy-attack/) \[4\] has mentioned, the victim will likely have to verify with their email because the logon activity is new. However, this might look less suspicious if we have already primed the victims to expect this by saying we’ve “revoked trusted devices”.

![Screenshot from [Versprite’s article](https://versprite.com/blog/application-security/reverse-proxy-attack/) \[4\]](https://cdn-images-1.medium.com/max/800/1*AFrkmKHksC6IO4B78C4evg.png)
*Screenshot from [Versprite’s article](https://versprite.com/blog/application-security/reverse-proxy-attack/) \[4\]*

Once the session is trusted, the victim’s browser will start to download the encrypted vault. We steal this using the proxy along with the username and password of the victim.

![](https://cdn-images-1.medium.com/max/800/1*jAXEAYqDL4WU1lPbzCwf3Q.png)

Afterward, the victim will be redirected a some chosen site. In this case, the victim will be [redirected to your chosen page.](https://www.youtube.com/watch?v=dQw4w9WgXcQ)

Meanwhile, we have all that we need to get all the victim’s credentials.

#### Decrypting the vault

To decrypt the LastPass Vault, you would need 3 main ingredients:

*   LastPass Username
*   LastPass Password
*   Encrypted Vault

![](https://cdn-images-1.medium.com/max/800/1*WcIJmdRs2_ZxtPbe9RZKIA.png)

With a MITM, we can steal the victim’s username and password, and once the session is trusted after OTP from the YubiKey, we can download the encrypted vault.

The original intention of the evilginx2 is to hijack the session. But I’ve found that it is easier to just dump the credentials in the vault. In theory, the proxy can get all necessary information to take takeover of the account.

In the project, I’ve provided a script `scripts/lastpass-python/dump_lastpass.py` This parses the evilginx2 DB and decrypts the credentials. The location of the DB depends on where the config file is. In my case it was `/var/root/.evilginx/data.db`

![](https://cdn-images-1.medium.com/max/800/1*wja3kBicR48eBBy2c1vKcQ.png)

This creates two files, one for credentials of the LastPass accounts, and the other is the credentials found in the vaults. You have everything in the vault, name, folder, username, password, URL, and secure notes associated with the item.

![creds-dump.csv](https://cdn-images-1.medium.com/max/800/1*U-ZDsURt9ZhgYTMKTYICMQ.png)
*creds-dump.csv*

You can easily leverage this to try to take control of as much of the accounts that you can. To maximize your impact, you can write a script to automatically check if there are recovery codes in the notes. With the passwords and the recovery codes, you will have full control of their accounts.

![Should we put all our eggs in one basket?](https://cdn-images-1.medium.com/max/800/1*ftmKGyeE8GaoxoVJEXnH5g.png)
*Should we put all our eggs in one basket?*

#### Quick Notes on Phishing

Again, this problem is not specific to LastPass. You can be phished on almost any site you use. Some of them would have fewer protections than LastPass. However, among the main password managers, I think LastPass is the only one who still doesn’t support U2F.

How do we detect a phishing email? 

It is trivial for an attacker to copy the design of an email. In our example, you might be able to detect it using the source domain. Although sometimes even the domain can be spoofed [if not configured properly.](https://support.google.com/a/answer/174124?hl=en)

Aside from the domain, the actual content is the only “fishy” thing.

![](https://cdn-images-1.medium.com/max/800/1*b4EF9NwWx23KVrJgOjHxBw.png)

As for the phishing website itself.  Gone are the days where phishing websites do not have SSL certificates [\[15\]](https://krebsonsecurity.com/2017/12/phishers-are-upping-their-game-so-should-you/)_._ _The only thing that would give it away is the domain._ Because of our MITM proxy, what the victim sees is the exact clone of the actual site. There would be no visual differences and it is practically undetectable in the short term.

![](https://cdn-images-1.medium.com/max/800/1*97OtOkvWNn225etGKT6jaA.png)

What are some ways you can protect yourself at this point?

**If you use your password manager’s browser extension, it will not give you the password because it doesn’t recognize the domain.**

The password manager looks solely at the domain of the site and doesn’t care whether or not it looks like FB, Twitter, Github, or Google. For example, `github.com` not the same as `giithub.com`. So if you are at `giithub.com` the password manager won’t give any credentials to give you.

![Why doesn’t my password manager show my Github credentials?!?! Is it broken?](https://cdn-images-1.medium.com/max/800/1*owX5Bl4Z8pzZHfJdmC0PLg.png)
*Why doesn’t my password manager show my Github credentials?!?! Is it broken?*

The special case for this would be your password manager yourself! It is one of the only sites that I manually input my password. So it is still a prime target for phishing.

### How can this happen?

> “I thought if we use security keys we can prevent phishing?”

Well that is only true if we are using U2F or some sort of challenge-response protocol. Unfortunately, as we’ve previously mentioned, LastPass’s integration with Yubikey is using the Yubico OTP.

The difference between Yubico OTP and U2F is subtle. In terms of user experience, they are very similar.

You are given a prompt, you insert your Yubikey, and you press the button. Now you’re in!

![“Insert your key and touch it”](https://cdn-images-1.medium.com/max/800/1*4d8i1lg12618LCdGvFkCOA.png)
*“Insert your key and touch it”*

When it comes to using NFC on mobile, the experience is exactly the same!

![U2F \[7\]](https://cdn-images-1.medium.com/max/800/1*qj-vBC5Xa0i_drN6Q0bTSQ.png)
*U2F \[7\]*

The user experiences here are comparable, however, the level of security is not! The differences here are all greatly invisible to us as end-users.

For this part we somewhat simplify our terminology. In the end, we want to generate some _“authentication code”,_ whether it is OTP or U2F. The way we generate this authentication code makes all the difference.

#### OTP Generation

Yubico OTP, Google Authenticator, SMS Codes, Email Codes, and RSA tokens, all generate their authentication codes in a linear fashion.

If we look at this slide from [\[5\]](https://jen.run/talks/why-u2f-is-awesome/why-u2f-is-awesome.pdf), the flow of information is always moving in one direction. The authentication code is generated independently of the identity of the destination.

![[Jen Tong, Security Keys are Awesome. ](https://jen.run/talks/why-u2f-is-awesome/why-u2f-is-awesome.pdf)\[5\]](https://cdn-images-1.medium.com/max/800/1*FrRKlahusFOuxf5xUYrFaw.png)
*[Jen Tong, Security Keys are Awesome. ](https://jen.run/talks/why-u2f-is-awesome/why-u2f-is-awesome.pdf)\[5\]*

In the same way that you can accidentally put the OTP from the wrong site when using Google Authenticator, you can also inadvertently give this OTP to the attacker.

If you look at how the Yubico OTP is generated \[16\], it is clear that the codes are generated independent of the identity of the destination. So that means whether or not the destination is the real site, the codes generated are always valid.

![[OTPs Explained](https://developers.yubico.com/OTP/OTPs_Explained.html) \[16\]](https://cdn-images-1.medium.com/max/800/1*JQ-Bykgs1t6s6OIhVSBblQ.png)
*[OTPs Explained](https://developers.yubico.com/OTP/OTPs_Explained.html) \[16\]*

The risk of phishing is always going to be high as long as:

*   The identity of the destination is not included in the generation of the authentication code
*   The generation and submission of the authentication code is not fully automated

For example, codes generated by Google Authenticator are specific to the destination site. However, since the user has to submit this manually, then there is room for human error. If we can somehow remove the human in the process and have the application submit the code only for the intended destination, then this would be more secure.

#### U2F and Security Keys

If the human is the biggest vulnerability in a phishing attack, then we should just remove the human in the process. 

This is what U2F tries to do. We relieve the human the burden of identifying between fake and real sites. This is going to be taken care of by the YubiKey and the browser working together.

If you look at the diagram below, we see a desirable end to end flow, and for the most part, this happens automatically end to end. In U2F, whenever the security key generates an authentication code, it is partly derived from the identity of the destination.

![](https://cdn-images-1.medium.com/max/800/1*yk4T3BC3bpampBcrT0xc_g.png)

We will start to oversimplify here. To make the “main idea” clear, there are details we will not show in the diagrams below, such so the “challenge” which is used to prevent replay attacks and it is proof of timeliness. 

Here is an even more simplified view of the diagram above. Notice that we have completely removed human in the drawing and that the authentication code uses the identity of the server it is talking to. This addresses our concerns with OTP codes.

![](https://cdn-images-1.medium.com/max/800/1*ChCHhOT-exWW0oV1lnYGHw.png)

So whenever an attacker tries to put himself between the victim and the site, the codes that will be generated will no longer be valid. For our phishing attack, the codes will be valid only for`lastpass.com.es` and not `lastpass.com` .

![](https://cdn-images-1.medium.com/max/800/1*BMBGxyCKmy8efcWU2qUwJw.png)

Since in step (2), the attacker asks for `lastpass.com.es` , the authentication produced in step (3) code cannot be used for `lastpass.com` . So why doesn’t the attacker just ask for authentication code for `lastpass.com` ?

This won’t be possible because the browser would not allow it.

![](https://cdn-images-1.medium.com/max/800/1*gNO_uTTbJ0atE5bgCs62CA.png)

The browser checks the certificates of the website, before it asks the security key to generate any codes. It makes sure doesn’t allow our fake website`lastpass.com.es` to get codes for `lastpass.com` . This makes it difficult for a hacker to do a MITM attack. The site not only has to look like the legitimate site, but it also has to have to correct certificates.

(Of course, if the hacker has legitimate certificates, maybe through access to a bad CA. Then a MITM attack can work.)

The tradeoffs between OTP and U2F are clearly listed in [\[13\]](https://www.yubico.com/blog/otp-vs-u2f-strong-to-stronger/) and [\[8\]](https://help.duo.com/s/article/2942?language=en_US).

### How LastPass decrypts your vault

Notes here are from [\[9\]](https://versprite.com/blog/application-security/password-database-compromised/#download), [\[10\]](https://enterprise.lastpass.com/wp-content/uploads/LastPass-Technical-Whitepaper-3.pdf), [\[11\]](https://github.com/konomae/lastpass-python/), [\[12\]](https://hackernoon.com/psa-lastpass-does-not-encrypt-everything-in-your-vault-8722d69b2032), and from my own experience setting up the phishing site.

![](https://cdn-images-1.medium.com/max/800/1*gJx-3CDlRnPteO0iZtC4-A.png)

If you want to check to know the specific requests that are important during log-in, I have highlighted them:

*   **login.php:** the username and master password
*   **getaccts.php:** the encrypted vault

![Proxy history of a LastPass log-in and vault decryption](https://cdn-images-1.medium.com/max/800/1*Q-KUGz-FD2qtzuZIrJW7mA.png)
*Proxy history of a LastPass log-in and vault decryption*

#### Getting the master password

Whenever you try to log-in, the username and password are used to derive the key used to decrypt the vault, and then plaintext password is erased.

It is nice to confirm that LastPass never sends the password to the server. For authentication, it sends a hash of the derived key.

If the master password is never sent over the wire, how does our MITM proxy get the master password? Answer: We inject some javascript in our login page to first copy the password field to another hidden field before the login logic starts.

<script src="https://gist.github.com/pberba/a9a5f5a34fd1b94c0c28e4719dc37ceb.js"></script>

When we inspect the traffic, we are looking for the `_password` form field which has the plaintext master password.

#### Deriving the AES keys

We use the username and password to derive the key used to encrypt and decrypt the Vault. ([source](https://github.com/konomae/lastpass-python/blob/1ece13f04bb6c20ba1d01e7bcfcad6a48ee6527f/lastpass/fetcher.py#L134-L139))

```python
key = hashlib.pbkdf2_hmac('sha256', password, username, 100100, 32)
```
Here, we hash `password` with the salt `username` with `100100` iterations. Having a lot of iterations make it harder to brute force the password.

#### Getting the authentication hash

You hash the AES key one more time to get the authentication hash ([source](https://github.com/konomae/lastpass-python/blob/1ece13f04bb6c20ba1d01e7bcfcad6a48ee6527f/lastpass/fetcher.py#L147-L153))

```python
auth_hash = hashlib.pbkdf2_hmac('sha256', key, password, 1, 32)
```

This is the hash that is sent along with the username and 2FA OTP in the `/login.php` request to authenticate.

#### Decrypting the chunks of the vault

Once authenticated, LastPass will try to download the vault. We intercept the encrypted vault in the `/getaccts.php` request. We process the vault by:

1.  decoding into bytes and divided into several chunks (one chunk is)
2.  each chunk can then be decomposed into the individual fields ([source](https://github.com/konomae/lastpass-python/blob/5063911b789868a1fd9db9922db82cdf156b938a/lastpass/parser.py#L26-L70))

If we display the individual fields, it would look something like this.

![[Screenshot from \[12\]](https://hackernoon.com/psa-lastpass-does-not-encrypt-everything-in-your-vault-8722d69b2032)](https://cdn-images-1.medium.com/max/800/1*42TGE2CU48TLl6XqsLCVCQ.png)
*[Screenshot from \[12\]](https://hackernoon.com/psa-lastpass-does-not-encrypt-everything-in-your-vault-8722d69b2032)*

Notice here that each field is encrypted. We use the key we derived from the username and password using **AES-CBC**. The first bytes of each field is the initialization vector.

#### Plaintext URLs

One notable thing here is that the **URL field is not encrypted,** which was pointed out by \[12\], and can be seen in [the python code \[11\].](https://github.com/konomae/lastpass-python/blob/5063911b789868a1fd9db9922db82cdf156b938a/lastpass/parser.py#L53)

![](https://cdn-images-1.medium.com/max/800/1*E3ivIg65jBpP39ZNi11D5w.png)

I don’t know why LastPass decided to keep the URLs in plaintext.

It might be a stretch but one guess is for the efficiency of the application. If the URLs, in plaintext, then I can search through the ciphertexts and only decrypt the account chunks I need. But does that really take that much time? You can always decrypt only the URLs first whenever you open the vault.

Another use case is to get some analytics of the sites that LastPass is stored. This would help them prioritize which sites to check whether or not password reset, autofill, and equivalent domains work? They can get an idea 

When asked about this by \[12\], LastPass responds:

> LastPass encrypts your Vault before it goes to the server using 256-bit AES encryption. Since the Vault is already encrypted before it leaves your computer and reaches the LastPass server, not even LastPass employees can see your sensitive data.


#### Key Takeaways

Here is what we can learn from this:

*   the master password is never sent to the server.
*   credentials are encrypted before they are sent to the server
*   decrypted is done on the client (desktop app or your browser)
*   **the URL is sent and stored in plaintext**

If LastPass was breached by just like [what happened in 2015](https://blog.lastpass.com/2015/06/lastpass-security-notice.html/) \[23\]then the hackers would have:

*   username
*   a hash of the master password and encryption keys
*   encrypted vault
*   All plaintext URLs that your account is associated with

Is there any risk to the users if a breach occurs? If you ask LastPass themselves then they would say no because the vault is encrypted and you shouldn’t be able to reverse the hash to get the decryption keys.

> “We are confident that our encryption measures are sufficient to protect the vast majority of users.” — LastPass \[23\]

This may be an unsatisfactory answer for you, and you might not really like the idea of someone else storing all your passwords, even if they are encrypted. If so, then you are probably using a self-hosted password manager.

Also, all these encryption breaks if you can just grab the passwords during a MITM phishing attack!

### Lastpass and U2F

To be clear, LastPass only supports OTP \[21\].

![[Works with Yubikey: LastPass](https://www.yubico.com/works-with-yubikey/catalog/lastpass-premium-and-families/) \[21\]](https://cdn-images-1.medium.com/max/800/1*pzqq43HKUIwXrFJwpkxREg.png)
*[Works with Yubikey: LastPass](https://www.yubico.com/works-with-yubikey/catalog/lastpass-premium-and-families/) \[21\]*

_Why did I mistakenly think that LastPass supports U2F?_

I think it boils down to naively associating YubiKey to security keys. But as I have learned, just because I’m using a YubiKey, doesn’t mean it’s U2F.

It doesn’t help that there were [pages like this](https://www.lastpass.com/yubico).

![](https://cdn-images-1.medium.com/max/800/1*JBB9n3hJZxZoTYBqD_IP0w.png)

The diagram suggests that using Yubikeys with Lastpass makes you less “phishable” and more secure, which is only true when using U2F.

If we update the page to be more accurate we should have something like.

![“Corrected” diagram](https://cdn-images-1.medium.com/max/800/1*LLbjsfEng91zSW2gNPqmsg.png)
*“Corrected” diagram*

Distinguishing between U2F and Yubico OTP makes it clear that the OTP is phishable. This is something we just demonstrated.

Here is another page which misled me:

![Immune to MITM? What am I missing?](https://cdn-images-1.medium.com/max/800/1*Kh8YDPTrfjXUlSjvA5DLbA.png)
*Immune to MITM? What am I missing?*

Technically, this is true when using U2F. But considering that LastPass doesn’t support security keys, I think that statement is misplaced.

I guess I’m not alone. Here are some articles that might have gotten it wrong: [\[17\]](https://portswigger.net/daily-swig/u2f-nowhere-near-ready-for-prime-time), [\[19\]](https://www.wired.com/story/how-to-use-a-yubikey/), and [\[20\]](https://www.zdnet.com/article/best-security-keys/). 

![](https://cdn-images-1.medium.com/max/800/1*3YPghlwNJ73QB9P2hV0cKw.png)
![](https://cdn-images-1.medium.com/max/800/1*VW37uuKw0fU1uSy-h0ObHA.png)
In the article below, it didn't mention explicitly that LastPass supports U2F, but the association is.

![](https://cdn-images-1.medium.com/max/800/1*RXLJIRkVw4lMvLP2UZTbLw.png)

> “If there’s one area where you’d expect U2F technology to be encouraged, it’s among password managers.” [\[17\]](https://portswigger.net/daily-swig/u2f-nowhere-near-ready-for-prime-time)

So when will LastPass support U2F? If we look at the comments sections in [this announcement](https://blog.lastpass.com/2018/09/lastpass-support-new-yubikey-5-series.html/), we see people clarify this and constantly asking for support of U2F.

![](https://cdn-images-1.medium.com/max/800/1*fEhPXUC9mUspqNLMhdB9gA.png)
![](https://cdn-images-1.medium.com/max/800/1*wY1HXTvX4yrXwCHoolrjNw.png)
![](https://cdn-images-1.medium.com/max/800/1*x-aQMK-7IZuXOuicbgvBtA.png)
![](https://cdn-images-1.medium.com/max/800/1*V5edUjUjRe7v3PGDMdz8XA.png)

Sadly, [we have posts as far back as 2014](https://forums.lastpass.com/viewtopic.php?f=7&t=172675&fbclid=IwAR0AOxTkbySHaKIWrglMK8cTCSLTu_d4Nko1_eWihm30vQOgA-n6G2175Sw) asking for this, and it is not clear if Lastpass ever plans to support U2F. There are still posts as recent as May 2020.

![](https://cdn-images-1.medium.com/max/800/1*ZhDkwXHb6xiMRRKNnWNgPw.png)

As for me, I felt really stupid paying for a premium account without double-checking what exactly I am paying for. Also, there are no refunds.

Note to self, simply looking at a table like this is misleading.

![[https://twofactorauth.org/](https://twofactorauth.org/)](https://cdn-images-1.medium.com/max/800/1*OljbRVS2RMMWngq-JZqYPg.png)
*[https://twofactorauth.org/](https://twofactorauth.org/)*

The “Hardware Token” can refer to both OTP and U2F. You have to took specifically whether or not it is U2F (or protocols).

![[https://www.dongleauth.info/](https://www.dongleauth.info/)](https://cdn-images-1.medium.com/max/800/1*FjR9P0a4aFrM41xSr61qQw.png)
*[https://www.dongleauth.info/](https://www.dongleauth.info/)*

#### Moving out of LastPass

Less than 24 hours of paying for a LastPass premium account, I’m moving out. 

Given the current lack of U2F support, the lack of concrete plans to support U2F, and the sketchy plaintext URLs , I’m done with LastPass. I don’t know why I have stayed with it for so long.

Now that I really think about it, my ideal password manager should have the following properties:

1.  supports U2F for multifactor authentication to prevent phishing
2.  open-sourced and 3rd-part audited [\[22\]](https://bitwarden.com/blog/post/third-party-security-audit/)
3.  Is self-hosted on my own servers

I’m currently looking into Bitwarden. Maybe [self-hosted.](https://github.com/dani-garcia/bitwarden_rs) If you have suggestions or comments on what password manager to use, I’d appreciate it.


#### Additional Resources:

Here are some tips on how to secure your workforce during the lockdown from Raymond Nunez.

[**CISO Perspectives in the Work-From-Home Era**](https://www.facebook.com/watch/?v=253307425864294)

For a deeper dive into implementing your own phishing campaign, checkout blogpost for **Evilginx2** or the [repository itself.](https://github.com/kgretzky/evilginx2)

[**Evilginx 2 — Next Generation of Phishing 2FA Tokens**](https://breakdev.org/evilginx-2-next-generation-of-phishing-2fa-tokens/)

Here is another blog that talks about how to phish Lastpass users as well. The approach is somewhat similar. Their approach differs slightly since they steal the credentials in the vault as they are decrypted by the victim’s browser. This generates a lot of additional requests, making it more likely to be detected.

The approach in this blog grabs the username, password, and the encrypted vault, which are queried legitimately in a typical session with Lastpass, and this is decrypted offline.

[**Utilizing reverse proxies offers a more advanced approach to phishing**](https://versprite.com/blog/application-security/reverse-proxy-attack/)

For a pedestrian overview of U2F, you can watch this introduction by Jen Tong \[5\].

[**DevOpsDays Seattle 2018: How FIDO U2F Security Keys Work by Jen Tong**](https://www.youtube.com/watch?v=DWrLBwi7ZBA)

<br/>

*Of course, this blog post can be irrelevant if LastPass suddenly comes out with an update to support U2F. That should be nearby since its been on their radar for so long and that Firefox and Chrome support it*

<br/>
<hr/> 
<br/>

### References

\[1\] [Google Transparency Report](https://transparencyreport.google.com/safe-browsing/overview?unsafe=dataset:0;series:malwareDetected,phishingDetected;start:1148194800000;end:1587279600000&lu=unsafe)

\[2\] PCMag, [“Phishing Attacks Increase 350 Percent Amid COVID-19 Quarantine (2020)”](https://sea.pcmag.com/security/36691/phishing-attacks-increase-350-percent-amid-covid-19-quarantine)

\[3\] Krebs on Security, [“Google: Security Keys Neutralized Employee Phishing (2018)”](https://krebsonsecurity.com/2018/07/google-security-keys-neutralized-employee-phishing/)

\[4\] [Versprite, Utilizing Reverse Proxies to Inject Malicious Code & Extract Sensitive Information.](https://versprite.com/blog/application-security/reverse-proxy-attack/)

\[5\] [Jen Tong, Security Keys are Awesome.](https://jen.run/talks/why-u2f-is-awesome/why-u2f-is-awesome.pdf)

\[6\] [https://github.com/kgretzky/evilginx2](https://github.com/kgretzky/evilginx2)

\[7\] [Yubico, FIDO U2F.](https://www.yubico.com/authentication-standards/fido-u2f/)

\[8\] [DUO, What’s the difference between the YubiKey OTP and Security Key functionalities?](https://help.duo.com/s/article/2942?language=en_US)

\[9\] [Versprite, Attacking LastPass: Compromising an Entire Password Database](https://versprite.com/blog/application-security/password-database-compromised/)

\[10\] [Lastpass Technical Whitepaper](https://enterprise.lastpass.com/wp-content/uploads/LastPass-Technical-Whitepaper-3.pdf)

\[11\] [https://github.com/konomae/lastpass-python/](https://github.com/konomae/lastpass-python/)

\[12\] [PSA: LastPass Does Not Encrypt Everything In Your Vault](https://hackernoon.com/psa-lastpass-does-not-encrypt-everything-in-your-vault-8722d69b2032)

\[13\] [OTP vs. U2F: Strong To Stronger](https://www.yubico.com/blog/otp-vs-u2f-strong-to-stronger/ "Permanent Link: OTP vs. U2F: Strong To Stronger")

\[14\] Lastpass Help, [Use YubiKey Multifactor Authentication](https://support.logmeininc.com/lastpass/help/yubikey-multifactor-authentication-lp030020)

\[15\] Kerbs on Security, [Phishers Are Upping Their Game. So Should You.](https://krebsonsecurity.com/2017/12/phishers-are-upping-their-game-so-should-you/)

\[16\] Yubico, [OTPs Explain](https://developers.yubico.com/OTP/OTPs_Explained.html)

\[17\] John Leyden, PortSwigger The Daily Swig, [U2F nowhere near ready for prime time](https://portswigger.net/daily-swig/u2f-nowhere-near-ready-for-prime-time)

\[18\] Troy Hunt, [Beyond Passwords: 2FA, U2F and Google Advanced Protection](https://www.troyhunt.com/beyond-passwords-2fa-u2f-and-google-advanced-protection/)

\[19\] Josie Colt, Wired, [Simplify and Secure Your Online Logins With a YubiKey](https://www.wired.com/story/how-to-use-a-yubikey/)

\[20\] ZDNet, [Best security keys in 2020](https://www.zdnet.com/article/best-security-keys/)

\[21\] [Yubico, LastPass Premium and Families](https://www.yubico.com/works-with-yubikey/catalog/lastpass-premium-and-families/)


\[22\] [Bitwarden Completes Third-party Security Audit](https://bitwarden.com/blog/post/third-party-security-audit/)

\[23\] [LastPass Hacked — Identified Early & Resolved](https://blog.lastpass.com/2015/06/lastpass-security-notice.html/)

  


Photo by [Ethan Sexton](https://unsplash.com/@ethansexton?utm_source=unsplash&utm_medium=referral&utm_content=creditCopyText) on [Unsplash](https://unsplash.com/s/photos/broken?utm_source=unsplash&utm_medium=referral&utm_content=creditCopyText)