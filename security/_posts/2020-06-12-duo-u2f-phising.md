---
layout: post
title: 'U2F with Duo Web Phishable by default'
date: 2020-06-12
category: security
sub_categories: [phishing, u2f, authentication]
author: "Pepe Berba"
summary:  A scenario when U2F/WebAuthn does not protect you against phishing attacks (until hostname whitelisting is enabled).
subtitle: A scenario when U2F/WebAuthn does not protect you against phishing attacks
  (until hostname whitelisting is enabled)
description: Without changes to evilginx, we can bypass U2F on Duo with default configurations. This is an analysis of how implementation and configuration of U2F can lead to a scenario where U2F/WebAuthn does not protect you against phishing attacks (until hostname whitelisting is enabled)
tags: [duo, u2f, security key, phishing, cyber security, 2fa, cryptography]
header-img-direct: https://cdn-images-1.medium.com/max/800/1*tqecx4DPyynV-a8ANX4zJg.jpeg
---

**TLDR:** **U2F prevents MITM attack between the victim and the Duo server, but not between the victim and the application.** Because Duo is a 3rd-party service, we don’t have the same security properties that are associated with U2F between the victim and the server. This boils down to bypassing the Duo integration. If you can bypass the Duo prompt, then the phishing attempt will be successful, even if U2F is used. **To prevent phishing, it is paramount that you enable** [**hostname whitelisting**](https://duo.com/docs/protecting-applications#:~:text=Hostname%20Whitelisting,-This%20optional%20setting&text=When%20you%20limit%20which%20sites,authenticate%20only%20from%20known%20sites.) **\[1\].** **Without hostname whitelisting, Duo is similar to an OTP generator during a phishing attack.**

![](https://cdn-images-1.medium.com/max/800/1*wnttuiAlAO9c7eElwHRa8w.png)

I’ve contacted Duo PSIRT about this and their full reply is quoted at the end of the blog post. Here are their main points:

*   Hostname whitelisting isn’t enabled by default because it’s difficult to know what hostname(s) are used by many Duo prompt integrations beforehand
*   This feature is encouraged in the [documentation](https://duo.com/docs/protecting-applications#:~:text=Hostname%20Whitelisting,-This%20optional%20setting&text=When%20you%20limit%20which%20sites,authenticate%20only%20from%20known%20sites.) and is proactively recommended by Duo support to its customers that use U2F or WebAuthn 
*   Fortunately, the Duo prompt and Web SDK are undergoing a major redesign that will eliminate the need for manual hostname whitelisting for all applications. This will be available soon.


#### Why is Default Web Duo Phishable

Because U2F is done through the an integration Duo and not directly on the application, the MFA can be bypassed without attacking the U2F directly. We just work around how Duo is integrated to the application. 

Here is an illustration of the process that results when implementing the Duo web (which we discuss in the next secions).

![](https://cdn-images-1.medium.com/max/800/1*JEFRhS58nbU2Ey3MgWPPQQ.png)

If we simplify this to two main connections:

*   victim to application
*   victim to Duo

![](https://cdn-images-1.medium.com/max/800/1*oSvf8s0l4-4a83J36WqMdQ.png)

U2F protects the connection between the victim and Duo. Any attempt to authenticate when there is a MITM between victim and Duo will fail.

Fortunately, with this setup, we only need to get a MITM between the victim and the application.

![](https://cdn-images-1.medium.com/max/800/1*wnttuiAlAO9c7eElwHRa8w.png)

Since the victim connects to the Duo API host directly, the necessary HTTPS connections are established with the right domain, `api-xxxxxx.duosecurity.com`, making U2F possible. Although you may be using U2F as part of this authentication process, you may get the U2F's "anti-phishing" because of the way the Duo web is architectured.


The rest of this post discusses other related topics such as:
- How the Duo Web is integrated 
- The security impact the architecture of Duo web
- Solutions and Mitigations

<br/>
<hr/>
<br/>

### Introduction

In my previous blog post, [_“Bypassing LastPass’s “Advanced” YubiKey MFA: A MITM Phishing Attack,”_](https://pberba.github.io/security/2020/05/28/lastpass-phishing/)  I discuss at length why U2F is important to mitigate the risk of MITM attacks. I also demonstrate how to set up the phishing site using [a fork](https://github.com/pberba/evilginx2) of [evilginx2](https://github.com/kgretzky/evilginx2), which we will use here.

I got a suggestion to try out U2F with LastPass’s integration with Duo. I’m not a Duo user but I was interested in trying this.

<blockquote class="twitter-tweet" style="margin: auto;"><p lang="en" dir="ltr"><a href="https://twitter.com/__pberba__?ref_src=twsrc%5Etfw">@__pberba__</a> Read your Lastpass/Yubikey article. Good stuff. Suggestion: Register for free Duo account, register Yubikey as U2F in Duo, enable Lastpass with Duo, now you have U2F/FIDO2 as 2FA.</p>&mdash; dreamer (@alabrian) <a href="https://twitter.com/alabrian/status/1266494832903704581?ref_src=twsrc%5Etfw">May 29, 2020</a></blockquote> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

Unlike the previous blog post, **this is not specific to LastPass (sorry LastPass).** I use LastPass here because it’s the application that is readily available to me. I have also tested with 1Password.

To be clear, **having MFA authentication is better than not having any at all**, and although I am not a Duo user, I think there are clear benefits when using MFA features such as the push notifications where you get actively notified when somebody tries to log-in into your account. On top of that, when using these kinds of services, you get additional authentications logs and analytics for your protected application.

**However, defaults matter** and we analyze how the default Duo U2F configuration in the context of a phishing attack.

### U2F with Duo Web and Phishing

#### Setting up Duo Web U2F

Here is a quick run-through of the setup process that I went through to integrate Duo with LastPass. 

![](https://cdn-images-1.medium.com/max/800/1*zBl0V7I1IqfNhqc8osyp9Q.png)

You click protect and you get the _Integration Key, Secret Key, and API hostname._

![](https://cdn-images-1.medium.com/max/800/1*4GGLahvPakcZ5HznRnM00g.png)

You enter these to the LastPass MFA settings.

![](https://cdn-images-1.medium.com/max/800/1*mdDux81tWJB6fHE7-lCOgQ.png)

And that’s it. It is enabled with LastPass.

![](https://cdn-images-1.medium.com/max/800/1*vwrV2TKaB50EvyWVqbUdRg.png)

To add a security key, I went to `Dashboard > Users > <USER>` and put in my security key.

![](https://cdn-images-1.medium.com/max/800/1*7NDQY1HmjsAydQx9yGyFKQ.png)

#### Phishing Site

We use the same set-up from the previous blog post. Here is the set-up script for the phishing site.

What’s nice about this is that there are no special changes needed to do a MITM attack on a default Duo Web setup.

The victim lands on the fake log-in page and enters their credentials.

![](https://cdn-images-1.medium.com/max/800/1*GBZmsEi6L7JMXBwQsL5bcA.png)

LastPass sends you an iframe with the Duo Web prompt. This connects to the real Duo API endpoint.

![](https://cdn-images-1.medium.com/max/800/1*1jBYGIM8PKz3EzImDubcyg.png)

The victim authenticates with the Duo endpoint and Duo then returns a signed authentication token that will be used to finish the sign-in process with LastPass.

![](https://cdn-images-1.medium.com/max/800/1*WJqo31OEWWMt331jUZaxwQ.png)

If you look at the Duo dashboard, you will see that this is indeed logged as U2F.

![](https://cdn-images-1.medium.com/max/800/1*n5O-aNxFqHo6jV2StwV2-g.png)

#### U2F but still phishable??

> What happened? I thought U2F was not phishable?

If the integration of the U2F on the original application server, this attack will fail. If you try this with Github you will see that in a usual context, U2F is indeed not phishable.

![The same attack fails with Github](https://cdn-images-1.medium.com/max/800/1*HuKYoMDGztnzXbN8pullVQ.png)
*The same attack fails with Github*

It boils down to this. Whether it is the “Duo prompt”, TOTP, U2F, WebAuthn, etc… in the end, Duo will sign an authentication token which the application will verify to finalize the log-in process

Without additional security mechanisms, then Duo is like a fancy OTP generator during a phishing attack. 

#### Understanding the Duo Web architecture

To understand this, let’s look at how Duo Web is set-up.

These instructions come from the Duo Web documentation [\[2\]](https://duo.com/docs/duoweb). This assumes that the application already has the _Integration Key, Secret Key,_ and _API hostname,_ that we set-up in the previous example.

![Authentication flow with Duo](https://cdn-images-1.medium.com/max/800/1*Pr20dxCB-VCDx3XNS-p3RA.png)
*Authentication flow with Duo*

**Step 1: Sign a request**

This is done on the server. The `akey` is some random data the server made.

```
sig_request = sign_request(ikey, skey, akey, username)
```

**Step 2: Initialize the Duo Web prompt in the form of an iframe**

This is done on the client-side and renders as an iframe. 

```html
<script src="/path/to/Duo-Web-v2.js"></script>  
<script>  
  Duo.init({  
    'host': 'host',  
    'sig\_request': 'sig\_request',  
    'post\_action': 'post\_action\_url'  
  });  
</script>
```

After the authentication, the iframe sends a post request to the URL defined in the `post_action` field.

**Step 3: Verify signature**

On the `post_action_url` you receive the response and verify the signature.

authenticated\_username = verify\_response(ikey, skey, akey, sig\_response)  
if authenticated\_username:  
  log\_user\_in(authenticated\_username)

**Some notes here**

Notice here that regardless of the authentication method, the server will receive a signed response. We can see that this is just like an OTP generator because nothing prevents a MITM phishing attack. The signatures prevent tampering of tokens in transit, but it doesn’t prevent someone from intercepting the tokens.

The initial request only has information about the username and not the IP address of the request. This comes in play later when we describe what the Duo endpoint “sees”.

From what I’ve read, the `post_action` parameter is not checked against anything. So **the signed authentication token that Duo generates can end up anywhere that the** `**post_action**` **is pointed to (like our phishing site)**. The `post_action` is similar to **OAuth2’s redirect URI**, which I will discuss more later.


#### Security Impact

These are the impact of keeping the default configuration of Duo Web to protect applications like LastPass and 1Password.

**Phishable U2F**

As we have shown, the first effect is that U2F is still phishable when using the default config of Duo Web. 

If you set-up U2F on a site directly, you are protected from phishing by default because of HTTPS. So in a way, if you want to be really sure that you get all the benefits of U2F, it is better to set up your security keys with each website directly. 

**Duo Prompt **

Because the browser talks directly to the Duo server, what Duo sees is the victim’s IP address. This means when a user uses the Duo push notification, they will not see anything suspicious and the MITM attack that we are using will be undetectable on the prompt.

![Prompt picture from \[4\]](https://cdn-images-1.medium.com/max/800/1*J8lctoBtLiTvOOrHesPJwA.png)
*Prompt picture from \[4\]*

If an employee sees that their IP address and location are correct on the push notification during a phishing attack, they may let their guards down. 

In such a case, the victim is better off relying on notifications from the web application itself, because that will show the attackers IP address. 

![](https://cdn-images-1.medium.com/max/800/1*VYg3ryPlaBZ8T4ppvWzBRQ.png)

**Authentication Log**

Similarly, **authentication logs will reflect the victim’s information rather than the attackers.** So when monitoring for phishing attacks, remember that authentication logs may not be as useful by default.

Below is an illustrative example.

![](https://cdn-images-1.medium.com/max/800/1*kT0lWucjJdIWW9I05UOiXw.png)

Of course, if the attacker then tried to authenticate on their own browser, then their IP address will be the one that is logged.

### Solutions and Mitigations

Here I will list down some of the solutions or ideas that can address some parts of this. The first one is the most flexible and straightforward to do with the current set-up. The latter ones may not be that applicable to some deployments.

#### Hostname Whitelisting 

Because the Duo Web prompt is embedded as an iframe, then the browser’s requests to the Duo API endpoint would put the phishing domain as the referrer.

![](https://cdn-images-1.medium.com/max/800/1*Bx3BekcTwLyA64TlBKPXzw.png)

Since Duo knows that application the user is trying to authenticate one, then there is an opportunity to block unknown _HTTP referers._

This is what I recommended to the Duo Security team when I reported this to them. What I realized, later on, was that this was already implemented as an [optional configuration](https://duo.com/docs/protecting-applications#hostname-whitelisting), I just didn’t realize it when I set it up.

![If the incorrect referrer is blocked](https://cdn-images-1.medium.com/max/800/1*Jb6ILeQnO7EYILAeld_tmQ.png)
If the incorrect referrer is blocked

If done properly, then the MITM will be forced to make the connections to the Duo endpoint so that they can put the right referer headers. This will make attacks a bit more complicated and more discoverable. 

This helps to make IP of the MITM show up in Duo push notifications and the authentication logs.

Unfortunately, this optional feature is:

*   not enabled by default
*   has no preconfigured hostnames 
*   not mentioned or asked during the setup process (_Do you want to turn on hostname whitelisting?)_
*   (in my opinion) not easy to find if you weren’t looking for it

It should be noted that these are mentioned in the documentation and briefly mentioned in the setup instructions [\[3\]](https://duo.com/docs/lastpass). However, I admit I missed these when I first set-up my Duo since they were in sections that I didn’t read anymore after the setup was successful.

![](https://cdn-images-1.medium.com/max/800/1*WavmgsJOTNkB-dv08dzI0w.png)

Here I would argue that it should be recommended not just for WebAuthn or U2F, because of the impact I have listed previously.

For custom applications, deployments, and integrations, I understand that this has to be configured by the users. 

However, I feel that if I’m are already choosing a commonly used application such as “**LastPass**” or “**1Password**”. It’s reasonable to expect that there’s an enabled pre-set whitelisted hostnames, like `*.lastpass.com` for LastPass.

But this is a design decision, and, in the end, it’s the user's responsibility to enable it. If you want to configure this, here is where you will find it

![](https://cdn-images-1.medium.com/max/800/1*foknEkQnNCXgEzZvSIn3Sw.png)

#### How OAuth2 handles redirect

This is similar to the hostname whitelisting, but we are filtering on the redirect URL. From what I’ve read in the Duo Web documentation, the `post_action` URL is an open redirect. This contrasts with what OAuth2 does \[5\]:

> Because the redirect URL will contain sensitive information, it is critical that the service doesn’t redirect the user to arbitrary locations.

> The best way to ensure the user will only be directed to appropriate locations is to require the developer to register one or more redirect URLs when they create the application. \[5\]

If implemented when applications like LastPass and 1Password set up their integration with Duo, they would have to set up a whitelist of their redirect URLs. 

In OAuth2, the onus of setting up the whitelist is on the developer of the application. In Duo, the responsibility is by default, on the IT administrators that try to use these integrations.

#### Remove the iframe

Although this is starting to introduce bigger changes in architecture and might be less flexible compared with the current set-up.

![](https://cdn-images-1.medium.com/max/800/1*dNNODW8-x1mYztZ1WaaoiQ.png)

If the integration of the application and Duo happens on the server-side such that there is no need to have an iframe, then we are closer to the conditions where U2F is able to prevent the fishing attack. 

This is similar to other setups like Universal FIDO server [\[6\]](https://noknok.com/fido2/)[\[7\]](https://www.youtube.com/watch?v=M30aZ2cxElo&t=2256s) 

![Nok nok lab \[6\]](https://cdn-images-1.medium.com/max/800/1*OMgVGNLx5WfHvaCwybTBrA.png)
*Nok nok lab \[6\]*

However, this would mean that the users would still need to set-up the security keys per site since the signatures are going to be tied to the domain of the application (which is something that we may actually want).

#### More information in the signed request

I haven’t thought this one through that much, but I’m just putting this out there. 

When the initial sign request is made by the application, part of the request should include the IP address of the client. In the case of a MITM attack, this IP address would be the IP address of the proxy.

This is the application telling Duo, “_Expect to authenticate <USERNAME> from <IP ADDRESS> location_”

```
sig_request = sign_request(ikey, skey, akey, ip_address, username)
```

And when Duo server receives a new request to authenticate, it validates whether the current source IP, matches the expected IP address from the signed request. If there is any mismatch then the request should fail.

### The response of Duo PSIRT

I contacted Duo PSIRT to verify that they already know about this. 

> Duo’s decision to allow customers to enable and configure hostname whitelisting themselves, rather than by default, is by design. For many Duo prompt integrations, it is difficult to know what hostname(s) might belong in the whitelist, as we don’t have knowledge of customer environments.

> Therefore, we encourage customers to make this decision by [providing publicly-available documentation](https://duo.com/docs/protecting-applications#:~:text=Hostname%20Whitelisting,-This%20optional%20setting&text=When%20you%20limit%20which%20sites,authenticate%20only%20from%20known%20sites.) on how to enable this feature, and by proactively communicating with customers who have not enabled the hostname whitelisting option to ensure they’re aware that we recommend hostname whitelisting be configured in the event U2F and/or WebAuthn are enabled as a second factor.

> We are also currently working on a major redesign of the Duo prompt. This redesign effort includes a significant overhaul of the Web SDK and its integration protocols that will eliminate the need for manual hostname whitelisting for all applications, not just ones with static/predictable hostnames. This iteration of the prompt will be made available in the near future for all customers.

Personally, I haven’t received any reminder or recommendations to turn on hostname whitelisting after configuring U2F as a second factor. Although, I’ve confirmed with someone whose employer is a Duo customer that recommendations such as hostname whitelisting are being suggested to them by Duo support. So they are focusing on paying customers (which I am not).

I'm also curious to see what the next iterations are. They don't give details on what these improvements are. We'll just have to wait and see.

The Duo PSIRT team has reviewed this and did some fact-checking. They ask some revisions:
- Changing the blog subtitle from: _"A scenario when U2F/WebAuthn does not protect you against phishing attacks by default"_ to _"... phishing attacks (until hostname whitelisting is enabled)"_
- Mentioning the ongoing overhaul of the Duo prompt in the TLDR so that their customers know that there are upcoming improvements. 

Aside from that, this blog post is mostly unchanged.

### Final Words

If you are an admin of a Duo account, an action point here is to check and configure hostname whitelisting for applications that matter to you. 

For me, I would prefer to be secured defaults. As I have mentioned, I think it is reasonable to have integrations with LastPass and 1Password have _hotstname whitelisting_ enabled by default. In security, we know that the [default options](https://en.wikipedia.org/wiki/Default_effect) matter\* since they become more likely to keep these defaults.

Aside from that, I hope you enjoyed this, and I hope you learned some gotchas when using U2F and 3rd party MFA providers.

  
\*Thank you @alabrian and Duo PSIRT for the suggestions and the feedback

<br/>

---------------------------

<br/>

### References

\[1\] [Duo: Protecting Applications, Hostname Whitelisting](https://duo.com/docs/protecting-applications#hostname-whitelisting)

\[2\] [Duo Web](https://duo.com/docs/duoweb)

\[3\] [Duo: LastPass](https://duo.com/docs/lastpass)

\[4\] [Duo Mobile on Windows Phone](https://guide.duo.com/windows-phone)

\[5\] [OAuth2: Redirect URIs](https://www.oauth.com/oauth2-servers/redirect-uris/)

\[6\] [Nok nok: What is FIDO2? ](https://noknok.com/fido2/)

\[7\] [Google and Microsoft Debut: Replacing Passwords with FIDO2 Authentication](https://www.youtube.com/watch?v=M30aZ2cxElo&t=2256s)

Photo by [stephen momot](https://unsplash.com/@ah360?utm_source=unsplash&utm_medium=referral&utm_content=creditCopyText) on [Unsplash](https://unsplash.com/s/photos/fishing?utm_source=unsplash&utm_medium=referral&utm_content=creditCopyText)