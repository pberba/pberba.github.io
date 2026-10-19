---
layout: post
title: "MacOS Infostealer \"adapts\" to new Keychain Protection"
mini_title: "MacOS Infostealer \"adapts\" to new Keychain Protection"
date: 2026-10-20
category: security
comments: true
author: "Pepe Berba"
sub_categories: [macos, amos, infostealer]
summary: MacOS sample adjusts  behaviours to adapt to new keychain protections 
description: MacOS sample adjusts behaviours to adapt to new keychain protections 

---

### TLDR 

A recent [sample](https://www.virustotal.com/gui/file/3a7f5fdf0716ffa57e0a32f1f9ff37ae07c7617040ce57aba93f232b57e081b7/) I've analyzed changed it's behaviour depending on the macOS version it is running on:
- `< 26.4`: it does the typical fake password dialog flow. 
- `>= 26.4` and has Google Chrome: it will use `security find-generic-password`

This is probably as a direct response to [Apple's additional keychain protections on 26.4](https://appleinsider.com/articles/26/09/13/macos-tahoe-264-update-stops-you-from-copying-your-login-keychain) which prevents keychains from being decrypted when it copied out of the machine.

### Background 

Since the first wave of macOS infostealers in 2023 ([MacStealer](https://www.uptycs.com/blog/threat-research-report-team/macstealer-command-and-control-c2-malware), then [AMOS](https://cyble.com/blog/threat-actor-selling-new-atomic-macos-amos-stealer-on-telegram/)), the macOS malware playbook has been fairly stable. There are a ton of different [macOS infostealer families](https://github.com/stuartjash/macos-malware-kb/tree/main/families/infostealer), and the most common set of techniques is:
1. Display a fake password prompt to collect the user's password
2. Steal the macOS keychain `~/Library/Keychains/login.keychain-db`
3. Steal browser cookies and other sensitive files (example: `~/Library/Application Support/Google/Chrome/Default/Cookies`)

With the user's password, the keychain and the browser cookie DB, the attacker would be able to decrypt and extract all of the user's sessions offline. However, because of Apple's update to MacOS keychain, this flow doesn't work anymore.

### 3a7f5fdf0716ffa57e0a32f1f9ff37ae07c7617040ce57aba93f232b57e081b7

A new [sample](https://www.virustotal.com/gui/file/3a7f5fdf0716ffa57e0a32f1f9ff37ae07c7617040ce57aba93f232b57e081b7/) I was analyzing, which is consistent with AMOS/Odyssey indicators, looked almost like your typical infostealer. However, when I ran this on a sandbox `26.6` I had, the behaviour I observed was slightly different.

For most sandbox environments, I would see usual fake password prompt 

![](/assets/posts/20261020/00-vt-box-of-apples.png)

However, in my sandbox, I found that the first action was the security ACL prompt for `Chrome Safe Storage`

![](/assets/posts/20261020/01-security-acl.png)

I tested this in my older sandbox that was still `26.2` and saw password prompt. 

![](/assets/posts/20261020/02-26.2.png)

To demonstrate the different behaviours, I mocked `sw_vers` by overriding the path. The sample runs `sw_vers -productVersion` to check the OS version, so by mocking it, we can see what it does for different MacOS versions.

```base
cat > ~/fakebin/sw_vers <<'EOF'
#!/bin/sh
case "$1" in
  -productVersion) echo "26.4" ;;
  *) printf 'ProductName:\t\tmacOS\nProductVersion:\t\t26.4\nBuildVersion:\t\t25E246\n' ;;
esac
EOF
chmod +x ~/fakebin/sw_vers

export PATH="$HOME/fakebin:$PATH" 
./3a7f5fdf0716ffa57e0a32f1f9ff37ae07c7617040ce57aba93f232b57e081b7
``` 

Once we override it to trick the sample into thinking that it's `26.4`, we see that it will use `security find-generic-password -ga "Chrome"` instead

![](/assets/posts/20261020/03-26.4.png)

The sample is obfuscated and strings are encrypted using an algorithm based on Murmur3/SplitMix32, [according to VT CodeInsights](https://www.virustotal.com/gui/file/3a7f5fdf0716ffa57e0a32f1f9ff37ae07c7617040ce57aba93f232b57e081b7/detection). Tried to vibe-reverse it but didn't finish.

![](/assets/posts/20261020/04-pain.png)

### Conclusion

This isn't new behaviour. In fact, it's something we've seen even before AMOS, (See: [Pureland](https://objective-see.org/blog/blog_0x77.html)) back in early 2023. It's also not the only recent samples going for `Chrome Safe Storage` 
- Group-IB's [ClickLock](https://www.group-ib.com/blog/clicklock-stealer-macos-malware/) forces the same Chrome Safe Storage prompt
- Netskope documented a [ClickFix stealer](https://www.netskope.com/blog/macos-clickfix-lures-deploy-applescript-stealer-persistent-rat) that instead runs `security unlock-keychain -p` with the phished password

It's interesting how some of the old techniques we've seen before come back because of the changes in controls.

### IOCs

```
# Sample
MD5     a6dd7a9332bed9225f0db4fe9453d4d1
SHA-256 3a7f5fdf0716ffa57e0a32f1f9ff37ae07c7617040ce57aba93f232b57e081b7

# Network (stage 1, from the binary)
okaloq[.]com / hxxps://okaloq[.]com/log      exfil panel (POST)
193.178.159[.]129                            stage-2 host
hxxp://193.178.159[.]129/web/bot             backdoor binary
hxxp://193.178.159[.]129/web/ledger.zip, /web/ledgerwallet.zip, /web/trezor.zip   trojanised wallet apps
HTTP headers: buildid: 7f877c932d9a462d9a01ba938231ec71 / username: 9j6tz0rkos

# Host (stage 1, from the binary)
/tmp/lksopo/, /tmp/lksopo.zip                staging (deleted after exfil)
/tmp/binaryexe                               stage-2 bot
~/.pwd ~/.phost ~/.bhost ~/.username ~/.botid
```
```
