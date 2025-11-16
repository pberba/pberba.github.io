---
layout: post
title: "MacOS Infection Vector: Using AppleScripts to bypass Gatekeeper"
mini_title: "MacOS Infection Vector: Using AppleScripts to bypass Gatekeeper"
date: 2025-11-11
category: security
comments: true
author: "Pepe Berba"
sub_categories: [AppleScript, macos, malware]
summary: A look at how threat actors are abusing AppleScript .scpt files to deliver macOS malware, from fake documents to browser update lures, and how these scripts can still run despite Gatekeeper protections.
description: A look at how threat actors are abusing AppleScript .scpt files to deliver macOS malware, from fake documents to browser update lures, and how these scripts can still run despite Gatekeeper protections.
header-img-direct: /assets/posts/20251111/header.jpeg

---


### TLDR 

This gives an overview of how `.scpt` AppleScript are used to creatively deliver macOS malware, such as fake office documents or fake Zoom/Teams updates. Previously a technique seen with APT campaigns for macOS, we can now see samples coming from the macOS stealer ecosystem like MacSync and Odyssey.

![tldr](/assets/posts/20251111/tldr.png)

### Introduction

Back in August 2024, Apple [removed one of the most popular infection vectors on macOS, the "right-click and open" Gatekeeper override](https://developer.apple.com/news/?id=saqachfa). Since then, attackers have had to rely on other ways to get their malware running on macOS.

Below is an overview of two alternative macOS malware delivery methods that we've seen. Both methods require the victim to interact with `Terminal.app`, which can make the technique less effective. 

_Expand for more info._

<details markdown="1">

<summary> <b>1. "Copy and paste a command to the Terminal"</b> </summary>


We've seen macOS stealers delivered through a number of [Clickfake-type websites that also target macOS users](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/), as well as [fake Homebrew installation pages](https://moonlock.com/macos-malware-homebrew-ads).


![MacOS Clickfix](https://unit42.paloaltonetworks.com/wp-content/uploads/2025/10/word-image-727488-160134-4.png) 
*[from Unit42's blog](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)*

</details>


<details markdown="1">

<summary> <b>2. "Drag and drop to the Terminal DMGs" </b> </summary>

The other common method we've seen is the "drag and drop to terminal".[[1]](https://9to5mac.com/2024/10/17/security-bite-hackers-are-now-directing-users-to-terminal-to-bypass-gatekeeper-in-macos-sequoia/)[[2]](https://0x626c6f67.xyz/posts/macos-dmg-malware/)

![ba43d7fb0f1a4b96518e80d0d4a27bb2450cd3b9e4c70d3e22092e888567ad4e](/assets/posts/20251111/ba43d7fb0f1a4b96518e80d0d4a27bb2450cd3b9e4c70d3e22092e888567ad4e.png)

</details>



<br/>

### Emergence of `.scpt` AppleScript files

An emerging "new" method involves using `.scpt` files. Although the use of `.scpt` AppleScript files may not be new [[5]](https://huntability.tech/threat-note-2025-04-23-nk-zoom/)[[6]](https://www.huntress.com/blog/inside-bluenoroff-web3-intrusion-analysis), we’ve observed more samples using this technique in the last few months.

What caught my interest was a sample analyzed by Moonlock Labs, where the AppleScript files were used to create fake `.docx` and `.pptx` files.

<blockquote class="twitter-tweet"><p lang="en" dir="ltr">3/ The initial infection vector is a compiled AppleScript, falsely given a .docx &quot;extension&quot;, and which is indeed an AppleScript: &#39;AM Management _Strategic OTC Collaboration Proposal.docx.scpt&#39; (6149…10b7). ‘OTC’ in the naming hints that it might be targeting crypto-related…</p>&mdash; Moonlock Lab (@moonlock_lab) <a href="https://twitter.com/moonlock_lab/status/1980684233690746897?ref_src=twsrc%5Etfw">October 21, 2025</a></blockquote> <script async src="https://platform.twitter.com/widgets.js" charset="utf-8"></script>

After looking for other similar samples, we've found some instances of this technique being used by commodity malware, like Odyssey Stealer and MacSync Stealer. Increasing commodity usage suggests trickle-down of APT techniques.

![sample flow](/assets/posts/20251111/sample_scpt_flow.png)
*Fake Chrome Update Example*
The flow is simple:
- By default, a `.scpt` file, whether plain text or compiled, opens in `Script Editor.app` when double-clicked.
- Comments in the script encourage the user to run it, while hiding the real code behind a large number of blank lines.
- Clicking the ▶️ Run button or pressing ⌘ + R executes the script, even if it’s quarantined by Gatekeeper.

### Examples in the wild

#### Fake Documents 

Pivoting from the sample above, we can look for other similarly named `.scpt` files:
- [#1.Apeiron_Token_Transfer_Proposal.docx.scpt](https://www.virustotal.com/gui/file/2e2cedbf1f09208ee7dad6ac5dec96e97bc0c41a31e190bc41e14f2929c05d4c)
- [Stable1 Investment Proposal (Draft) (EN).pptx.scpt](https://www.virustotal.com/gui/file/b489039b502afd8b8267853c4d2cf65f75b76aa1f128f13d332f7d26ffcbd114)
- [AM Management _Strategic OTC Collaboration Proposal.docx.scpt](https://www.virustotal.com/gui/file/6149bacfb02eb3db6f95947bc57d89bfb92b90f16f92a61266ea6fbec81d10b7/details)

Similar analysis was published by [L0Psec](https://x.com/L0Psec/status/1987181570265112719?s=20). To add to that discussion, we note that the threat actors also used custom icons to make these fake documents even more convincing.

![](/assets/posts/20251111/fake_doc_icons.png)
*Discussed more in a later section*


#### Fake Installers and Updates

Just like the fake DMG updates [[9]](https://www.malwarebytes.com/blog/threat-intel/2023/11/atomic-stealer-distributed-to-mac-users-via-fake-browser-updates), we continue to see threat actors use fake websites to trick users into installing updates. Some of the lure sites are quite sophisticated (see [Kapsersky's writeup](https://securelist.com/bluenoroff-apt-campaigns-ghostcall-and-ghosthire/117842)):
- [MSTeamsUpdate.scpt](https://www.virustotal.com/gui/file/14aba88b5f87ab9415bbca855d24abc3f151b819302930897e71e2626e823271)
- [Zoom SDK Update.scpt](https://www.virustotal.com/gui/file/a7c7d75c33aa809c231f1b22521ae680248986c980b45aa0881e19c19b7b1892), [(sample 2)](https://www.virustotal.com/gui/file/8e897a1e0c3092a7a8f8c3946da6ef23f013dd7633bdea185d15f6ea9c902ef0), [(sample 3)](https://www.virustotal.com/gui/file/580f6dd3f4cb78f80167a3d980bab3590dca877d78bb4e17360dc50fdbef7692/content)


And we've also seen MacSync use this to drop the script described in [[11]](https://x.com/moonlock_lab/status/1983550008344375443):
- [Packages.scpt](https://www.virustotal.com/gui/file/24ba8e79bd22ece03fc7cd0b00822a38ecec146dc5c70404476110a4028c9caf), [(sample 2)](https://www.virustotal.com/gui/file/f9f9ac24381acad8957724b6aacb0a7fe83d9359c6b7ceded10b2c8e2f4a729b)
- [InstallSoftZone.scpt](https://www.virustotal.com/gui/file/2f99de308882fb9a6686913c4f6cc6654e75eb861d39a9ce33ae23c2d11271ec)
- [InstallDealoryx.scpt](https://www.virustotal.com/gui/file/bef32c3e895b661b1aa755f98edd86791c9f9af2e6c936e89d526d9af8dab37c/)


And Odyssey Stealer 
- [Microsoft.TeamsSDK.scpt](https://www.virustotal.com/gui/file/7f69f3012e134d1f5084fbb9086697da66a9b0e9240c4e1413777b9e1099aca9)

All of these scripts look very similar once opened. In some cases, variations exist - but the social engineering angle remains the same.
![](/assets/posts/20251111/fake_installer_00.png)
![](/assets/posts/20251111/fake_installer_01.png)

As noted by other researchers, several of these `.scpt` files still have zero detections on VirusTotal:

![](/assets/posts/20251111/fake_installer_detections.png)

#### Bad DMG

`.scpt` files naturally lends itself back into the DMG flow that we've seen in the last few years. The only example I've found so far is `远程安装/双击打开我.scpt`, which Google translates to `Remote installation/double-click to open my.scpt`

![](/assets/posts/20251111/bad_dmg_itw.png)
*[31cd....a6c6](https://www.virustotal.com/gui/file/31cd55a2f96f6d760653c28699c18589cf2e7d39a0f257579f587f3dce03a6c6)*

The format of the prompt here is slightly different from what we've seen.
![](/assets/posts/20251111/bad_dmg_scpt.png)

This script will run [888.scpt](https://www.virustotal.com/gui/file/c6dae9481354466531c186421dda521cbedc72c0bf32ba8d49f6eee2cbf2477f/) which is an obfuscated read-only AppleScript that drops another malicious dmg, and so on - clearly bad.


### Where can this go?

#### File Icons on macOS

On macOS, each file type has a default icon. Normally, this icon is determined by the file’s type (for example, all .txt files share the same default icon). However, macOS allows users to assign custom icons to individual files or folders.

This is stored in the file's `resource fork`, which can be preserved, depending on how the file is delivered. For example, if a file is delivered through a `zip`, then you can see the resource fork in the bundled items of the zip file.

![](/assets/posts/20251111/fake_doc_vt.png)
*[99cf...f06d](https://www.virustotal.com/gui/file/99cfb160a2453a22cc025fe0afc21d660744205eff2885836d8e543fda50f06d/)*

When this is unzipped on a Mac endpoint, the custom icon will be displayed, resulting in a convincing fake document. In the sample below, we see that the attacker has provided fake docs for both macOS and Windows.


![](/assets/posts/20251111/fake_doc_dir.png)

This applies to all files on mac. `.command`, `.js`, `.txt` and even those without extensions.

#### File Extensions

Similar to the file icon, there is a per file setting for the visibility of file extensions that is stored in the extended attributes. Below, we demo what the `.pptx.scpt` sample would look like with this setting enabled.

![](/assets/posts/20251111/extension_setting.png)

Note that the `.pptx.scpt` will not work right away. You'd have to use some tricks with characters/unicode to get the `.scpt` to be hidden while still showing `.pptx`

![](/assets/posts/20251111/extension_demo.png)



#### More malicious DMGs 

Similar to `zip` files, `dmg` files also preserve the icons of the files. This is something that has become common samples we've seen for "Drag and drop to the terminal DMGs".  Although we don't see many DMG samples that include `.scpt`, it wouldn’t be surprising to see this technique grow in adoption.

![Example create for demonstration](/assets/posts/20251111/demo_dmg.png)

[Sample DMG (password: infected)](/assets/posts/20251111/DemoFakeChromeSetup.zip)

### Additional Notes

#### Hunting for samples

This technique works for both plaintext AppleScripts and compiled AppleScripts. To hunt for new scripts, we look at both cases. 

For plain scripts, you can look for suspicious looking strings like `do shell script` and/or `run script` accompanied by strings that could be used to construct the comment.
```
content: "#############" AND content: "do shell script" AND content: "curl" AND (type: "text" OR type: "AppleScript")
```

For compiled AppleScripts, it's not as simple. After playing around, I've found that the event code for `do shell script` is `sysoexec` and the event code for `run script` is `sysodsct` [[13]](https://AppleScriptlibrary.wordpress.com/wp-content/uploads/2013/11/AppleScript-terminology-and-apple-eve-nt-codes-e28094-developer-documentation.pdf), and some strings in ASCII and some as UTF-16. I'm not sure if this is the case for all versions of compiled AppleScripts. `*shrug*`
```
(content: "#########" OR content: {23 00 23 00 23 00 23 00 23 00 23}) AND content: {63 00 75 00 72 00 6c} AND content: "sysoexec" AND type:AppleScript
```

A note: Although rare, we have seen obfuscation of AppleScript, like in [888.scpt](https://www.virustotal.com/gui/file/c6dae9481354466531c186421dda521cbedc72c0bf32ba8d49f6eee2cbf2477f/). 


```applescript
set part1 to "a"
set part2 to "b"
set part3 to "c"
...
set part136 to "="
set part137 to "."

-- Reconstructing http://...
set c2 to part8 & part20 & part20 & part16 & "://" & ...
```

In fact, utilizing the similar obfuscations techniques we've seen with PowerShell [[14]](https://github.com/t3l3machus/PowerShell-Obfuscation-Bible), we can achieve a similar effect for AppleScript scripts. 

```bash
osAscRIPT -e 'set fnxP9 to "tware U"' -e 'set vdrK2 to "ate"' -e 'set lmT3b to "pd"' -e 'set qzrA7 to "Sof"' -e 'tELl aPp ("Syst" & "Em" & " P" & "REfeRE" & "nces") TO DISpLAy dIALOg "Soft" & "ware " & "U" & "pda" & "te" & " requi" & "res th" & "at you ty" & "pe your passwo" & "rd " & "to " & "apply c" & "han" & "ges." & reTURn & RETUrn  dEFAuLt anSweR "" WIth iCOn 1 WItH HIddEN AnsWeR witH Title (qzrA7 & fnxP9 & lmT3b & vdrK2)'
```

### Detections and Mitigations 

#### Change the default app of `.scpt` files

Similar to recommendations on how we can mitigate `.js`, `.vbs`, and other dangerous extensions on Windows [[15]](https://redcanary.com/blog/threat-intelligence/notepad-javascript/), we can set the default app of `.scpt` and other similar extensions like `.applescript` and `.scptd`

![](/assets/posts/20251111/open_with_textedit.png)

But because compiled applescripts are not text, `TextEdit` will not display it properly. 


#### Set extensions to always show

It was pointed out to me that by[sysop_host](https://0x626c6f67.xyz/posts/hiding-compiled-applescripts/#hidden-extensions) that the per-file setting for hiding extensions is overriden by Finder's settings.


![](/assets/posts/20251111/finder_settings.png)

#### Detections

- Look for weird executions from `Script Editor`, especially things that reach out. [(Sigma rule for reference)](https://github.com/SigmaHQ/sigma/blob/4355ece230d68c36f08ebd53d5408ec5f8d629cc/rules/macos/process_creation/proc_creation_macos_susp_execution_macos_script_editor.yml)
- In file events, look for files with `.docx.scpt`, `.pptx.scpt`, and `<common extension>.scpt`

### Indicators 

```
# Fake doc zips
f5b4fec2263950ca5cfac9f9d060bb96f6323fcb908b09eedb7996c107bdcf5a
99cfb160a2453a22cc025fe0afc21d660744205eff2885836d8e543fda50f06d
# Fake doc .scpt and domains
6149bacfb02eb3db6f95947bc57d89bfb92b90f16f92a61266ea6fbec81d10b7
2e2cedbf1f09208ee7dad6ac5dec96e97bc0c41a31e190bc41e14f2929c05d4c
b489039b502afd8b8267853c4d2cf65f75b76aa1f128f13d332f7d26ffcbd114
endesway[.]life
customizetion[.]com

# BlueNoroff IOCs
14aba88b5f87ab9415bbca855d24abc3f151b819302930897e71e2626e823271
support.ms-live[.]com

580f6dd3f4cb78f80167a3d980bab3590dca877d78bb4e17360dc50fdbef7692
uk06webzoom[.]us

a7c7d75c33aa809c231f1b22521ae680248986c980b45aa0881e19c19b7b1892
8e897a1e0c3092a7a8f8c3946da6ef23f013dd7633bdea185d15f6ea9c902ef0
uk04webzoom[.]us

# MacSync 
24ba8e79bd22ece03fc7cd0b00822a38ecec146dc5c70404476110a4028c9caf
foldgalaxy[.]com

2f99de308882fb9a6686913c4f6cc6654e75eb861d39a9ce33ae23c2d11271ec
forestnumb[.]top

f9f9ac24381acad8957724b6aacb0a7fe83d9359c6b7ceded10b2c8e2f4a729b
elbrone[.]com

43e2681212b6324c6087d78e8c30313e199d42e4554e616c6880ed4c4f6bf088
b9c35bccb5ee635269780983265c40169e7c268f73f6e38651cc8efcaf13ed41
globalnetman[.]xyz

# Odyssey
7f69f3012e134d1f5084fbb9086697da66a9b0e9240c4e1413777b9e1099aca9
185.93.89[.]62
aubr[.]io

# Bad DMG 888.scpt
6a95ab1e7a94fb55a1789f5dfb0fb98237ac72d14ae89ac557101a6176826610

03458265a47dd655c7c6eccff7c273618f768f52ecf11db7fd67c857b1eca0cd
9f3a2876f29b336f4372e3c0be26cecaa2966bc5ef5bf2403cb6354ddb87691a

e41efd9eeb08571b4322433df84f81d660ce2fc1ba24134ff14a58a06cd2436b
fbea68ff0dc10f85e859ad09c02c1fea4b85d58e80d8a68af7e93f4a1443b34b

dosmac[.]top
192.140.161[.]143
124.132.136[.]17
114.66.50[.]134

```

### Sources
- [[1] https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/](https://unit42.paloaltonetworks.com/clickfix-generator-first-of-its-kind/)
- [[2] https://moonlock.com/macos-malware-homebrew-ads](https://moonlock.com/macos-malware-homebrew-ads)
- [[3] https://9to5mac.com/2024/10/17/security-bite-hackers-are-now-directing-users-to-terminal-to-bypass-gatekeeper-in-macos-sequoia/](https://9to5mac.com/2024/10/17/security-bite-hackers-are-now-directing-users-to-terminal-to-bypass-gatekeeper-in-macos-sequoia/)
- [[4] https://0x626c6f67.xyz/posts/macos-dmg-malware/](https://0x626c6f67.xyz/posts/macos-dmg-malware/)
- [[5] https://huntability.tech/threat-note-2025-04-23-nk-zoom/](https://huntability.tech/threat-note-2025-04-23-nk-zoom/)
- [[6] https://www.huntress.com/blog/inside-bluenoroff-web3-intrusion-analysis](https://www.huntress.com/blog/inside-bluenoroff-web3-intrusion-analysis)
- [[7] https://twitter.com/moonlock_lab/status/1980684233690746897](https://twitter.com/moonlock_lab/status/1980684233690746897)
- [[8] https://x.com/L0Psec/status/1987181570265112719?s=20](https://x.com/L0Psec/status/1987181570265112719?s=20)
- [[9] https://www.malwarebytes.com/blog/threat-intel/2023/11/atomic-stealer-distributed-to-mac-users-via-fake-browser-updates](https://www.malwarebytes.com/blog/threat-intel/2023/11/atomic-stealer-distributed-to-mac-users-via-fake-browser-updates)
- [[10] https://securelist.com/bluenoroff-apt-campaigns-ghostcall-and-ghosthire/117842/](https://securelist.com/bluenoroff-apt-campaigns-ghostcall-and-ghosthire/117842/)
- [[11] https://x.com/moonlock_lab/status/1983550008344375443](https://x.com/moonlock_lab/status/1983550008344375443)
- [[12] https://securelist.com/bluenoroff-apt-campaigns-ghostcall-and-ghosthire/117842](https://securelist.com/bluenoroff-apt-campaigns-ghostcall-and-ghosthire/117842)
- [[13] https://AppleScriptlibrary.wordpress.com/wp-content/uploads/2013/11/AppleScript-terminology-and-apple-eve-nt-codes-e28094-developer-documentation.pdf](https://AppleScriptlibrary.wordpress.com/wp-content/uploads/2013/11/AppleScript-terminology-and-apple-eve-nt-codes-e28094-developer-documentation.pdf)
- [[14] https://github.com/t3l3machus/PowerShell-Obfuscation-Bible](https://github.com/t3l3machus/PowerShell-Obfuscation-Bible)
- [[15] https://redcanary.com/blog/threat-intelligence/notepad-javascript/](https://redcanary.com/blog/threat-intelligence/notepad-javascript/)
- [[16] proc_creation_macos_susp_execution_macos_script_editor.yml](https://github.com/SigmaHQ/sigma/blob/4355ece230d68c36f08ebd53d5408ec5f8d629cc/rules/macos/process_creation/proc_creation_macos_susp_execution_macos_script_editor.yml)