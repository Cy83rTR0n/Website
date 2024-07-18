---
title: "HotPage: The Silent Browser Hijacker"
date: 2024-07-19
description: "format string vulnerability 1"
tags: ["Malware Analysis Article"]
type: post
weight: 20
showTableOfContents: false
---

### Overiew
Recently there has been a new adware which goes by the name as "HotPage". It comes in the disguise of giving protection from random advertisements and malicious websites, however in the background it drops a malicious signed driver which gives the attacker privileges to execute arbitary code on Windows hosts.

### Infection Chain

Though the actual process by which the installer is shared is still unknown, however. The installer places the driver on the disk and initiates a service to execute it. The driver decrypts its configuration file, which includes a list of target Chromium-based browsers and libraries. If it detects any of these browser executables running or being loaded, the driver attempts to inject one of the specified libraries into the browser process. By hooking network-related Windows API functions, the injected library monitors the URLs being accessed and, under certain conditions, redirects the user to a different page using various methods

### Notable Functionalities
##### 1. Injector Driver

The injector driver’s main function is to inject libraries into browser applications, changing URLs or opening new tabs. It uses two threads from the Blackbone project to handle these requests and monitors newly created processes and executable images.

Upon initialization, the driver deletes its image from the disk and creates a device object \\.\KNewTableBaseIo to manage I/O requests using specific IOCTLs. These control codes are protected by a regular expression, ensuring only legitimate updates.

##### 2. Process creation notification routine

The driver ensures that the homepage of a new browser instance is redirected to a specific URL from the hotPage configuration, even if this version of the installer doesn't use it.

A browser process is marked for redirection if:

- It's the first instance of the browser, not just a new tab.
- The process’s file path matches a regular expression in the hotPage configuration.
- The command line doesn't match any regular expression in the wlist.
- If the command line includes its own file path, it must not match any in the ppwlist.
When the browser starts loading, a request to open a new tab is queued.


##### 3. Security issues and privilege escalation

When initializing its device object, the driver does not specify any access control lists (ACLs) to restrict who can communicate with it. This oversight means that any process, regardless of its privilege level, can send I/O requests to the driver. The lack of ACLs exposes the driver to potential abuse, as it does not differentiate between legitimate and malicious requests.

Despite this, the driver employs a secondary layer of protection for certain I/O control codes. These control codes are designed to only accept requests from processes whose file paths match a specific regular expression pattern: `*ShieldNetWork\\Business\\DwBusiness_*`. This regular expression acts as a filter, ensuring that only processes located in the specified directory structure can execute these control codes.

The ESET researchers developed a proof-of-concept Python script that proved two scenarios where individuals could be allowed to escalate their privileges through the HotPage driver to run code as the NT AUTHORITY/Systems. One involved using arbitrary DLL injection in arbitrary processes, the other changing the command line of newly created processes.


### Conclusion

The analysis of this seemingly generic malware reveals the lengths to which adware developers will go to achieve their goals. They’ve not only crafted a sophisticated kernel component capable of manipulating processes with a variety of techniques but also navigated Microsoft's stringent requirements to obtain a code-signing certificate for their driver. This level of dedication highlights the ongoing challenge in cybersecurity: even the most unassuming threats can carry advanced capabilities, emphasizing the need for constant vigilance and robust security measures.


For further read please refer to the following:

1. [Alert: HotPage Adware Disguised as Ad Blocker Installs Malicious Kernel Driver](https://thehackernews.com/2024/07/alert-hotpage-adware-disguised-as-ad.html)
2. [HotPage: Story of a signed, vulnerable, ad-injecting driver](https://www.welivesecurity.com/en/eset-research/hotpage-story-signed-vulnerable-ad-injecting-driver/)




