# Digital Forensics=

## Disk Image Creation Tools

* [AccessData FTK Imager](http://accessdata.com/product-download/?/support/adownloads#FTKImager) - AccessData FTK Imager is a forensics tool whose main purpose is to preview recoverable data from a disk of any kind. FTK Imager can also acquire live memory and paging file on 32bit and 64bit systems
* [Bitscout](https://github.com/vitaly-kamluk/bitscout) - Bitscout by Vitaly Kamluk helps you build your fully-trusted customizable LiveCD/LiveUSB image to be used for remote digital forensics (or perhaps any other task of your choice). It is meant to be transparent and monitorable by the owner of the system, forensically sound, customizable and compact.
* [GetData Forensic Imager](http://www.forensicimager.com/) - GetData Forensic Imager is a Windows based program that will acquire, convert, or verify a forensic image in one of the following common forensic file formats
* [Guymager](http://guymager.sourceforge.net) - Guymager is a free forensic imager for media acquisition on Linux
* [Magnet ACQUIRE](https://www.magnetforensics.com/magnet-acquire/) - ACQUIRE by Magnet Forensics allows various types of disk acquisitions to be performed on Windows, Linux, and OS X as well as mobile operating systems.

## File Carving

* [bulk_extractor](https://github.com/simsong/bulk_extractor) - Fast file
  carving tool.
* [EVTXtract](https://github.com/williballenthin/EVTXtract) - Carve Windows
  Event Log files from raw binary data.
* [Foremost](http://foremost.sourceforge.net/) - File carving tool designed
  by the US Air Force.
* [hachoir3](https://github.com/vstinner/hachoir3) - Hachoir is a Python library
  to view and edit a binary stream field by field.
* [Scalpel](https://github.com/sleuthkit/scalpel) - Another data carving
  tool.
* [SFlock](https://github.com/jbremer/sflock) - Nested archive
  extraction/unpacking (used in Cuckoo Sandbox).

## Evidence Collection

* [bulk_extractor](https://github.com/simsong/bulk_extractor) - bulk_extractor is a computer forensics tool that scans a disk image, a file, or a directory of files and extracts useful information without parsing the file system or file system structures. Because of ignoring the file system structure, the program distinguishes itself in terms of speed and thoroughness
* [Cold Disk Quick Response](https://github.com/rough007/CDQR) - uses a streamlined list of parsers to quickly analyze a forenisic image file (dd, E01, .vmdk, etc) and output nine reports
* [ir-rescue](https://github.com/diogo-fernan/ir-rescue) - *ir-rescue* is a Windows Batch script and a Unix Bash script to comprehensively collect host forensic data during incident response.
* [Live Response Collection](https://www.brimorlabs.com/tools/) - The Live Response collection by BriMor Labs is an automated tool that collects volatile data from Windows, OSX, and *nix based operating systems

## All-In-One Tools

* [Belkasoft Evidence Center](https://belkasoft.com/ec) -  The toolkit will quickly extract digital evidence from multiple sources by analyzing hard drives, drive images, memory dumps, iOS, Blackberry and Android backups, UFED, JTAG and chip-off dumps
* [CimSweep](https://github.com/PowerShellMafia/CimSweep) - CimSweep is a suite of CIM/WMI-based tools that enable the ability to perform incident response and hunting operations remotely across all versions of Windows
* [CIRTkit](https://github.com/byt3smith/CIRTKit) - CIRTKit is not just a collection of tools, but also a framework to aid in the ongoing unification of Incident Response and Forensics investigation processes
* [Cyber Triage](http://www.cybertriage.com) - Cyber Triage remotely collects and analyzes endpoint data to help determine if it is compromised.  It’s agentless approach and focus on ease of use and automation allows companies to respond without major infrastructure changes and without a team of forensics experts.  Its results are used to decide if the system should be erased or investigated further.
* [Digital Forensics Framework](http://www.arxsys.fr/discover/) - DFF is an Open Source computer forensics platform built on top of a dedicated Application Programming Interface (API). DFF proposes an alternative to the aging digital forensics solutions used today. Designed for simple use and automation, the DFF interface guides the user through the main steps of a digital investigation so it can be used by both professional and non-expert to quickly and easily conduct a digital investigations and perform incident response
* [Doorman](https://github.com/mwielgoszewski/doorman) - Doorman is an osquery fleet manager that allows remote management of osquery configurations retrieved by nodes. It takes advantage of osquery's TLS configuration, logger, and distributed read/write endpoints, to give administrators visibility across a fleet of devices with minimal overhead and intrusiveness
* [Envdb](https://github.com/mephux/envdb) - Envdb turns your production, dev, cloud, etc environments into a database cluster you can search using osquery as the foundation. It wraps the osquery process with a (cluster) node agent that can communicate back to a central location
* [Falcon Orchestrator](https://github.com/CrowdStrike/falcon-orchestrator) - Falcon Orchestrator by CrowdStrike is an extendable Windows-based application that provides workflow automation, case management and security response functionality.
* [GRR Rapid Response](https://github.com/google/grr) - GRR Rapid Response is an incident response framework focused on remote live forensics. It consists of a python agent (client) that is installed on target systems, and a python server infrastructure that can manage and talk to the agent
* [Kolide Fleet](https://kolide.com/fleet) - Kolide Fleet is a state of the art host monitoring platform tailored for security experts. Leveraging Facebook's battle-tested osquery project, Kolide delivers fast answers to big questions.
* [Limacharlie](https://github.com/refractionpoint/limacharlie) - an endpoint security platform. It is itself a collection of small projects all working together, and gives you a cross-platform (Windows, OSX, Linux, Android and iOS) low-level environment allowing you to manage and push additional modules into memory to extend its functionality
* [MIG](http://mig.mozilla.org/) - Mozilla Investigator (MIG) is a platform to perform investigative surgery on remote endpoints. It enables investigators to obtain information from large numbers of systems in parallel, thus accelerating investigation of incidents and day-to-day operations security
* [MozDef](https://github.com/mozilla/MozDef) - The Mozilla Defense Platform (MozDef) seeks to automate the security incident handling process and facilitate the real-time activities of incident handlers
* [nightHawk](https://github.com/biggiesmallsAG/nightHawkResponse) - the nightHawk Response Platform is an application built for asynchronus forensic data presentation using ElasticSearch as the backend. It's designed to ingest Redline collections.
* [Open Computer Forensics Architecture](http://sourceforge.net/projects/ocfa/) - Open Computer Forensics Architecture (OCFA) is another popular distributed open-source computer forensics framework. This framework was built on Linux platform and uses postgreSQL database for storing data
* [Osquery](https://osquery.io/) - with osquery you can easily ask questions about your Linux and OSX infrastructure. Whether your goal is intrusion detection, infrastructure reliability, or compliance, osquery gives you the ability to empower and inform a broad set of organizations within your company. Queries in the *incident-response pack* help you detect and respond to breaches
* [Redline](https://www.fireeye.com/services/freeware/redline.html) - provides host investigative capabilities to users to find signs of malicious activity through memory and file analysis, and the development of a threat assessment profile
* [The Sleuth Kit & Autopsy](http://www.sleuthkit.org) - The Sleuth Kit is a Unix and Windows based tool which helps in forensic analysis of computers. It comes with various tools which helps in digital forensics. These tools help in analyzing disk images, performing in-depth analysis of file systems, and various other things
* [TheHive](https://thehive-project.org/) - TheHive is a scalable 3-in-1 open source and free solution designed to make life easier for SOCs, CSIRTs, CERTs and any information security practitioner dealing with security incidents that need to be investigated and acted upon swiftly.
* [X-Ways Forensics](http://www.x-ways.net/forensics/) - X-Ways is a forensics tool for Disk cloning and imaging. It can be used to find deleted files and disk analysis
* [Zentral](https://github.com/zentralopensource/zentral) - combines osquery's powerful endpoint inventory features with a flexible notification and action framework. This enables one to identify and react to changes on OS X and Linux clients.

## Linux Distributions

* [ADIA](https://forensics.cert.org/#ADIA) - The Appliance for Digital Investigation and Analysis (ADIA) is a VMware-based appliance used for digital investigation and acquisition and is built entirely from public domain software. Among the tools contained in ADIA are Autopsy, the Sleuth Kit, the Digital Forensics Framework, log2timeline, Xplico, and Wireshark. Most of the system maintenance uses Webmin. It is designed for small-to-medium sized digital investigations and acquisitions. The appliance runs under Linux, Windows, and Mac OS. Both i386 (32-bit) and x86_64 (64-bit) versions are available.
* [CAINE](http://www.caine-live.net/index.html) - The Computer Aided Investigative Environment (CAINE) contains numerous tools that help investigators during their analysis, including forensic evidence collection
* [CCF-VM](https://github.com/rough007/CCF-VM) - CyLR CDQR Forensics Virtual Machine (CCF-VM): An all-in-one solution to parsing collected data, making it easily searchable with built-in common searches, enable searching of single and multiple hosts simultaneously
* [DEFT](http://www.deftlinux.net/) - The Digital Evidence & Forensics Toolkit (DEFT) is a Linux distribution made for computer forensic evidence collection. It comes bundled with the Digital Advanced Response Toolkit (DART) for Windows. A light version of DEFT, called DEFT Zero, is also available, which is focused primarily on forensically sound evidence collection
* [NST - Network Security Toolkit](https://sourceforge.net/projects/nst/files/latest/download?source=files) - Linux distribution that includes a vast collection of best-of-breed open source network security applications useful to the network security professional
* [PALADIN](https://sumuri.com/software/paladin/) - PALADIN is a modified Linux distribution to perform various forenics task in a forensically sound manner. It comes with many open source forensics tools included
* [Security Onion](https://github.com/Security-Onion-Solutions/security-onion) - Security Onion is a special Linux distro aimed at network security monitoring featuring advanced analysis tools
* [SIFT Workstation](http://digital-forensics.sans.org/community/downloads) - The SANS Investigative Forensic Toolkit (SIFT) Workstation demonstrates that advanced incident response capabilities and deep dive digital forensic techniques to intrusions can be accomplished using cutting-edge open-source tools that are freely available and frequently updated

## Linux Evidence Collection

* [FastIR Collector Linux](https://github.com/SekoiaLab/Fastir_Collector_Linux) - FastIR for Linux collects different artefacts on live Linux and records the results in csv files

## Log Analysis Tools

* [Lorg](https://github.com/jensvoid/lorg) - a tool for advanced HTTPD logfile security analysis and forensics
* [Logdissect](https://github.com/dogoncouch/logdissect) - A CLI utility and Python API for analyzing log files and other data.

## Memory Analysis Tools

* [Evolve](https://github.com/JamesHabben/evolve) - Web interface for the Volatility Memory Forensics Framework
* [inVtero.net](https://github.com/ShaneK2/inVtero.net) - Advanced memory analysis for Windows x64 with nested hypervisor support
* [KnTList](http://www.gmgsystemsinc.com/knttools/) - Computer memory analysis tools
* [LiME](https://github.com/504ensicsLabs/LiME) - LiME (formerly DMD) is a Loadable Kernel Module (LKM), which allows the acquisition of volatile memory from Linux and Linux-based devices
* [Memoryze](https://www.fireeye.com/services/freeware/memoryze.html) - Memoryze by Mandiant is a free memory forensic software that helps incident responders find evil in live memory. Memoryze can acquire and/or analyze memory images, and on live systems, can include the paging file in its analysis
* [Memoryze for Mac](https://www.fireeye.com/services/freeware/memoryze-for-the-mac.html) - Memoryze for Mac is Memoryze but then for Macs. A lower number of features, however
* [Rekall](http://www.rekall-forensic.com/) - Open source tool (and library) for the extraction of digital artifacts from volatile memory (RAM) samples
* [Responder PRO](http://www.countertack.com/responder-pro) - Responder PRO is the industry standard physical memory and automated malware analysis solution
* [Volatility](https://github.com/volatilityfoundation/volatility) - An advanced memory forensics framework
* [VolatilityBot](https://github.com/mkorman90/VolatilityBot) - VolatilityBot is an automation tool for researchers cuts all the guesswork and manual tasks out of the binary extraction phase, or to help the investigator in the first steps of performing a memory analysis investigation
* [VolDiff](https://github.com/aim4r/VolDiff) - Malware Memory Footprint Analysis based on Volatility
* [WindowsSCOPE](http://www.windowsscope.com/index.php?page=shop.product_details&flypage=flypage.tpl&product_id=35&category_id=3&option=com_virtuemart) - another memory forensics and reverse engineering tool used for analyzing volatile memory. It is basically used for reverse engineering of malwares. It provides the capability of analyzing the Windows kernel, drivers, DLLs, virtual and physical memory

## Memory Imaging Tools

* [Belkasoft Live RAM Capturer](http://belkasoft.com/ram-capturer) - A tiny free forensic tool to reliably extract the entire content of the computer’s volatile memory – even if protected by an active anti-debugging or anti-dumping system
* [Linux Memory Grabber](https://github.com/halpomeranz/lmg/) - A script for dumping Linux memory and creating Volatility profiles.
* [Magnet RAM Capture](https://www.magnetforensics.com/free-tool-magnet-ram-capture/) - Magnet RAM Capture is a free imaging tool designed to capture the physical memory of a suspect’s computer. Supports recent versions of Windows
* [OSForensics](http://www.osforensics.com/) - OSForensics can acquire live memory on 32bit and 64bit systems. A dump of an individual process’s memory space or physical memory dump can be done

## Process Dump Tools

* [Microsoft User Mode Process Dumper](http://www.microsoft.com/en-us/download/details.aspx?id=4060) - The User Mode Process Dumper (userdump) dumps any running Win32 processes memory image on the fly
* [PMDump](http://www.ntsecurity.nu/toolbox/pmdump/) - PMDump is a tool that lets you dump the memory contents of a process to a file without stopping the process

## Timeline tools

* [Highlighter](https://www.fireeye.com/services/freeware/highlighter.html) - Free Tool available from Fire/Mandiant that will depict log/text file that can highlight areas on the graphic, that corresponded to a key word or phrase. Good for time lining an infection and what was done post compromise
* [Morgue](https://github.com/etsy/morgue) - A PHP Web app by Etsy for managing postmortems.
* [Plaso](https://github.com/log2timeline/plaso) -  a Python-based backend engine for the tool log2timeline
* [Timesketch](https://github.com/google/timesketch) - open source tool for collaborative forensic timeline analysis

## OSX Evidence Collection

* [Knockknock](https://github.com/synack/knockknock) - Displays persistent items(scripts, commands, binaries, etc.) that are set to execute automatically on OSX
* [mac_apt - macOS Artifact Parsing Tool](https://github.com/ydkhatri/mac_apt) - Plugin based forensics framework for quick mac triage that works on live machines, disk images or individual artifact files
* [OSX Auditor](https://github.com/jipegit/OSXAuditor) - OSX Auditor is a free Mac OS X computer forensics tool
* [OSX Collector](https://github.com/yelp/osxcollector) - An OSX Auditor offshoot for live response

## Windows Evidence Collection

* [AChoir](https://github.com/OMENScan/AChoir) - Achoir is a framework/scripting tool to standardize and simplify the process of scripting live acquisition utilities for Windows
* [Binaryforay](http://binaryforay.blogspot.co.il/p/software.html)
* [Crowd Response](http://www.crowdstrike.com/community-tools/) - Crowd Response by CrowdStrike is a lightweight Windows console application designed to aid in the gathering of system information for incident response and security engagements. It features numerous modules and output formats
* [FastIR Collector](https://github.com/SekoiaLab/Fastir_Collector) - FastIR Collector is a tool that collects different artefacts on live Windows systems and records the results in csv files. With the analyses of these artefacts, an early compromise can be detected
* [FECT](https://github.com/jipegit/FECT) - Fast Evidence Collector Toolkit (FECT) is a light incident response toolkit to collect evidences on a suspicious Windows computer. Basically it is intended to be used by non-tech savvy people working with a journeyman Incident Handler
* [Fibratus](https://github.com/rabbitstack/fibratus) - tool for exploration and tracing of the Windows kernel
* [IOC Finder](https://www.fireeye.com/services/freeware/ioc-finder.html) - IOC Finder is a free tool from Mandiant for collecting host system data and reporting the presence of Indicators of Compromise (IOCs). Support for Windows only
* [Fidelis ThreatScanner](https://www.fidelissecurity.com/resources/fidelis-threatscanner) - Fidelis ThreatScanner is a free tool from Fidelis Cybersecurity that uses OpenIOC and YARA rules to report on the state of an endpoint. The user provides OpenIOC and YARA rules and executes the tool. ThreatScanner measures the state of the system and, when the run is complete, a report for any matching rules is generated. Windows Only.
* [LOKI](https://github.com/Neo23x0/Loki) - Loki is a free IR scanner for scanning endpoint with yara rules and other indicators(IOCs)
* [Panorama](https://github.com/AlmCo/Panorama) - Fast incident overview on live Windows systems
* [PowerForensics](https://github.com/Invoke-IR/PowerForensics) - Live disk forensics platform, using PowerShell
* [PSRecon](https://github.com/gfoss/PSRecon/) - PSRecon gathers data from a remote Windows host using PowerShell (v2 or later), organizes the data into folders, hashes all extracted data, hashes PowerShell and various system properties, and sends the data off to the security team. The data can be pushed to a share, sent over email, or retained locally
* [RegRipper](https://code.google.com/p/regripper/wiki/RegRipper) - Regripper is an open source tool, written in Perl, for extracting/parsing information (keys, values, data) from the Registry and presenting it for analysis
* [TRIAGE-IR](https://code.google.com/p/triage-ir/) - Triage-IR is a IR collector for Windows