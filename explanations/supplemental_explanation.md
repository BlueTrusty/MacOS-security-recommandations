# Explanation of the rules for supplemental

## Rule: supplemental_cis_manual

### Severity: 

Explanation:
 List of CIS recommendations that are manual check in the CIS macOS Benchmark.
[cols="15%h, 85%a"]
 |===
 |Section
 |System Settings
|Recommendations
 |2.1.1.1 Audit iCloud Keychain +
 2.1.1.2 Audit iCloud Drive + 
 2.1.2 Audit App Store Password Settings +
 2.3.3.12 Ensure Computer Name Does Not Contain PII or Protected Organizational Information +
 2.5.1 Audit Siri Settings +
 2.6.1.3 Audit Location Services Access +
 2.6.6 Audit Lockdown Mode +
 2.8.1 Audit Universal Control Settings +
 2.11.2 Audit Touch ID and Wallet & Apple Pay Settings +  
 2.13.1 Audit Passwords System Preference Setting +
 2.14.1 Audit Notification & Focus Settings +  
 |===
[cols="15%h, 85%a"]
 |===
 |Section
 |Logging and Auditing
|Recommendations
 |3.7 Audit Software Inventory
 |===
[cols="15%h, 85%a"]
 |===
 |Section
 |System Access, Authentication and Authorization
|Recommendations
 |5.2.3 Ensure Complex Password Must Contain Alphabetic Characters Is Configured +
 5.2.4 Ensure Complex Password Must Contain Numeric Character Is Configured +
 5.2.5 Ensure Complex Password Must Contain Special Character Is Configured +
 5.2.6 Ensure Complex Password Must Contain Uppercase and Lowercase Characters Is Configured +
 5.3.1 Ensure All User Storage APFS Volumes are Encrypted +
 5.3.2 Ensure All User Storage CoreStorage Volumes are Encrypted +
 5.5 Ensure Login Keychain is Locked when the Computer Sleeps +
 |===
[cols="15%h, 85%a"]
 |===
 |Section
 |Applications
|6.2.1 Ensure Protect Mail Activity in Mail Is Enabled +
 6.3.2 Audit History and Remove History Items +
 6.3.5 Audit Hide IP Address in Safari Setting +
 6.3.7 Audit History and Remove History Items +
 |===


Command:
```bash
 ```

Expected result: 

## Rule: supplemental_controls

### Severity: 

Explanation:
 There are several requirements defined in National Institute of Standards and Technology (NIST) Special Publication (SP) 800-53, Security and Privacy Controls for Information Systems and Organizations, Revision 5 that can be met by making configuration changes to the operating system. However, NIST SP 800-53 (Rev. 5) contains a broad set of guidelines that attempt to address all aspects of an information system or systems within an organization. Because the macOS Security Compliance Project is tailored specifically to macOS, some requirements defined in NIST SP 800-53 (Rev. 5) are not applicable. 
This supplemental contains those controls that are assigned to a baseline in NIST SP 800-53 (Rev. 5) which cannot be addressed with a technical configuration for macOS. These controls can be accomplished though administrative or procedural processes within an organization or via integration of the macOS system into enterprise information systems which are configured to protect the systems within. 
[cols="15%h, 85%a"]
 |===
|Family
 |Access Control (AC)
|Controls 
 |link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=AC-1[AC-1], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=AC-2[AC-2], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=AC-3[AC-3(14)], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=AC-14[AC-14], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=AC-17[AC-17(4)], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=AC-22[AC-22]
|=== 
[cols="15%h, 85%a"]
 |===
|Family
 |Awareness and Training (AT)
|Controls
 |link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=AT-1[AT-1], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=AT-2[AT-2], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=AT-3[AT-3], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=AT-4[AT-4]
 |===
[cols="15%h, 85%a"]
 |===
|Family
 |Audit and Accountability (AU)
|Controls
 |link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=AU-1[AU-1], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=AU-6[AU-6], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=AU-9[AU-9(2)]
 |=== 
[cols="15%h, 85%a"]
 |===
|Family
 |Security Assessment and Authorization (CA)
|Controls
 |link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=CA-1[CA-1], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=CA-2[CA-2], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=CA-3[CA-3], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=CA-3[CA-3(6)], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=CA-5[CA-5], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=CA-6[CA-6], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=CA-7[CA-7], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=CA-7[CA-7(4)], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=CA-9[CA-9]
 |=== 
[cols="15%h, 85%a"]
 |===
|Family
 |Configuration Management (CM)
|Controls
 |link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=CM-1[CM-1], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=CM-4[CM-4], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=CM-8[CM-8], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=CM-10[CM-10], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=CM-11[CM-11]
 |=== 
[cols="15%h, 85%a"]
 |===
|Family
 |Contingency Planning (CP)
|Controls
 |link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=CP-1[CP-1], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=CP-2[CP-2], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=CP-3[CP-3], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=CP-4[CP-4], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=CP-9[CP-9], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=CP-10[CP-10]
 |=== 
[cols="15%h, 85%a"]
 |===
|Family
 |Identification and Authentication (IA)
|Controls
 |link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=IA-1[IA-1], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=IA-8[IA-8(1)], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=IA-8[IA-8(2)], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=IA-8[IA-8(3)], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=IA-8[IA-8(4)]
 |=== 
[cols="15%h, 85%a"]
 |===
|Family
 |Incident Response (IR)
|Controls
 |link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=IR-1[IR-1], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=IR-2[IR-2], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=IR-4[IR-4], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=IR-5[IR-5], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=IR-6[IR-6], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=IR-7[IR-7], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=IR-8[IR-8]
 |=== 
[cols="15%h, 85%a"]
 |===
|Family
 |Maintenance (MA)
|Controls
 |link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=MA-1[MA-1], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=MA-2[MA-2], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=MA-5[MA-5]
 |===
[cols="15%h, 85%a"]
 |===
|Family
 |Media Protection (MP)
|Controls
 |link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=MP-1[MP-1], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=MP-2[MP-2], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=MP-6[MP-6], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=MP-7[MP-7]
 |===
[cols="15%h, 85%a"]
 |===
|Family
 |Physical and Environmental Protection (PE)
|Controls
 |link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=PE-1[PE-1], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=PE-2[PE-2], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=PE-3[PE-3], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=PE-6[PE-6], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=PE-8[PE-8], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=PE-12[PE-12], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=PE-13[PE-13], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=PE-14[PE-14], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=PE-15[PE-15],  link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=PE-16[PE-16]
 |=== 
[cols="15%h, 85%a"]
 |===
|Family
 |Planning (PL)
|Controls
 |link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=PL-1[PL-1], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=PL-2[PL-2], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=PL-4[PL-4]
 |===
[cols="15%h, 85%a"]
 |===
|Family
 |Personnel Security (PS)

 |Controls
 |link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=PS-1[PS-1], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=PS-2[PS-2], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=PS-3[PS-3], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=PS-4[PS-4], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=PS-5[PS-5], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=PS-6[PS-6], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=PS-7[PS-7], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=PS-8[PS-8]
 |=== 
[cols="15%h, 85%a"]
 |===
|Family
 |Risk Assessment (RA)
|Controls
 |link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=RA-1[RA-1], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=RA-2[RA-2], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=RA-3[RA-3], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=RA-5[RA-5]
 |===
[cols="15%h, 85%a"]
 |===
|Family
 |System and Services Acquisition (SA)
|Controls
 |link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=SA-1[SA-1], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=SA-2[SA-2], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=SA-3[SA-3], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=SA-4[SA-4], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=SA-4[SA-4(10)], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=SA-5[SA-5], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=SA-9[SA-9]
 |===
[cols="15%h, 85%a"]
 |===
|Family
 |System and Communications Protection (SC)
|Controls
 |link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=SC-1[SC-1], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=SC-7[SC-7(3)], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=SC-7[SC-7(7)], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=SC-7[SC-7(8)], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=SC-7[SC-7(18)], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=SC-7[SC-7(21)], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=SC-12[SC-12], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=SC-12[SC-12(1)], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=SC-20[SC-20], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=SC-22[SC-22], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=SC-23[SC-23]
 |===
[cols="15%h, 85%a"]
 |===
|Family
 |System and Information Integrity (SI)
|Controls
 |link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=SI-1[SI-1], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=SI-4[SI-4], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=SI-4[SI-4(2)], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=SI-4[SI-4(4)], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=SI-4[SI-4(5)], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=SI-4[SI-4(12)], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=SI-4[SI-4(14)], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=SI-4[SI-4(20)], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=SI-4[SI-4(22)], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=SI-5[SI-5], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=SI-7[SI-7(2)], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=SI-8[SI-8(2)], link:https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=SI-12[SI-12]
 |===


Command:
```bash
 ```

Expected result: 

## Rule: supplemental_filevault

### Severity: 

Explanation:
 The supplemental guidance found in this section is applicable for the following rules:
   * system_settings_filevault_enforce
In macOS 11 the internal Apple File System (APFS) data volume can be protected by FileVault. The system volume is always cryptographically protected (T2 and Apple Silicon) and is a read-only volume.
NOTE: FileVault uses an AES-XTS data encryption algorithm to protect full volumes of internal and external storage. Macs with a secure enclave (T2 and Apple Silicon) utilize the hardware security features of the architecture.
FileVault is described in detail here: link:https://support.apple.com/guide/security/volume-encryption-with-filevault-sec4c6dc1b6e/web[].
FileVault can be enabled in two ways within the macOS. It can be managed using the fdesetup command or by a Configuration Profile. When enabling FileVault via either of the aforementioned methods, you will be required to enter a username and password, which must be a local Open Directory account with a valid SecureToken password.
[discrete]
 ==== Using the fdesetup Command
 When enabling FileVault via the command line in the Terminal application, you can run the following command.
 [source,bash]
 ----
 /usr/bin/fdesetup enable
 ----
 Running this command will prompt you for a username and password and then enable FileVault and return the personal recovery key. There are a number of management features available when managing FileVault via the command line that are not available when using a configuration profile. More information on these management features is available in the man page for `fdesetup`. 
NOTE: Apple has deprecated `fdesetup` command line tool from recognizing user name and password for security reasons and may remove the ability in future versions of macOS. 
[discrete]
 ==== Using a Configuration Profile
When managing FileVault with a configuration profile, you must deploy a profile with the payload type `com.apple.MCX.FileVault2`. When using the Enable key to enable FileVault with a configuration profile, you must include 1 of the following:
[source,xml]
 ----
 <key>Enable</key>
 <string>On</string>
 <key>Defer</key>
 <true />
 ----
 [source,xml]
 ----
 <key>Enable</key>
 <string>On</string>
 <key>UserEntersMissingInfo</key>
 <true/>
 ----
If using the Defer key it will prompt for the user name and password at logout.
The `UserEntersMissingInfo` key will only work if installed through manual installation, and it will prompt for the username and password immediately. 
When using a configuration profile, you can escrow the Recovery key to a Mobile Device Management (MDM) server. Documentation for that can be found on Apple's Developer site: link:https://developer.apple.com/documentation/devicemanagement/fderecoverykeyescrow[].
It's recommended that you use a Personal Recovery key instead of an Institutional key as it will generate a specific key for each device. You can find more guidance on choosing a recover key here: link:https://docs.jamf.com/technical-papers/jamf-pro/administering-filevault-macos/10.7.1/Choosing_a_Recovery_Key.html[].
NOTE: FileVault currently only uses password-based authentication and cannot be done using a smartcard or any other type of multi-factor authentication. 


Command:
```bash
 ```

Expected result: 

## Rule: supplemental_firewall_pf

### Severity: 

Explanation:
 The supplemental guidance found in this section is applicable for the following rules:
*	os_firewall_default_deny_require
macOS contains an application layer firewall (ALF) and a packet filter (PF) firewall.
  * The ALF can block incoming traffic on a per-application basis and prevent applications from gaining control of network ports, but it cannot be configured to block outgoing traffic.
   ** More information on the ALF can be found here: https://support.apple.com/en-ca/HT201642 
  *  The PF firewall can manipulate virtually any packet data and is highly configurable. 
   ** More information on the BF firewall can be found here: https://www.openbsd.org/faq/pf/index.html
Below is a script that configures ALF and the PF firewall to meet the requirements defined in NIST SP 800-53 (Rev. 5). The script will make sure the application layer firewall is enabled, set logging to "detailed", set built-in signed applications to automatically receive incoming connections, and set downloaded signed applications to automatically receive incoming connections. It will then create a custom rule set and copy `com.apple.pfctl.plis` from `/System/Library/LaunchDaemons/` into the `/Library/LaunchDaemons` folder and name it `800-53.pfctl.plist`. This is done to not conflict with the system's pf ruleset.
The custom pf rules are created at `/etc/pf.anchors/800_53_pf_anchors`.
The ruleset will block connections on the following ports:
[%header,width="100%",cols="3,7"]
 |===
 ^.^|Port
 ^.^|Service
|548
 |Apple File Protocol (AFP)
|1900
 |Bonjour
|79
 |Finger
|20, 21
 |File Transfer Protocol (FTP)
|80
 |HTTP
|icmp
 |ping
|143
 |Internet Message Access Protocol (IMAP)
|993
 |Internet Message Access Protocol over SSL (IMAPS)
|3689
 |Music Sharing
|5353
 |mDNSResponder
|2049
 |Network File System (NFS)
|49152
 |Optical Media Sharing
|110
 |Post Office Protocol (POP3)
|995
 |Post Office Protocol Secure (POP3S)
|631
 |Printer Sharing
|3031
 |Remote Apple Events
|5900
 |Screen Sharing
|137, 138, 138, 445
 |Samba (SMB)
|25
 |Simple Mail Transfer Protocol (SMTP)
|22
 |Secure Shell (SSH)
|23
 |Telnet
|69
 |Trivial File Transfer Protocol (TFTP)
|540
 |Unix-to-Unix Copy (UUCP)
|===
For more on configuring the PF firewall check out the man pages on `pf.conf` and `pfctl`.
[source,bash]
 ----
 include::../../includes/enablePF-mscp.sh[]
 ----


Command:
```bash
 ```

Expected result: 

## Rule: supplemental_password_policy

### Severity: 

Explanation:
 The supplemental guidance found in this section is applicable for the following rules:
  * pwpolicy_lower_case_character_enforce
   * pwpolicy_upper_case_character_enforce
   * pwpolicy_account_inactivity_enforce
   * pwpolicy_minimum_lifetime_enforce
Password policies should be enforced as much as possible via Configuration Profiles. However, the following policies are currently not enforceable via Configuration Profiles, and must therefore be enabled using the `pwpolicy` command:
  * Enforcing at least 1 lowercase character
   * Enforcing at least 1 uppercase character
   * Disabling an account after 35 days of inactivity
   * Password minimum lifetime
To set the local policy to meet these requirements, save the following XML password policy to a file.
[source,xml]
 ----
 include::../../includes/pwpolicy.xml[]
 ----
Run the following command to load the new policy file, substituting the path to the file in place of "$pwpolicy_file".
[source,bash]
 ----
 /usr/bin/pwpolicy setaccountpolicies $pwpolicy_file
 ----
[NOTE]
 ====
 If directory services is being utilized, password policies should come from the domain.
 ====


Command:
```bash
 ```

Expected result: 

## Rule: supplemental_smartcard

### Severity: 

Explanation:
 The supplemental guidance found in this section is applicable for the following rules:
  * auth_ssh_password_authentication_disable
   * auth_smartcard_enforce
   * auth_smartcard_certificate_trust_enforce_moderate
   * auth_smartcard_certificate_trust_enforce_high
   * auth_smartcard_allow
   * auth_pam_sudo_smartcard_enforce
   * auth_pam_su_smartcard_enforce
   * auth_pam_login_smartcard_enforce
macOS supports smartcards, such as U.S. Personal Identity Verification (PIV) cards and U.S. Department of Defense Common Access Cards (CAC). Smartcards can be used on a macOS for the following:
  * Authentication (Loginwindow, Screensaver, SSH, PKINIT, Safari, Finder, and PAM Authorization (`sudo`, `login`, and `su`) )
   * Digital Encryption
   * Digital Signing
   * Remote Access (VPN:L2TP)
   * Port-based Network Access Control (802.1X)
   * Keychain Unlock
macOS has built-in support for USB CCID class-compliant smartcard readers.
[discrete]
 ==== Smartcard Pairing
 The default method for using smartcards in macOS is a method called "local account pairing". Local account pairing is automatically initiated when a user inserts a smartcard into the Mac. The user is prompted to pair their smartcard with their account. If a user receives a new smartcard, the previous card must be unpaired, and the new card paired to the account. Local account pairing employs fixed key mapping with the hash of a public key on the user's smartcard with a local account.
[discrete]
 ==== Smartcard Attribute Mapping
 Smartcards can be used to authenticate against a directory via attribute mapping configured in `/private/etc/SmartcardLogin.plist`. This file takes precedence over local account pairing. Attribute mapping matches the configured certificate field values from the smart card to the value in a directory. This may be used with network accounts, mobile accounts, or local accounts.
[discrete]
 ==== Smartcard Management in macOS
The following settings are available to manage smartcards (com.apple.security.smartcard):
[%header,cols="2,1,7"]
 |===
 |Key
 |Type
 |Value
<.^|userPairing
 ^.^|bool
 |If false, users will not get the pairing dialog, although existing pairings will still work.
<.^|allowSmartCard
 ^.^|bool
 |If false, the SmartCard is disabled for logins, authorizations, and screensaver unlocking. It is still allowed for other functions, such as signing emails and web access. A restart is required for a change of setting to take effect.
<.^|checkCertificateTrust
 ^.^|int
 a|Valid values are 0-3:
- 0: certificate trust check is turned off
- 1: certificate trust check is turned on. Standard validity check is being performed but this does not include additional revocation checks.
- 2: certificate trust check is turned on, and a soft revocation check is performed. Until the certificate is explicitly rejected by CRL/OCSP, it is considered valid. This implies that unavailable/unreachable CRL/OCSP allows this check to succeed.
- 3: certificate trust check is turned on, plus a hard revocation check is performed. Unless CRL/OCSP explicitly states that "this certificate is OK", the certificate is considered invalid. This is the most secure value for this setting.
<.^|oneCardPerUser
 ^.^|bool
 |If true, a user can pair with only one smartcard, although existing pairings will be allowed if already set up.
<.^|enforceSmartCard
 ^.^|bool
 |If true, a user can only login or authenticate with a smartcard.
<.^|tokenRemovalAction
 ^.^|int
 |If 1, the screen saver will automatically when the smartcard is removed.
<.^|allowUnmappedUsers
 ^.^|int
 |If 1, allows users who are in a directory group to be exempt from smartcard-only enforcement. The group allowed for exemption is defined in /private/etc/SmartcardLogin.plist
|===
A custom configuration profile (`com.apple.loginwindow`) should be created to disable automatic login when FileVault is enabled. This ensures that authorized users boot their Macs, enter a password at the pre-boot screen (which decrypts the boot volume), and are then presented with a login window where they can authenticate with a smartcard.
[%header,cols="2,1,7"]
 |===
 |Key
 |Type
 |Value
<.^|DisableFDEAutoLogin
 ^.^|bool
 |If true, both Extensible Firmware Interface (EFI) login password and loginwindow PIN are required.
|===
NOTE: DisableFDEAutoLogin does not have to be set on Apple Silicon based macOS systems that are smartcard enforced as smartcards are available at pre-boot.
[discrete]
 ==== Trusted Authorities
 The macOS allows users to specify which certificate authorities (CA) can be used for trust evaluation during smartcard authentication. Only CAs listed in the TrustedAuthorities section of the SmartcardLogin.plist will be evaluated as trusted. This setting only works if `checkCertificateTrust` is set to either 1, 2, or 3 in `com.apple.security.smartcard`.
To get the SHA-256 hash in the correct format, run the following command within terminal:
 [source,bash]
 ----
 /usr/bin/openssl x509 -noout -fingerprint -sha256 -inform pem -in <issuer cert> | /usr/bin/awk -F '=' '{print $2}' |  /usr/bin/sed 's/://g'
 ----
To configure Trusted Authorities, the `SmartcardLogin.plist` should be minimally configured as below:
[source,xml]
 ----
 <?xml version="1.0" encoding="UTF-8"?>
 <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
 <plist version="1.0">
 <dict>
     <key>AttributeMapping</key>
     <dict>
           <key>fields</key>
           <array>
               <string>NT Principal Name</string>
           </array>
           <key>formatString</key>
           <string>Kerberos:$1</string>
           <key>dsAttributeString</key>
           <string>dsAttrTypeStandard:AltSecurityIdentities</string>
     </dict>
     <key>TrustedAuthorities</key>
   <array>
       <string>SHA256_HASH_OF_CERTDOMAIN_1,SHA256_HASH_OF_CERTDOMAIN_2</string>
   </array>
 </dict>
 </plist>
 ----
[discrete]
 ==== Smartcard Enforcement Exemption
[discrete]
 ===== Group Exemption
Starting in macOS 10.15, enforcement on a system can be granularly configured by adding a field to `/private/etc/SmartcardLogin.plist`. The `NotEnforcedGroup` can be added to the file to list a Directory group that will not be included in smartcard enforcement. In order to activate this feature, `enforceSmartCard` and `allowUnmappedUsers` must be applied via a configuration profile (`com.apple.security.smartcard`).
To configure the `NotEnforcedGroup`, the `SmartcardLogin.plist` should be minimally configured as follows:
 [source,xml]
 ----
 <?xml version="1.0" encoding="UTF-8"?>
 <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
 <plist version="1.0">
 <dict>
     <key>AttributeMapping</key>
     <dict>
           <key>fields</key>
           <array>
               <string>NT Principal Name</string>
           </array>
           <key>formatString</key>
           <string>Kerberos:$1</string>
           <key>dsAttributeString</key>
           <string>dsAttrTypeStandard:AltSecurityIdentities</string>
     </dict>
     <key>TrustedAuthorities</key>
   <array>
       <string>SHA256_HASH_OF_CERTDOMAIN_1,SHA256_HASH_OF_CERTDOMAIN_2</string>
   </array>
     <key>NotEnforcedGroup</key>
     <string>EXEMPTGROUP</key>
 </dict>
 </plist>
 ----
Once a system is configured for the `NotEnforcedGroup` a user can be added to the assigned group by running the following:
 [source,bash]
 ----
 /usr/sbin/dseditgroup -o edit -a <exempt_user> -t user <notenforcegroup>
 ----
[discrete]
 ===== User Exemption
Alternatively, if a single user needs to be exempt for a period of time, `kDSNativeAttrTypePrefix:SmartCardEnforcement` can be set in the user's Open Directory record. The following values can be set:
* 0 - The system default is respected.
 * 1 - Smartcard enforcement is enabled.
 * 2 - Smartcard enforcement is disabled. 
NOTE: In Active Directory environments, the value of the `userAccountControl` attribute is respected.
Run the following command to set the exemption when booted from macOS:
 [source,bash]
 ----
 /usr/bin/dscl . -append /Users/<username> SmartCardEnforcement 2
 ----
Run the following command to set the exemption when booted from Recovery:
 [source,bash]
 ----
 /usr/bin/defaults write /Volumes/Macintosh
 HD/var/db/dslocal/nodes/Default/users/<username> SmartCardEnforcement -array-add 2
 ----
 NOTE: When booted to recovery on an Apple Silicon Mac, run the following after setting the exemption.
 `/usr/sbin/diskutil apfs updatePreboot /Volumes/Macintosh
 HD`
[discrete]
 ===== Temporary Exemption
On an Apple Silicon Mac, if a temporary exemption is needed, `security filevault skip-sc-enforcement` will disable smartcard enforcement on next boot only. 
Run the following command to set the temporary exemption when booted from Recovery:
 [source,bash]
 ----
 /usr/bin/security filevault skip-sc-enforcement <data volume UUID> set
 ----
To obtain the `data volume UUID` run the following:
 [source,bash]
 ----
 /usr/sbin/diskutil apfs listGroups | /usr/bin/awk -F: '/ Data/ { getline; gsub(/ /,""); print $2}'
 ----
[discrete]
 ==== Pluggable Authentication Module (PAM)
Terminal sessions in macOS can be configured for smartcard enforcement by modifying the PAM modules for `sudo`, `su`, and `login`.
[source,bash]
 ----
 /etc/pam.d/sudo
 # sudo: auth account password session
 auth        sufficient    pam_smartcard.so
 auth        required      pam_opendirectory.so
 auth        required      pam_deny.so
 account     required      pam_permit.so
 password    required      pam_deny.so
 session     required      pam_permit.so
 ----
[source,bash]
 ----
 /etc/pam.d/su
 # su: auth account password session
 auth        sufficient    pam_smartcard.so
 auth        required      pam_rootok.so
 auth        required      pam_group.so no_warn group=admin,wheel ruser root_only fail_safe
 account     required      pam_permit.so
 account     required      pam_opendirectory.so no_check_shell
 password    required      pam_opendirectory.so
 session     required      pam_launchd.so
 ----
[source,bash]
 ----
 /etc/pam.d/login
 # login: auth account password session
 auth        sufficient    pam_smartcard.so
 auth        optional      pam_krb5.so use_kcminit
 auth        optional      pam_ntlm.so try_first_pass
 auth        optional      pam_mount.so try_first_pass
 auth        required      pam_opendirectory.so try_first_pass
 auth        required      pam_deny.so
 account     required      pam_nologin.so
 account     required      pam_opendirectory.so
 password    required      pam_opendirectory.so
 session     required      pam_launchd.so
 session     required      pam_uwtmp.so
 session     optional      pam_mount.so
 ----
[discrete]
 ==== Screen Sharing and Screen Recording
 macOS will disable support for TouchID, Watch, or Smartcard authentication when being watched or recorded. This can cause certain portions of the system to not recognize your smartcard. 
In Unified Logging you'll notice an entry such as
 [source,bash]
 ----
 2022-07-14 16:45:46.880038-0400 0x2F97 Info 0xC8D2 1600 SecurityAgent: (SecurityAgent) [com.apple.Authorization:SecurityAgent] Screen is being watched, no Touch ID, Watch or SmartCard support is allowed
 ----
 This can be remediated by writing the preference domain com.apple.authorization with the key ignoreARD.
`defaults write com.apple.Authorization ignoreARD -bool true`
Or applied system wide with a configuration profile named `com.apple.security.authorization.mobileconfig` in the project's `includes` folder.
 [source,xml]
 ----
 <key>PayloadType</key>
 <string>com.apple.security.authorization</string>
 <key>ignoreArd</key>
 <true/>
 ----  


Command:
```bash
 ```

Expected result: 

