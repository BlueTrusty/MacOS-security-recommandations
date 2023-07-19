# Explanation of the rules for inherent

## Rule: audit_record_reduction_report_generation

### Severity: 

Explanation:
 The system _IS_ configured with the ability provide and implement an audit record reduction and report generation capability. 
Audit record reduction is a process that manipulates collected audit log information and organizes it into a summary format that is more meaningful to analysts. Audit record reduction and report generation capabilities do not always emanate from the same system or from the same organizational entities that conduct audit logging activities. The audit record reduction capability includes modern data mining techniques with advanced data filters to identify anomalous behavior in audit records. The report generation capability provided by the system can generate customizable reports. Time ordering of audit records can be an issue if the granularity of the timestamp in the record is insufficient.
Audit record reduction and report generation can be done with tools built into macOS such as auditreduce and praudit. These tools are protected by System Integrity Protection (SIP).


Command:
```bash
 The technology supports this requirement and cannot be configured to be out of compliance. The technology inherently meets this requirement.
```

Expected result: 

## Rule: os_allow_info_passed

### Severity: 

Explanation:
 The information system _IS_ configured to allow the transfer of information to and from other operating systems and users.
The macOS is a UNIX 03-compliant operating system, which allows owners of object to have discretion over who should be authorized to access information.
link:https://developer.apple.com/library/archive/documentation/Security/Conceptual/AuthenticationAndAuthorizationGuide/Permissions/Permissions.html[]


Command:
```bash
 The technology supports this requirement and cannot be configured to be out of compliance. The technology inherently meets this requirement.
```

Expected result: 

## Rule: os_application_sandboxing

### Severity: 

Explanation:
 The inherent configuration of the macOS _IS_ in compliance as Apple has implemented multiple features Mandatory access controls (MAC), System Integrity Protection (SIP), and application sandboxing. 
link:https://support.apple.com/guide/security/system-integrity-protection-secb7ea06b49/web[]
link:https://developer.apple.com/library/archive/documentation/Security/Conceptual/AppSandboxDesignGuide/AboutAppSandbox/AboutAppSandbox.html[]


Command:
```bash
 The technology supports this requirement and cannot be configured to be out of compliance. The technology inherently meets this requirement.
```

Expected result: 

## Rule: os_change_security_attributes

### Severity: 

Explanation:
 The information system _IS_ configured to allow administrators to modify security settings and system attributes. 
The macOS is a UNIX 03-compliant operating system, which allows administrators of the system to change security settings and system attributes, including those which are kept within preference panes that are locked for standard users. . 
link:https://support.apple.com/guide/mac-help/change-permissions-for-files-folders-or-disks-mchlp1203/mac[]


Command:
```bash
 The technology supports this requirement and cannot be configured to be out of compliance. The technology inherently meets this requirement.
```

Expected result: 

## Rule: os_crypto_audit

### Severity: 

Explanation:
 The information system _IS_ configured to implement cryptographic mechanisms to protect the integrity of audit information and audit tools. 
The Apple T2 Security Chip includes a dedicated Advanced Encryption Standard (AES) crypto engine built into the direct memory access (DMA) path between the flash storage and main system memory, which powers line-speed encrypted storage with FileVault and makes internal volume highly efficient. 
link:https://www.apple.com/euro/mac/shared/docs/Apple_T2_Security_Chip_Overview.pdf[]
NOTE: This will only apply to a Mac that includes a T2 security chip. 


Command:
```bash
 The technology supports this requirement and cannot be configured to be out of compliance. The technology inherently meets this requirement.
```

Expected result: 

## Rule: os_enforce_access_restrictions

### Severity: 

Explanation:
 The information system _IS_ configured to enforce access restrictions and support auditing of the enforcement actions.
The inherent configuration of a macOS provides users with the ability to set their own permission settings to control who can view and alter files on the computer. 
link:https://support.apple.com/guide/mac-help/change-permissions-for-files-folders-or-disks-mchlp1203/mac[]


Command:
```bash
 The technology supports this requirement and cannot be configured to be out of compliance. The technology inherently meets this requirement.
```

Expected result: 

## Rule: os_error_message

### Severity: 

Explanation:
 The information system _IS_ configured to generate error messages that provide the information necessary for corrective actions without revealing information that could be exploited by adversaries.


Command:
```bash
 The technology supports this requirement and cannot be configured to be out of compliance. The technology inherently meets this requirement.
```

Expected result: 

## Rule: os_fail_secure_state

### Severity: 

Explanation:
 The information system _IS_ configured to fail to a known safe state in the event of a failed system initialization, shutdown, or abort. 
Failure to a known safe state helps prevent systems from failing to a state that may cause loss of data or unauthorized access to system resources. 
Apple File System (APFS) is the default file system for Mac computers using macOS 10.13 and all later versions. APFS includes native encryption, safe document saves, stable snapshots, and crash protection; these features ensure that the macOS fails to safe state. 
link:https://developer.apple.com/videos/play/wwdc2017/715/[]


Command:
```bash
 The technology supports this requirement and cannot be configured to be out of compliance. The technology inherently meets this requirement.
```

Expected result: 

## Rule: os_grant_privs

### Severity: 

Explanation:
 The information system _IS_ configured to allow current administrators to promote standard users to administrator user status. 
The macOS is a UNIX 03-compliant operating system which allows administrators of the system to grant privileges to other users.
link:https://support.apple.com/guide/mac-help/set-up-other-users-on-your-mac-mtusr001/mac[]


Command:
```bash
 The technology supports this requirement and cannot be configured to be out of compliance. The technology inherently meets this requirement.
```

Expected result: 

## Rule: os_implement_cryptography

### Severity: 

Explanation:
 The information system _IS_ configured to implement approved cryptography to protect information. 
Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The operating system must implement cryptographic modules that adhere to the higher standards that have been tested, validated, and approved by the federal government. 
Apple is committed to the FIPS validation process and historically has always submitted and validated the cryptographic modules in macOS. macOS Ventura will be submitted for FIPS validation.
link:https://csrc.nist.gov/Projects/cryptographic-module-validation-program/validated-modules[]
link:https://support.apple.com/en-us/HT201159[]


Command:
```bash
 The technology supports this requirement and cannot be configured to be out of compliance. The technology inherently meets this requirement using FIPS Validated Cryptographic Modules.
```

Expected result: 

## Rule: os_implement_memory_protection

### Severity: 

Explanation:
 The information system _IS_ configured to implement non-executable data to protect memory from code execution.
Some adversaries launch attacks with the intent of executing code in non-executable regions of memory or in memory locations that are prohibited (e.g., buffer overflow attacks). Security safeguards (e.g., data execution prevention and address space layout randomization) can be employed to protect non-executable regions of memory. Data execution prevention safeguards can either be hardware-enforced or software-enforced; hardware-enforced methods provide the greater strength of mechanism. 
macOS supports address space layout randomization (ASLR), position-independent executable (PIE), Stack Canaries, and NX stack and heap protection.
link:https://developer.apple.com/library/archive/documentation/Darwin/Conceptual/64bitPorting/transition/transition.html[]
link:https://developer.apple.com/library/archive/qa/qa1788/_index.html[]
link:https://www.apple.com/macos/security/[]


Command:
```bash
 The technology supports this requirement and cannot be configured to be out of compliance. The technology inherently meets this requirement.
```

Expected result: 

## Rule: os_isolate_security_functions

### Severity: 

Explanation:
 The information system _IS_ configured to isolate security functions from non-security functions. 
link:https://support.apple.com/guide/security/welcome/web[]


Command:
```bash
 The technology supports this requirement and cannot be configured to be out of compliance. The technology inherently meets this requirement.
```

Expected result: 

## Rule: os_limit_auditable_events

### Severity: 

Explanation:
 Without the capability to restrict which roles and individuals can select which events are audited, unauthorized personnel may be able to prevent the auditing of critical events. Misconfigured audits may degrade the system's performance by overwhelming the audit log. Misconfigured audits may also make it more difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.


Command:
```bash
 The technology supports this requirement and cannot be configured to be out of compliance. The technology inherently meets this requirement.
```

Expected result: 

## Rule: os_limit_gui_sessions

### Severity: 

Explanation:
 The information system _IS_ configured to limit the number of concurrent graphical user interface (GUI) sessions to a maximum of ten for all users. 
Operating system management includes the ability to control the number of users and user sessions that utilize an operating system. Limiting the number of allowed users and sessions per user helps reduce the risks related to Denial-of-Service (DoS) attacks. This requirement addresses concurrent sessions for information system accounts and does not address concurrent sessions by single users via multiple system accounts. The maximum number of concurrent sessions should be defined based upon mission needs and the operational environment for each system.


Command:
```bash
 The technology supports this requirement and cannot be configured to be out of compliance. The technology inherently meets this requirement.
```

Expected result: 

## Rule: os_logical_access

### Severity: 

Explanation:
 The information system _IS_ configured to enforce an approved authorization process before granting users logical access. 
The inherent configuration of the macOS does not grant users logical access without authorization. Authorization is achieved on the macOS through permissions, which are controlled at many levels, from the Mach and BSD components of the kernel, through higher levels of the operating system and, for networked applications, through the networking protocols. Permissions can be granted at the level of directories, subdirectories, files or applications, or specific data within files or functions within applications. 
link:https://developer.apple.com/library/archive/documentation/Security/Conceptual/AuthenticationAndAuthorizationGuide/Permissions/Permissions.html[]


Command:
```bash
 The technology supports this requirement and cannot be configured to be out of compliance. The technology inherently meets this requirement.
```

Expected result: 

## Rule: os_logoff_capability_and_message

### Severity: 

Explanation:
 Provides a logout capability for user-initiated communications sessions whenever authentication is used to gain access to the system.
Displays an explicit logout message to users indicating the reliable termination of authenticated communications sessions.


Command:
```bash
 The technology supports this requirement and cannot be configured to be out of compliance. The technology inherently meets this requirement.
```

Expected result: 

## Rule: os_malicious_code_prevention

### Severity: 

Explanation:
 The inherent configuration of the macOS _IS_ in compliance as Apple has designed the system with three layers of protection against malware. Each layer of protection is comprised of one or more malicious code protection mechanisms, which are automatically implemented and which, collectively, meet the requirements of all applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance for malicious code prevention.
1. This  first layer of defense targets the distribution of malware; the aim is to prevent malware from ever launching. 
 The following mechanisms are inherent to the macOS design and constitute the first layer of protection against malicious code: 
 *	The Apple App Store: the safest way to add new applications to a Mac is by downloading them from the App Store; all apps available for download from the App Store have been reviewed for signs of tampering and signed by Apple to indicate that the app meets security requirements and does not contain malware. 
 *	XProtect: a built-in, signature-based, anti-virus, anti-malware technology inherent to all Macs. XProtect automatically detects and blocks the execution of known malware. 
   *	In macOS 10.15 and all subsequent releases, XProtect checks for known malicious content when:
     *	an app is first launched,
     *	an app has been changed (in the file system), and
     *	XProtect signatures are updated.
 *	YARA: another built-in tool (inherent to all Macs), which conducts signature-based detection of malware. Apple updates YARA rules regularly.
 *	Gatekeeper: a security feature inherent to all Macs; Gatekeeper scans apps to detect malware and/or revocations of a developer's signing certificate and prevents unsafe apps from running.
 *	Notarization: Apple performs regular, automated scans to detect signs of malicious content and to verify developer ID-signed software; when no issues are found, Apple notarizes the software and delivers the results of scans to the system owner. 
2. The second layer of defense targets malware that manages to appear on a Mac before it runs; the aim is to quickly identify and block any malware present on a Mac in order to prevent the malware from running and further spreading. 
 The following mechanisms are inherent to the macOS design and constitute the second layer of protection against malicious code: 
 *	XProtect (defined above).
 *	Gatekeeper (defined above).
 *	Notarization (defined above).
3.  The third layer of defense targets infected Mac system(s); the aim is to remediate Macs on which malware has managed to successfully execute. 
 The following mechanism is inherent to the macOS design and constitutes the third layer of protection against malicious code: 
 *	Apple's XProtect: a technology included on all macOS systems. XProtect will remediate infections upon receiving updated information delivered and when infections are detected
link:https://support.apple.com/guide/security/protecting-against-malware-sec469d47bd8/1/web/1[]
link:https://support.apple.com/guide/security/app-security-overview-sec35dd877d0/web[]


Command:
```bash
 The technology supports this requirement and cannot be configured to be out of compliance. The technology inherently meets this requirement.
```

Expected result: 

## Rule: os_map_pki_identity

### Severity: 

Explanation:
 Without mapping the certificate used to authenticate to the user account, the ability to determine the identity of the individual user or group will not be available for forensic analysis.


Command:
```bash
 For directory bound systems, the technology supports this requirement and cannot be configured to be out of compliance. The technology inherently meets this requirement.
```

Expected result: 

## Rule: os_mfa_network_access

### Severity: 

Explanation:
 The information system implements multifactor authentication for network access to privileged accounts.


Command:
```bash
 For directory bound systems:
The technology supports this requirement and cannot be configured to be out of compliance. The technology inherently meets this requirement.
```

Expected result: 

## Rule: os_mfa_network_non-priv

### Severity: 

Explanation:
 The information system implements multifactor authentication for network access to non-privileged accounts.


Command:
```bash
 For directory bound systems:
The technology supports this requirement and cannot be configured to be out of compliance. The technology inherently meets this requirement.
```

Expected result: 

## Rule: os_obscure_password

### Severity: 

Explanation:
 The information system _IS_ configured to obscure feedback of authentication information during the authentication process to protect the information from possible exploitation by unauthorized individuals.
The inherent configuration of a macOS uses NSSecureTextField for any text field that receives a password, which automatically obscures text which is entered.
link:https://developer.apple.com/documentation/appkit/nssecuretextfield[]


Command:
```bash
 The technology supports this requirement and cannot be configured to be out of compliance. The technology inherently meets this requirement.
```

Expected result: 

## Rule: os_peripherals_identify

### Severity: 

Explanation:
 Without identifying devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity.
Peripherals include, but are not limited to, such devices as flash drives, external storage, and printers.


Command:
```bash
 The technology supports this requirement and cannot be configured to be out of compliance. The technology inherently meets this requirement.
```

Expected result: 

## Rule: os_predictable_behavior

### Severity: 

Explanation:
 The information system behaves in a predictable and documented manner that reflects organizational and system objectives when invalid inputs are received.


Command:
```bash
 The technology supports this requirement and cannot be configured to be out of compliance. The technology inherently meets this requirement.
```

Expected result: 

## Rule: os_prevent_priv_execution

### Severity: 

Explanation:
 In certain situations, software applications/programs need to execute with elevated privileges to perform required functions. However, if the privileges required for execution are at a higher level than the privileges assigned to organizational users invoking such applications/programs, those users are indirectly provided with greater privileges than assigned by the organizations.Some programs and processes are required to operate at a higher privilege level and therefore should be excluded from the organization-defined software list after review.
The inherent configuration of the macOS does not allow for non-privileged users to be able to execute functions requiring privilege. 
link:https://developer.apple.com/library/archive/documentation/Security/Conceptual/AuthenticationAndAuthorizationGuide/Permissions/Permissions.html[]


Command:
```bash
 The technology supports this requirement and cannot be configured to be out of compliance. The technology inherently meets this requirement.
```

Expected result: 

## Rule: os_prevent_priv_functions

### Severity: 

Explanation:
 The information system _IS_ configured to block standard users from executing privileged functions. 
Privileged functions include disabling, circumventing, or altering implemented security safeguards and countermeasures. 
The inherent configuration of the macOS does not allow for non-privileged users to be able to execute functions requiring privilege. 
link:https://developer.apple.com/library/archive/documentation/Security/Conceptual/AuthenticationAndAuthorizationGuide/Introduction/Introduction.html[]


Command:
```bash
 The technology supports this requirement and cannot be configured to be out of compliance. The technology inherently meets this requirement.
```

Expected result: 

## Rule: os_prevent_unauthorized_disclosure

### Severity: 

Explanation:
 The information system _IS_ configured to ensure that the unauthorized disclosure of data does not occur when resources are shared. 
The inherent configuration of the macOS does not allow for resources to be shared between users without authorization. 
link:https://developer.apple.com/library/archive/documentation/Security/Conceptual/AuthenticationAndAuthorizationGuide/Permissions/Permissions.html[]


Command:
```bash
 The technology supports this requirement and cannot be configured to be out of compliance. The technology inherently meets this requirement.
```

Expected result: 

## Rule: os_prohibit_remote_activation_collab_devices

### Severity: 

Explanation:
 The inherent configuration of the macOS _IS_ in compliance.
Apple has implemented a green light physically next to your camera that will glow when the camera is activated. There is an orange dot indicator by the Control Center pull down menu item to indicate when the system's microphone is listening or activated.
The macOS has built into the system, the ability to grant or deny access to the camera and microphone which requires the application to have an entitlement to use the device.
link:https://support.apple.com/guide/mac-help/use-the-built-in-camera-mchlp2980/mac[]
link:https://support.apple.com/guide/mac-help/control-access-to-your-camera-mchlf6d108da/mac[]
link:https://support.apple.com/guide/mac-help/control-access-to-your-microphone-on-mac-mchla1b1e1fe/12.0/mac/12.0[]


Command:
```bash
 The technology partially supports this requirement and cannot be configured to be in full compliance.
```

Expected result: 

## Rule: os_provide_disconnect_remote_access

### Severity: 

Explanation:
 Without the ability to immediately disconnect or disable remote access, an attack or other compromise taking place would not be immediately stopped.Operating system remote access functionality must have the capability to immediately disconnect current users remotely accessing the information system and/or disable further remote access. The speed of disconnect or disablement varies based on the criticality of missions functions and the need to eliminate immediate or future remote access to organizational information systems.The remote access functionality (e.g., SSH) may implement features such as automatic disconnect (or user-initiated disconnect) in case of adverse information based on an indicator of compromise or attack.


Command:
```bash
 The technology supports this requirement and cannot be configured to be out of compliance. The technology inherently meets this requirement.
```

Expected result: 

## Rule: os_reauth_privilege

### Severity: 

Explanation:
 Without reauthentication, users may access resources or perform tasks for which they do not have authorization. When operating systems provide the capability to escalate a functional capability, it is critical the user reauthenticate.


Command:
```bash
 The technology supports this requirement and cannot be configured to be out of compliance. The technology inherently meets this requirement.
```

Expected result: 

## Rule: os_reauth_users_change_authenticators

### Severity: 

Explanation:
 Without reauthentication, users may access resources or perform tasks for which they do not have authorization. When operating systems provide the capability to change user authenticators, it is critical the user reauthenticate.


Command:
```bash
 The technology supports this requirement and cannot be configured to be out of compliance. The technology inherently meets this requirement.
```

Expected result: 

## Rule: os_remote_access_methods

### Severity: 

Explanation:
 The information system monitors and controls remote access methods.


Command:
```bash
 The technology supports this requirement and cannot be configured to be out of compliance. The technology inherently meets this requirement.
```

Expected result: 

## Rule: os_remove_software_components_after_updates

### Severity: 

Explanation:
 Previous versions of software components that are not removed from the information system after updates have been installed may be exploited by adversaries. Some information technology products may remove older versions of software automatically from the information system.


Command:
```bash
 The technology supports this requirement and cannot be configured to be out of compliance. The technology inherently meets this requirement.
```

Expected result: 

## Rule: os_required_crypto_module

### Severity: 

Explanation:
 The inherent configuration of the macOS _IS_ in compliance by implementing mechanisms for authentication to a cryptographic module that meet the requirements of all applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance for such authentication
macOS contains many open source projects that may use their own cryptographic libraries typically for the purposes of maintaining platform independence. These services are not covered by the Apple FIPS Validation of the CoreCrypto and CoreCrypto Kernel modules.
Apple is committed to the FIPS validation process and historically has always submitted and validated the cryptographic modules in macOS. macOS Ventura will be submitted for FIPS validation.
link:https://csrc.nist.gov/Projects/cryptographic-module-validation-program/validated-modules[]
link:https://support.apple.com/en-us/HT201159[]


Command:
```bash
 The technology supports this requirement and cannot be configured to be out of compliance. The technology inherently meets this requirement.
```

Expected result: 

## Rule: os_secure_enclave

### Severity: 

Explanation:
 A system _IS_ configured to provide protected storage for cryptographic keys either by hardware protected key store or an organizationally defined safeguard.
Macs with Apple Silicon or T2 processors provide protected storage for cryptographic keys via the secure enclave.
link:https://support.apple.com/guide/security/secure-enclave-sec59b0b31ff/1/web/1[]
NOTE: This will only return a proper result on a T2 or Apple Silicon Macs.


Command:
```bash
 /usr/sbin/ioreg -w 0 -c AppleSEPManager | /usr/bin/grep -q 'AppleSEPManager'; /bin/echo $?
```

Expected result: 0

## Rule: os_separate_functionality

### Severity: 

Explanation:
 The information system _IS_ configured to separate user and system functionality. 
Operating system management functionality includes functions necessary for administration and requires privileged user access. Allowing non-privileged users to access operating system management functionality capabilities increases the risk that non-privileged users may obtain elevated privileges. Operating system management functionality includes functions necessary to administer console, network components, workstations, or servers and typically requires privileged user access. 
The inherent configuration of the macOS allows only privileged users to access operating system management functionalities. 
link:https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/DesigningDaemons.html[]


Command:
```bash
 The technology supports this requirement and cannot be configured to be out of compliance. The technology inherently meets this requirement.
```

Expected result: 

## Rule: os_store_encrypted_passwords

### Severity: 

Explanation:
 The information system _IS_ configured to encrypt stored passwords.
Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised.
link:https://developer.apple.com/documentation/opendirectory/kodattributetypeauthenticationauthority[]


Command:
```bash
 The technology supports this requirement and cannot be configured to be out of compliance. The technology inherently meets this requirement.
```

Expected result: 

## Rule: os_terminate_session

### Severity: 

Explanation:
 Terminates session and network connections when nonlocal maintenance is completed.


Command:
```bash
 The technology supports this requirement and cannot be configured to be out of compliance. The technology inherently meets this requirement.
```

Expected result: 

## Rule: os_unique_identification

### Severity: 

Explanation:
 The macOS is a UNIX 03-compliant operating system. The system uniquely identifies and authenticates organizational users or processes.


Command:
```bash
 The technology supports this requirement and cannot be configured to be out of compliance. The technology inherently meets this requirement.
```

Expected result: 

## Rule: os_verify_remote_disconnection

### Severity: 

Explanation:
 The information system implements remote disconnect verification at the termination of nonlocal maintenance and diagnostic sessions.


Command:
```bash
 The technology supports this requirement and cannot be configured to be out of compliance. The technology inherently meets this requirement.
```

Expected result: 

## Rule: pwpolicy_emergency_accounts_disable

### Severity: 

Explanation:
 The macOS is able to be configured to automatically remove or disable emergency accounts within 72 hours or less. 
Emergency administrator accounts are privileged accounts established in response to crisis situations where the need for rapid account activation is required. Therefore, emergency account activation may bypass normal account authorization processes. If these accounts are disabled, system maintenance during emergencies may not be possible, thus adversely affecting system availability.
Although the ability to create and use emergency administrator accounts is necessary for performing system maintenance during emergencies, these accounts present vulnerabilities to the system if they are not disabled and removed when they are no longer needed. Configuring the macOS to automatically remove or disable emergency accounts within 72 hours of creation mitigates the risks posed if one were to be created and accidentally left active once the crisis is resolved. 
Emergency administrator accounts are different from infrequently used accounts (i.e., local logon accounts used by system administrators when network or normal logon is not available). Infrequently used accounts also remain available and are not subject to automatic termination dates. However, an emergency administrator account is normally a different account created for use by vendors or system maintainers.
To address access requirements, many operating systems can be integrated with enterprise-level authentication/access mechanisms that meet or exceed access control policy requirements.


Command:
```bash
 The technology supports this requirement and cannot be configured to be out of compliance. The technology inherently meets this requirement.
```

Expected result: 

## Rule: pwpolicy_force_password_change

### Severity: 

Explanation:
 The macOS is able to be configured to force users to change their password at next logon.
Temporary passwords are often used for new users when accounts are created. However, once logged in to the system, users must be immediately prompted to change to a permanent password of their creation.
For a user to change their password at next logon, run the following command:
 [source,bash]
 ----
 /usr/bin/pwpolicy -u [USER] -setpolicy "newPasswordRequired=1"
 ----
 NOTE: Replace [USER] with the username that must change the password at next logon


Command:
```bash
 The technology supports this requirement and cannot be configured to be out of compliance. The technology inherently meets this requirement.
```

Expected result: 

## Rule: pwpolicy_temporary_accounts_disable

### Severity: 

Explanation:
 The macOS is able to be configured to set an automated termination for 72 hours or less for all temporary accounts upon account creation. 
If temporary user accounts remain active when no longer needed or for an excessive period, these accounts may be targeted by attackers to gain unauthorized access. To mitigate this risk, automated termination of all temporary accounts _MUST_ be set to 72 hours (or less) when the temporary account is created.
If no policy is enforced by a directory service, a password policy can be set with the "pwpolicy" utility. The variable names may vary depending on how the policy was set.
If there are no temporary accounts defined on the system, this is Not Applicable.


Command:
```bash
 The technology supports this requirement and cannot be configured to be out of compliance. The technology inherently meets this requirement.
```

Expected result: 

