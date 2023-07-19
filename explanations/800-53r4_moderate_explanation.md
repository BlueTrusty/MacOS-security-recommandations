# Explanation of the rules for 800-53r4_moderate

## Rule: audit_acls_files_configure

### Severity: medium

Explanation:
 The audit log files _MUST_ not contain access control lists (ACLs).
This rule ensures that audit information and audit files are configured to be readable and writable only by system administrators, thereby preventing unauthorized access, modification, and deletion of files.


Command:
```bash
 /bin/ls -le $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}') | /usr/bin/awk '{print $1}' | /usr/bin/grep -c ":"
```

Expected result: 0

## Rule: audit_acls_folders_configure

### Severity: medium

Explanation:
 The audit log folder _MUST_ not contain access control lists (ACLs).
Audit logs contain sensitive data about the system and users. This rule ensures that the audit service is configured to create log folders that are readable and writable only by system administrators in order to prevent normal users from reading audit logs.


Command:
```bash
 /bin/ls -lde $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}') | /usr/bin/awk '{print $1}' | /usr/bin/grep -c ":"
```

Expected result: 0

## Rule: audit_auditd_enabled

### Severity: medium

Explanation:
 The information system _MUST_ be configured to generate audit records. 
Audit records establish what types of events have occurred, when they occurred, and which users were involved. These records aid an organization in their efforts to establish, correlate, and investigate the events leading up to an outage or attack.
The content required to be captured in an audit record varies based on the impact level of an organization's system. Content that may be necessary to satisfy this requirement includes, for example, time stamps, source addresses, destination addresses, user identifiers, event descriptions, success/fail indications, filenames involved, and access or flow control rules invoked.
The information system initiates session audits at system start-up.
NOTE: Security auditing is enabled by default on macOS.


Command:
```bash
 /bin/launchctl list | /usr/bin/grep -c com.apple.auditd
```

Expected result: 1

## Rule: audit_failure_halt

### Severity: medium

Explanation:
 The audit service _MUST_ be configured to shut down the computer if it is unable to audit system events. 
Once audit failure occurs, user and system activity are no longer recorded, and malicious activity could go undetected. Audit processing failures can occur due to software/hardware errors, failures in the audit capturing mechanisms, and audit storage capacity being reached or exceeded. 


Command:
```bash
 /usr/bin/awk -F':' '/^policy/ {print $NF}' /etc/security/audit_control | /usr/bin/tr ',' '\n' | /usr/bin/grep -Ec 'ahlt' 
```

Expected result: 1

## Rule: audit_files_group_configure

### Severity: medium

Explanation:
 Audit log files _MUST_ have the group set to wheel.
The audit service _MUST_ be configured to create log files with the correct group ownership to prevent normal users from reading audit logs. 
Audit logs contain sensitive data about the system and users. If log files are set to be readable and writable only by system administrators, the risk is mitigated.


Command:
```bash
 /bin/ls -n $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}') | /usr/bin/awk '{s+=$4} END {print s}'
```

Expected result: 0

## Rule: audit_files_mode_configure

### Severity: medium

Explanation:
 The audit service _MUST_ be configured to create log files that are readable only by the root user and group wheel. To achieve this, audit log files _MUST_ be configured to mode 440 or less permissive; thereby preventing normal users from reading, modifying or deleting audit logs. 


Command:
```bash
 /bin/ls -l $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}') | /usr/bin/awk '!/-r--r-----|current|total/{print $1}' | /usr/bin/wc -l | /usr/bin/tr -d ' '
```

Expected result: 0

## Rule: audit_files_owner_configure

### Severity: medium

Explanation:
 Audit log files _MUST_ be owned by root.
The audit service _MUST_ be configured to create log files with the correct ownership to prevent normal users from reading audit logs.
Audit logs contain sensitive data about the system and users. If log files are set to only be readable and writable by system administrators, the risk is mitigated.


Command:
```bash
 /bin/ls -n $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}') | /usr/bin/awk '{s+=$3} END {print s}'  
```

Expected result: 0

## Rule: audit_flags_aa_configure

### Severity: medium

Explanation:
 The auditing system _MUST_ be configured to flag authorization and authentication (aa) events.
Authentication events contain information about the identity of a user, server, or client. Authorization events contain information about permissions, rights, and rules. If audit records do not include aa events, it is difficult to identify incidents and to correlate incidents to subsequent events. 
Audit records can be generated from various components within the information system (e.g., via a module or policy filter).


Command:
```bash
 /usr/bin/awk -F':' '/^flags/ { print $NF }' /etc/security/audit_control | /usr/bin/tr ',' '\n' | /usr/bin/grep -Ec 'aa'
```

Expected result: 1

## Rule: audit_flags_ad_configure

### Severity: medium

Explanation:
 The auditing system _MUST_ be configured to flag administrative action (ad) events.
Administrative action events include changes made to the system (e.g. modifying authentication policies). If audit records do not include ad events, it is difficult to identify incidents and to correlate incidents to subsequent events. 
Audit records can be generated from various components within the information system (e.g., via a module or policy filter). 
The information system audits the execution of privileged functions.
NOTE: We recommend changing the line "43127:AUE_MAC_SYSCALL:mac_syscall(2):ad" to "43127:AUE_MAC_SYSCALL:mac_syscall(2):zz" in the file /etc/security/audit_event. This will prevent sandbox violations from being audited by the ad flag. 


Command:
```bash
 /usr/bin/awk -F':' '/^flags/ { print $NF }' /etc/security/audit_control | /usr/bin/tr ',' '\n' | /usr/bin/grep -Ec 'ad'
```

Expected result: 1

## Rule: audit_flags_ex_configure

### Severity: 

Explanation:
 The audit system _MUST_ be configured to record enforcement actions of access restrictions, including failed program execute (-ex) attempts.
Enforcement actions are the methods or mechanisms used to prevent unauthorized access and/or changes to configuration settings. One common and effective enforcement action method is using program execution restrictions (e.g., denying users access to execute certain processes). 
This configuration ensures that audit lists include events in which program execution has failed. 
 Without auditing the enforcement of program execution, it is difficult to identify attempted attacks, as there is no audit trail available for forensic investigation.


Command:
```bash
 /usr/bin/awk -F':' '/^flags/ { print $NF }' /etc/security/audit_control | /usr/bin/tr ',' '\n' | /usr/bin/grep -Ec '\-ex'
```

Expected result: 1

## Rule: audit_flags_fm_failed_configure

### Severity: medium

Explanation:
 The audit system _MUST_ be configured to record enforcement actions of failed attempts to modify file attributes (-fm). 
Enforcement actions are the methods or mechanisms used to prevent unauthorized changes to configuration settings. One common and effective enforcement action method is using access restrictions (i.e., denying modifications to a file by applying file permissions). 
This configuration ensures that audit lists include events in which enforcement actions prevent attempts to modify a file. 
Without auditing the enforcement of access restrictions, it is difficult to identify attempted attacks, as there is no audit trail available for forensic investigation.


Command:
```bash
 /usr/bin/awk -F':' '/^flags/ { print $NF }' /etc/security/audit_control | /usr/bin/tr ',' '\n' | /usr/bin/grep -Ec '\-fm'
```

Expected result: 1

## Rule: audit_flags_fr_configure

### Severity: medium

Explanation:
 The audit system _MUST_ be configured to record enforcement actions of access restrictions, including failed file read (-fr) attempts. 
Enforcement actions are the methods or mechanisms used to prevent unauthorized access and/or changes to configuration settings. One common and effective enforcement action method is using access restrictions (e.g., denying access to a file by applying file permissions). 
This configuration ensures that audit lists include events in which enforcement actions prevent attempts to read a file. 
Without auditing the enforcement of access restrictions, it is difficult to identify attempted attacks, as there is no audit trail available for forensic investigation.


Command:
```bash
 /usr/bin/awk -F':' '/^flags/ { print $NF }' /etc/security/audit_control | /usr/bin/tr ',' '\n' | /usr/bin/grep -Ec '\-fr'
```

Expected result: 1

## Rule: audit_flags_fw_configure

### Severity: medium

Explanation:
 The audit system _MUST_ be configured to record enforcement actions of access restrictions, including failed file write (-fw) attempts.
Enforcement actions are the methods or mechanisms used to prevent unauthorized access and/or changes to configuration settings. One common and effective enforcement action method is using access restrictions (e.g., denying users access to edit a file by applying file permissions). 
This configuration ensures that audit lists include events in which enforcement actions prevent attempts to change a file. 
Without auditing the enforcement of access restrictions, it is difficult to identify attempted attacks, as there is no audit trail available for forensic investigation.


Command:
```bash
 /usr/bin/awk -F':' '/^flags/ { print $NF }' /etc/security/audit_control | /usr/bin/tr ',' '\n' | /usr/bin/grep -Ec '\-fw'
```

Expected result: 1

## Rule: audit_flags_lo_configure

### Severity: medium

Explanation:
 The audit system _MUST_ be configured to record all attempts to log in and out of the system (lo). 
Frequently, an attacker that successfully gains access to a system has only gained access to an account with limited privileges, such as a guest account or a service account. The attacker must attempt to change to another user account with normal or elevated privileges in order to proceed. Auditing both successful and unsuccessful attempts to switch to another user account (by way of monitoring login and logout events) mitigates this risk.
The information system monitors login and logout events.


Command:
```bash
 /usr/bin/awk -F':' '/^flags/ { print $NF }' /etc/security/audit_control | /usr/bin/tr ',' '\n' | /usr/bin/grep -Ec '^lo'
```

Expected result: 1

## Rule: audit_folders_mode_configure

### Severity: medium

Explanation:
 The audit log folder _MUST_ be configured to mode 700 or less permissive so that only the root user is able to read, write, and execute changes to folders. 
Because audit logs contain sensitive data about the system and users, the audit service _MUST_ be configured to mode 700 or less permissive; thereby preventing normal users from reading, modifying or deleting audit logs. 


Command:
```bash
 /usr/bin/stat -f %A $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}')
```

Expected result: 700

## Rule: audit_folder_group_configure

### Severity: medium

Explanation:
 Audit log files _MUST_ have the group set to wheel.
The audit service _MUST_ be configured to create log files with the correct group ownership to prevent normal users from reading audit logs. 
Audit logs contain sensitive data about the system and users. If log files are set to be readable and writable only by system administrators, the risk is mitigated.


Command:
```bash
 /bin/ls -dn $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}') | /usr/bin/awk '{print $4}'
```

Expected result: 0

## Rule: audit_folder_owner_configure

### Severity: medium

Explanation:
 Audit log files _MUST_ be owned by root.
The audit service _MUST_ be configured to create log files with the correct ownership to prevent normal users from reading audit logs.
Audit logs contain sensitive data about the system and users. If log files are set to only be readable and writable by system administrators, the risk is mitigated.


Command:
```bash
 /bin/ls -dn $(/usr/bin/grep '^dir' /etc/security/audit_control | /usr/bin/awk -F: '{print $2}') | /usr/bin/awk '{print $3}'
```

Expected result: 0

## Rule: audit_retention_configure

### Severity: medium

Explanation:
 The audit service _MUST_ be configured to require records be kept for a organizational defined value before deletion, unless the system uses a central audit record storage facility. 
When "expire-after" is set to "$ODV", the audit service will not delete audit logs until the log data criteria is met.


Command:
```bash
 /usr/bin/awk -F: '/expire-after/{print $2}' /etc/security/audit_control
```

Expected result: 7d

## Rule: auth_pam_login_smartcard_enforce

### Severity: medium

Explanation:
 The system _MUST_ be configured to enforce multifactor authentication.
All users _MUST_ go through multifactor authentication to prevent unauthenticated access and potential compromise to the system.
IMPORTANT: Modification of Pluggable Authentication Modules (PAM) now require user authorization, or use of a Privacy Preferences Policy Control (PPPC) profile from MDM that authorizes modifying system administrator files or full disk access.
NOTE: /etc/pam.d/login will be automatically modified to its original state following any update or major upgrade to the operating system.


Command:
```bash
 /usr/bin/grep -Ec '^(auth\s+sufficient\s+pam_smartcard.so|auth\s+required\s+pam_deny.so)' /etc/pam.d/login
```

Expected result: 2

## Rule: auth_pam_sudo_smartcard_enforce

### Severity: medium

Explanation:
 The system _MUST_ be configured to enforce multifactor authentication when the sudo command is used to elevate privilege. 
All users _MUST_ go through multifactor authentication to prevent unauthenticated access and potential compromise to the system.
IMPORTANT: Modification of Pluggable Authentication Modules (PAM) now require user authorization, or use of a Privacy Preferences Policy Control (PPPC) profile from MDM that authorizes modifying system administrator files or full disk access.
NOTE: /etc/pam.d/sudo will be automatically modified to its original state following any update or major upgrade to the operating system.


Command:
```bash
 /usr/bin/grep -Ec '^(auth\s+sufficient\s+pam_smartcard.so|auth\s+required\s+pam_deny.so)' /etc/pam.d/sudo
```

Expected result: 2

## Rule: auth_pam_su_smartcard_enforce

### Severity: medium

Explanation:
 The system _MUST_ be configured such that, when the su command is used, multifactor authentication is enforced.
All users _MUST_ go through multifactor authentication to prevent unauthenticated access and potential compromise to the system.
IMPORTANT: Modification of Pluggable Authentication Modules (PAM) now require user authorization, or use of a Privacy Preferences Policy Control (PPPC) profile from MDM that authorizes modifying system administrator files or full disk access.
NOTE: /etc/pam.d/su will be automatically modified to its original state following any update or major upgrade to the operating system.


Command:
```bash
 /usr/bin/grep -Ec '^(auth\s+sufficient\s+pam_smartcard.so|auth\s+required\s+pam_rootok.so)' /etc/pam.d/su
```

Expected result: 2

## Rule: auth_smartcard_allow

### Severity: 

Explanation:
 Smartcard authentication _MUST_ be allowed. 
The use of smartcard credentials facilitates standardization and reduces the risk of unauthorized access.
When enabled, the smartcard can be used for login, authorization, and screen saver unlocking.


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.security.smartcard').objectForKey('allowSmartCard').js
EOS
```

Expected result: true

## Rule: auth_smartcard_certificate_trust_enforce_moderate

### Severity: medium

Explanation:
 The macOS system _MUST_ be configured to block access to users who are no longer authorized (i.e., users with revoked certificates).  
To prevent the use of untrusted certificates, the certificates on a smartcard card _MUST_ meet the following criteria: its issuer has a system-trusted certificate, the certificate is not expired, its "valid-after" date is in the past, and it passes Certificate Revocation List (CRL) and Online Certificate Status Protocol (OCSP) checking.
By setting the smartcard certificate trust level to moderate, the system will execute a soft revocation, i.e., if the OCSP/CRL server is unreachable, authentication will still succeed.
NOTE: Before applying this setting, please see the smartcard supplemental guidance.


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.security.smartcard').objectForKey('checkCertificateTrust').js
EOS
```

Expected result: 2

## Rule: auth_smartcard_enforce

### Severity: high

Explanation:
 Smartcard authentication _MUST_ be enforced.
The use of smartcard credentials facilitates standardization and reduces the risk of unauthorized access.
When enforceSmartCard is set to "true", the smartcard must be used for login, authorization, and unlocking the screensaver.
CAUTION: enforceSmartCard will apply to the whole system. No users will be able to login with their password unless the profile is removed or a user is exempt from smartcard enforcement.
NOTE: enforceSmartcard requires allowSmartcard to be set to true in order to work.


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.security.smartcard').objectForKey('enforceSmartCard').js
EOS
```

Expected result: true

## Rule: auth_ssh_password_authentication_disable

### Severity: 

Explanation:
 If remote login through SSH is enabled, password based authentication _MUST_ be disabled for user login.
All users _MUST_ go through multifactor authentication to prevent unauthenticated access and potential compromise to the system.
NOTE: /etc/ssh/sshd_config will be automatically modified to its original state following any update or major upgrade to the operating system.


Command:
```bash
 /usr/bin/grep -Ec '^(PasswordAuthentication\s+no|ChallengeResponseAuthentication\s+no)' /etc/ssh/sshd_config
```

Expected result: 2

## Rule: icloud_addressbook_disable

### Severity: low

Explanation:
 The macOS built-in Contacts.app connection to Apple's iCloud service _MUST_ be disabled. 
Apple's iCloud service does not provide an organization with enough control over the storage and access of data, and, therefore, automated contact synchronization _MUST_ be controlled by an organization approved service.


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess').objectForKey('allowCloudAddressBook').js
EOS
```

Expected result: false

## Rule: icloud_appleid_system_settings_disable

### Severity: high

Explanation:
 The system setting for Apple ID _MUST_ be disabled.
Disabling the system setting prevents login to Apple ID and iCloud. 


Command:
```bash
 /usr/bin/profiles show -output stdout-xml | /usr/bin/xmllint --xpath '//key[text()="DisabledSystemSettings"]/following-sibling::*[1]' - | /usr/bin/grep -c com.apple.systempreferences.AppleIDSettings
```

Expected result: 1

## Rule: icloud_bookmarks_disable

### Severity: medium

Explanation:
 The macOS built-in Safari.app bookmark synchronization via the iCloud service _MUST_ be disabled.
Apple's iCloud service does not provide an organization with enough control over the storage and access of data and, therefore, automated bookmark synchronization _MUST_ be controlled by an organization approved service.


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess').objectForKey('allowCloudBookmarks').js
EOS
```

Expected result: false

## Rule: icloud_calendar_disable

### Severity: low

Explanation:
 The macOS built-in Calendar.app connection to Apple's iCloud service _MUST_ be disabled. 
Apple's iCloud service does not provide an organization with enough control over the storage and access of data and, therefore, automated calendar synchronization _MUST_ be controlled by an organization approved service.


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess').objectForKey('allowCloudCalendar').js
EOS
```

Expected result: false

## Rule: icloud_drive_disable

### Severity: medium

Explanation:
 The macOS built-in iCloud document synchronization service _MUST_ be disabled to prevent organizational data from being synchronized to personal or non-approved storage. 
Apple's iCloud service does not provide an organization with enough control over the storage and access of data and, therefore, automated document synchronization _MUST_ be controlled by an organization approved service. 


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess').objectForKey('allowCloudDocumentSync').js
EOS
```

Expected result: false

## Rule: icloud_game_center_disable

### Severity: medium

Explanation:
 This works only with supervised devices (MDM) and allows to disable Apple Game Center. The rationale is Game Center is using Apple ID and will shared data on AppleID based services, therefore, Game Center _MUST_ be disabled.
 This setting also prohibits functionality of adding friends to Game Center.


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess').objectForKey('allowGameCenter').js
EOS
```

Expected result: false

## Rule: icloud_keychain_disable

### Severity: medium

Explanation:
 The macOS system's ability to automatically synchronize a user's passwords to their iCloud account _MUST_ be disabled. 
Apple's iCloud service does not provide an organization with enough control over the storage and access of data and, therefore, password management and synchronization _MUST_ be controlled by an organization approved service. 


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess').objectForKey('allowCloudKeychainSync').js
EOS
```

Expected result: false

## Rule: icloud_mail_disable

### Severity: low

Explanation:
 The macOS built-in Mail.app connection to Apple's iCloud service _MUST_ be disabled.
Apple's iCloud service does not provide an organization with enough control over the storage and access of data and, therefore, automated mail synchronization _MUST_ be controlled by an organization approved service.


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess').objectForKey('allowCloudMail').js
EOS
```

Expected result: false

## Rule: icloud_notes_disable

### Severity: low

Explanation:
 The macOS built-in Notes.app connection to Apple's iCloud service _MUST_ be disabled. 
Apple's iCloud service does not provide an organization with enough control over the storage and access of data and, therefore, automated Notes synchronization _MUST_ be controlled by an organization approved service.


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess').objectForKey('allowCloudNotes').js
EOS
```

Expected result: false

## Rule: icloud_photos_disable

### Severity: medium

Explanation:
 The macOS built-in Photos.app connection to Apple's iCloud service _MUST_ be disabled. 
Apple's iCloud service does not provide an organization with enough control over the storage and access of data and, therefore, automated photo synchronization _MUST_ be controlled by an organization approved service. 


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess').objectForKey('allowCloudPhotoLibrary').js
EOS
```

Expected result: false

## Rule: icloud_private_relay_disable

### Severity: medium

Explanation:
 Enterprise networks may be required to audit all network traffic by policy, therefore, iCloud Private Relay _MUST_ be disabled.
Network administrators can also prevent the use of this feature by blocking DNS resolution of mask.icloud.com and mask-h2.icloud.com.


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess').objectForKey('allowCloudPrivateRelay').js
EOS
```

Expected result: false

## Rule: icloud_reminders_disable

### Severity: low

Explanation:
 The macOS built-in Reminders.app connection to Apple's iCloud service _MUST_ be disabled. 
Apple's iCloud service does not provide an organization with enough control over the storage and access of data and, therefore, automated reminders synchronization _MUST_ be controlled by an organization approved service.


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess').objectForKey('allowCloudReminders').js
EOS
```

Expected result: false

## Rule: icloud_sync_disable

### Severity: 

Explanation:
 The macOS system's ability to automatically synchronize a user's desktop and documents folder to their iCloud Drive _MUST_ be disabled.
Apple's iCloud service does not provide an organization with enough control over the storage and access of data and, therefore, automated file synchronization _MUST_ be controlled by an organization approved service. 


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess').objectForKey('allowCloudDesktopAndDocuments').js
EOS
```

Expected result: false

## Rule: os_airdrop_disable

### Severity: medium

Explanation:
 AirDrop _MUST_ be disabled to prevent file transfers to or from unauthorized devices.
 AirDrop allows users to share and receive files from other nearby Apple devices.

Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess').objectForKey('allowAirDrop').js
EOS
```

Expected result: false

## Rule: os_appleid_prompt_disable

### Severity: medium

Explanation:
 The prompt for Apple ID setup during Setup Assistant _MUST_ be disabled. 
macOS will automatically prompt new users to set up an Apple ID while they are going through Setup Assistant if this is not disabled, misleading new users to think they need to create Apple ID accounts upon their first login.


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.SetupAssistant.managed').objectForKey('SkipCloudSetup').js
EOS
```

Expected result: true

## Rule: os_authenticated_root_enable

### Severity: 

Explanation:
 Authenticated Root _MUST_ be enabled. 
When Authenticated Root is enabled the macOS is booted from a signed volume that is cryptographically protected to prevent tampering with the system volume.
NOTE: Authenticated Root is enabled by default on macOS systems.


Command:
```bash
 /usr/bin/csrutil authenticated-root | /usr/bin/grep -c 'enabled'
```

Expected result: 1

## Rule: os_auth_peripherals

### Severity: 

Explanation:
 Organizational devices requiring unique device-to-device identification and authentication may be defined by type, by device, or by a combination of type/device. Information systems typically use either shared known information (e.g., Media Access Control [MAC] or Transmission Control Protocol/Internet Protocol [TCP/IP] addresses) for device identification or organizational authentication solutions (e.g., IEEE 802.1x and Extensible Authentication Protocol [EAP], Radius server with EAP-Transport Layer Security [TLS] authentication, Kerberos) to identify/authenticate devices on local and/or wide area networks. Organizations determine the required strength of authentication mechanisms by the security categories of information systems. Because of the challenges of applying this control on large scale, organizations are encouraged to only apply the control to those limited number (and type) of devices that truly need to support this capability.


Command:
```bash
 The technology does support this requirement, however, third party solutions are required to implement at an infrastructure level.
```

Expected result: 

## Rule: os_bonjour_disable

### Severity: medium

Explanation:
 Bonjour multicast advertising _MUST_ be disabled to prevent the system from broadcasting its presence and available services over network interfaces.


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.mDNSResponder').objectForKey('NoMulticastAdvertisements').js
EOS
```

Expected result: true

## Rule: os_calendar_app_disable

### Severity: medium

Explanation:
 The macOS built-in Calendar.app _MUST_ be disabled as this application can establish a connection to non-approved services. This rule is in place to prevent inadvertent data transfers.
[IMPORTANT]
 ====
 Some organizations allow the use of the built-in Calendar.app for organizational communication. Information System Security Officers (ISSOs) may make the risk-based decision not to disable the macOS built-in Mail.app to avoid losing this functionality, but they are advised to first fully weigh the potential risks posed to their organization.
 ====


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
function run() {
  let pref1 = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess.new')  .objectForKey('familyControlsEnabled'))
  let pathlist = $.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess.new')  .objectForKey('pathBlackList').js
  for ( let app in pathlist ) {
      if ( ObjC.unwrap(pathlist[app]) == "/Applications/Calendar.app" && pref1 == true ){
          return("true")
      }
  }
  return("false")
  }
EOS
```

Expected result: true

## Rule: os_certificate_authority_trust

### Severity: high

Explanation:
 The organization _MUST_ issue or obtain public key certificates from an organization-approved service provider and ensure only approved trust anchors are in the System Keychain.


Command:
```bash
 /usr/bin/security dump-keychain /Library/Keychains/System.keychain | /usr/bin/awk -F'"' '/labl/ {print $4}'
```

Expected result: alistcontainingapprovedrootcertificates

## Rule: os_continuous_monitoring

### Severity: 

Explanation:
 The macOS system _MUST_ be configured to determine the state of system components with regard to flaw remediation.


Command:
```bash
 The technology does not support this requirement. This is an applicable-does not meet finding.
```

Expected result: 

## Rule: os_facetime_app_disable

### Severity: low

Explanation:
 The macOS built-in FaceTime.app _MUST_ be disabled. 
The FaceTime.app establishes a connection to Apple's iCloud service, even when security controls have been put in place to disable iCloud access. 


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
function run() {
  let pref1 = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess.new')  .objectForKey('familyControlsEnabled'))
  let pathlist = $.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess.new')  .objectForKey('pathBlackList').js
  for ( let app in pathlist ) {
      if ( ObjC.unwrap(pathlist[app]) == "/Applications/FaceTime.app" && pref1 == true ){
          return("true")
      }
  }
  return("false")
  }
EOS
```

Expected result: true

## Rule: os_filevault_autologin_disable

### Severity: medium

Explanation:
 If FileVault is enabled, automatic login _MUST_ be disabled, so that both FileVault and login window authentication are required.
The default behavior of macOS when FileVault is enabled is to automatically log in to the computer once successfully passing your FileVault credentials. 
NOTE: DisableFDEAutoLogin does not have to be set on Apple Silicon based macOS systems that are smartcard enforced as smartcards are available at pre-boot.


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.loginwindow').objectForKey('DisableFDEAutoLogin').js
EOS
```

Expected result: true

## Rule: os_firewall_default_deny_require

### Severity: 

Explanation:
 A deny-all and allow-by-exception firewall policy _MUST_ be employed for managing connections to other systems. 
Organizations _MUST_ ensure the built-in packet filter firewall is configured correctly to employ the default deny rule.
Failure to restrict network connectivity to authorized systems permits inbound connections from malicious systems. It also permits outbound connections that may facilitate the exfiltration of data.
If you are using a third-party firewall solution, this setting does not apply. 
[IMPORTANT]
 ====
 Configuring the built-in packet filter firewall to employ the default deny rule has the potential to interfere with applications on the system in an unpredictable manner. Information System Security Officers (ISSOs) may make the risk-based decision not to configure the built-in packet filter firewall to employ the default deny rule to avoid losing functionality, but they are advised to first fully weigh the potential risks posed to their organization.
 ====


Command:
```bash
 /sbin/pfctl -a '*' -sr &> /dev/null | /usr/bin/grep -c "block drop in all"
```

Expected result: 1

## Rule: os_firewall_log_enable

### Severity: 

Explanation:
 Firewall logging _MUST_ be enabled. 
Firewall logging ensures that malicious network activity will be logged to the system. 
NOTE: The firewall data is logged to Apple's Unified Logging with the subsystem `com.apple.alf` and the data is marked as private. In order to enable private data, review the `com.apple.alf.private_data.mobileconfig` file in the project's `includes` folder. 


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
function run() {
  let pref1 = $.NSUserDefaults.alloc.initWithSuiteName('com.apple.security.firewall')  .objectForKey('EnableLogging').js
  let pref2 = $.NSUserDefaults.alloc.initWithSuiteName('com.apple.security.firewall')  .objectForKey('LoggingOption').js
  if ( pref1 == true && pref2 == "detail" ){
    return("true")
  } else {
    return("false")
  }
}
EOS
```

Expected result: true

## Rule: os_firmware_password_require

### Severity: medium

Explanation:
 A firmware password _MUST_ be enabled and set. 
Single user mode, recovery mode, the Startup Manager, and several other tools are available on macOS by holding the "Option" key down during startup. Setting a firmware password restricts access to these tools.
To set a firmware passcode use the following command:
[source,bash]
 ----
 /usr/sbin/firmwarepasswd -setpasswd
 ----
NOTE: If firmware password or passcode is forgotten, the only way to reset the forgotten password is through the use of a machine specific binary generated and provided by Apple. Schedule a support call, and provide proof of purchase before the firmware binary will be generated.
NOTE: Firmware passwords are not supported on Apple Silicon devices. This rule is only applicable to Intel devices.


Command:
```bash
 /usr/sbin/firmwarepasswd -check | /usr/bin/grep -c "Password Enabled: Yes"
```

Expected result: 1

## Rule: os_gatekeeper_enable

### Severity: high

Explanation:
 Gatekeeper _MUST_ be enabled. 
Gatekeeper is a security feature that ensures that applications are digitally signed by an Apple-issued certificate before they are permitted to run. Digital signatures allow the macOS host to verify that the application has not been modified by a malicious third party.
Administrator users will still have the option to override these settings on a case-by-case basis.


Command:
```bash
 /usr/sbin/spctl --status | /usr/bin/grep -c "assessments enabled"
```

Expected result: 1

## Rule: os_gatekeeper_rearm

### Severity: 

Explanation:
 Gatekeeper _MUST_ be configured to automatically rearm after 30 days if disabled.


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.security').objectForKey('GKAutoRearm').js
EOS
```

Expected result: true

## Rule: os_handoff_disable

### Severity: low

Explanation:
 Handoff _MUST_ be disabled. 
Handoff allows you to continue working on a document or project when the user switches from one Apple device to another. Disabling Handoff prevents data transfers to unauthorized devices.


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess').objectForKey('allowActivityContinuation').js
EOS
```

Expected result: false

## Rule: os_home_folders_secure

### Severity: medium

Explanation:
 The system _MUST_ be configured to prevent access to other user's home folders.
The default behavior of macOS is to allow all valid users access to the the top level of every other user's home folder while restricting access only to the Apple default folders within. 


Command:
```bash
 /usr/bin/find /System/Volumes/Data/Users -mindepth 1 -maxdepth 1 -type d -perm -1 | /usr/bin/grep -v "Shared" | /usr/bin/grep -v "Guest" | /usr/bin/wc -l | /usr/bin/xargs
```

Expected result: 0

## Rule: os_httpd_disable

### Severity: medium

Explanation:
 The built-in web server is a non-essential service built into macOS and _MUST_ be disabled.
NOTE: The built in web server service is disabled at startup by default macOS.


Command:
```bash
 /bin/launchctl print-disabled system | /usr/bin/grep -c '"org.apache.httpd" => disabled'
```

Expected result: 1

## Rule: os_icloud_storage_prompt_disable

### Severity: medium

Explanation:
 The prompt to set up iCloud storage services during Setup Assistant _MUST_ be disabled.
The default behavior of macOS is to prompt new users to set up storage in iCloud. Disabling the iCloud storage setup prompt provides organizations more control over the storage of their data. 


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.SetupAssistant.managed').objectForKey('SkipiCloudStorageSetup').js
EOS
```

Expected result: true

## Rule: os_identify_non-org_users

### Severity: 

Explanation:
 The information system uniquely identifies and authenticates non-organizational users (or processes acting on behalf of non-organizational users).


Command:
```bash
 This requirement is NA for this technology.
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

## Rule: os_ir_support_disable

### Severity: 

Explanation:
 Infrared (IR) support _MUST_ be disabled to prevent users from controlling the system with IR devices. 
By default, if IR is enabled, the system will accept IR control from any remote device. 
NOTE: This is applicable only to models of Mac Mini systems earlier than Mac Mini8,1.


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.driver.AppleIRController').objectForKey('DeviceEnabled').js
EOS
```

Expected result: false

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

## Rule: os_mail_app_disable

### Severity: medium

Explanation:
 The macOS built-in Mail.app _MUST_ be disabled. 
The Mail.app contains functionality that can establish connections to Apple's iCloud, even when security controls to disable iCloud access have been put in place.
[IMPORTANT]
 ====
 Some organizations allow the use of the built-in Mail.app for organizational communication. Information System Security Officers (ISSOs) may make the risk-based decision not to disable the macOS built-in Mail.app to avoid losing this functionality, but they are advised to first fully weigh the potential risks posed to their organization.
 ====


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
function run() {
  let pref1 = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess.new')  .objectForKey('familyControlsEnabled'))
  let pathlist = $.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess.new')  .objectForKey('pathBlackList').js
  for ( let app in pathlist ) {
      if ( ObjC.unwrap(pathlist[app]) == "/Applications/Mail.app" && pref1 == true ){
          return("true")
      }
  }
  return("false")
  }
EOS
```

Expected result: true

## Rule: os_mdm_require

### Severity: 

Explanation:
 You _MUST_ enroll your Mac in a Mobile Device Management (MDM) software.
User Approved MDM (UAMDM) enrollment or enrollment via Apple Business Manager (ABM)/Apple School Manager (ASM) is required to manage certain security settings. Currently these include:
* Allowed Kernel Extensions
 * Allowed Approved System Extensions
 * Privacy Preferences Policy Control Payload
 * ExtensibleSingleSignOn
 * FDEFileVault
In macOS 11, UAMDM grants Supervised status on a Mac, unlocking the following MDM features, which were previously locked behind ABM:
* Activation Lock Bypass
 * Access to Bootstrap Tokens
 * Scheduling Software Updates
 * Query list and delete local users


Command:
```bash
 /usr/bin/profiles status -type enrollment | /usr/bin/awk -F: '/MDM enrollment/ {print $2}' | /usr/bin/grep -c "Yes (User Approved)"
```

Expected result: 1

## Rule: os_messages_app_disable

### Severity: low

Explanation:
 The macOS built-in Messages.app _MUST_ be disabled. 
The Messages.app establishes a connection to Apple's iCloud service, even when security controls to disable iCloud access have been put in place. 


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
function run() {
  let pref1 = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess.new')  .objectForKey('familyControlsEnabled'))
  let pathlist = $.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess.new')  .objectForKey('pathBlackList').js
  for ( let app in pathlist ) {
      if ( ObjC.unwrap(pathlist[app]) == "/Applications/Messages.app" && pref1 == true ){
          return("true")
      }
  }
  return("false")
  }
EOS
```

Expected result: true

## Rule: os_nfsd_disable

### Severity: medium

Explanation:
 Support for Network File Systems (NFS) services is non-essential and, therefore, _MUST_ be disabled.


Command:
```bash
 /bin/launchctl print-disabled system | /usr/bin/grep -c '"com.apple.nfsd" => disabled'
```

Expected result: 1

## Rule: os_nonlocal_maintenance

### Severity: 

Explanation:
 Nonlocal maintenance and diagnostic activities are those activities conducted by individuals communicating through a network, either an external network or an internal network.  


Command:
```bash
 This requirement is NA for this technology.
```

Expected result: 

## Rule: os_notify_account_created

### Severity: 

Explanation:
 The macOS should be configured to automatically notify system administrators and Information System Security Officers (ISSOs) when new accounts are created.
Once an attacker establishes initial access to a system, the attacker often attempts to create a persistent method of reestablishing and maintaining access by creating a new account. Configuring the information system to send a notification when new accounts are created is one method for mitigating this risk. A comprehensive account management process should not only notify when new accounts are created, but also maintain an audit record of accounts made. Such a process greatly reduces the risk that accounts will be surreptitiously created and provides logging that can be used for forensic purposes. 
To enable notifications and audit logging of accounts created, many operating systems can be integrated with enterprise-level auditing mechanisms that meet or exceed this requirement. 


Command:
```bash
 The technology does not support this requirement. This is an applicable-does not meet finding.
```

Expected result: 

## Rule: os_notify_account_disabled

### Severity: 

Explanation:
 The macOS should be configured to automatically notify system administrators and Information System Security Officers (ISSOs) when accounts are disabled.
When operating system accounts are disabled, user accessibility is affected. Accounts are utilized for identifying individual operating system users or for identifying the operating system processes themselves. To detect and respond to events that affect user accessibility and system processing, operating systems should audit account disabling actions and, as required, notify system administrators and ISSOs so they can investigate the event. Such a capability greatly reduces the risk that operating system accessibility will be negatively affected for extended periods of time and also provides logging that can be used for forensic purposes.
To enable notifications and audit logging of disabled accounts, many operating systems can be integrated with enterprise-level auditing mechanisms that meet or exceed this requirement. 


Command:
```bash
 The technology does not support this requirement. This is an applicable-does not meet finding.
```

Expected result: 

## Rule: os_notify_account_enable

### Severity: 

Explanation:
 The macOS should be configured to automatically notify system administrators and Information System Security Officers (ISSOs) when accounts are enabled.
Once an attacker establishes initial access to a system, the attacker often attempts to create a persistent method of reestablishing and maintaining access by enabling a new or previously disabled account.  Configuring the information system to send a notification when  a new or disabled account is enabled is one method for mitigating this risk. A comprehensive account management process should not only notify when accounts are enabled, but also maintain an audit record of these actions.  Such a process greatly reduces the risk that accounts will be surreptitiously enabled and provides logging that can be used for forensic purposes. 
To enable notifications and audit logging of enabled accounts, many operating systems can be integrated with enterprise-level auditing mechanisms that meet or exceed this requirement. 


Command:
```bash
 The technology does not support this requirement. This is an applicable-does not meet finding.
```

Expected result: 

## Rule: os_notify_account_modified

### Severity: 

Explanation:
 The macOS should be configured to automatically notify system administrators and Information System Security Officers (ISSOs) when accounts are modified.
Once an attacker establishes initial access to a system, the attacker often attempts to create a persistent method of reestablishing and maintaining access by modifying an existing account. Configuring the information system to send a notification when accounts are modified is one method for mitigating this risk. A comprehensive account management process should not only notify when new accounts are modified, but also maintain an audit record of these actions. Such a process greatly reduces the risk that accounts will be surreptitiously created and provides logging that can be used for forensic purposes. 
To enable notifications and audit logging of modified account, many operating systems can be integrated with enterprise-level auditing mechanisms that meet or exceed this requirement. 


Command:
```bash
 The technology does not support this requirement. This is an applicable-does not meet finding.
```

Expected result: 

## Rule: os_notify_account_removal

### Severity: 

Explanation:
 The macOS should be configured to automatically notify system administrators and Information System Security Officers (ISSOs) when accounts are removed.
When operating system accounts are disabled, user accessibility is affected. Accounts are utilized for identifying individual operating system users or for identifying the operating system processes themselves. To detect and respond to events that affect user accessibility and system processing, operating systems should audit account removal actions and, as required, notify system administrators and ISSOs so they can investigate the event. Such a capability greatly reduces the risk that operating system accessibility will be negatively affected for extended periods of time and also provides logging that can be used for forensic purposes.
To enable notifications and audit logging of removed accounts, many operating systems can be integrated with enterprise-level auditing mechanisms that meet or exceed this requirement. 


Command:
```bash
 The technology does not support this requirement. This is an applicable-does not meet finding.
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

## Rule: os_parental_controls_enable

### Severity: 

Explanation:
 Parental Controls _MUST_ be enabled. 
Control of program execution is a mechanism used to prevent program execution of unauthorized programs, which is critical to maintaining a secure system baseline.
Parental Controls on the macOS consist of many different payloads, which are set individually depending on the type of control required. Enabling parental controls allows for further configuration of these restrictions.


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess.new').objectForKey('familyControlsEnabled').js
EOS
```

Expected result: true

## Rule: os_password_autofill_disable

### Severity: 

Explanation:
 Password Autofill _MUST_ be disabled. 
macOS allows users to save passwords and use the Password Autofill feature in Safari and compatible apps. To protect against malicious users gaining access to the system, this feature _MUST_ be disabled to prevent users from being prompted to save passwords in applications.


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess').objectForKey('allowPasswordAutoFill').js
EOS
```

Expected result: false

## Rule: os_password_proximity_disable

### Severity: medium

Explanation:
 Proximity based password sharing requests _MUST_ be disabled. 
The default behavior of macOS is to allow users to request passwords from other known devices (macOS and iOS). This feature _MUST_ be disabled to prevent passwords from being shared.


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess').objectForKey('allowPasswordProximityRequests').js
EOS
```

Expected result: false

## Rule: os_password_sharing_disable

### Severity: 

Explanation:
 Password Sharing _MUST_ be disabled. 
The default behavior of macOS is to allow users to share a password over Airdrop between other macOS and iOS devices. This feature _MUST_ be disabled to prevent passwords from being shared.


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess').objectForKey('allowPasswordSharing').js
EOS
```

Expected result: false

## Rule: os_policy_banner_loginwindow_enforce

### Severity: medium

Explanation:
 Displaying a standardized and approved use notification before granting access to the operating system ensures that users are provided with privacy and security notification verbiage that is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.
System use notifications are required only for access via login interfaces with human users and are not required when such human interfaces do not exist.
The policy banner will show if a "PolicyBanner.rtf" or "PolicyBanner.rtfd" exists in the "/Library/Security" folder.
 NOTE: 
   The banner text of the document _MUST_ read:
  "$ODV"


Command:
```bash
 /bin/ls -ld /Library/Security/PolicyBanner.rtf* | /usr/bin/wc -l | /usr/bin/tr -d ' '
```

Expected result: 1

## Rule: os_policy_banner_ssh_configure

### Severity: medium

Explanation:
 Remote login service _MUST_ be configured to display a policy banner at login. 
Displaying a standardized and approved use notification before granting access to the operating system ensures that users are provided with privacy and security notification verbiage that is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.
System use notifications are required only for access via login interfaces with human users and are not required when such human interfaces do not exist.


Command:
```bash
 bannerText="You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions:
-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
-At any time, the USG may inspect and seize data stored on this IS.
-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG authorized purpose.
-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.
-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."
/usr/bin/grep -c "$bannerText" /etc/banner
```

Expected result: 1

## Rule: os_policy_banner_ssh_enforce

### Severity: medium

Explanation:
 SSH _MUST_ be configured to display a policy banner. 
Displaying a standardized and approved use notification before granting access to the operating system ensures that users are provided with privacy and security notification verbiage that is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.
System use notifications are required only for access via login interfaces with human users and are not required when such human interfaces do not exist
NOTE: /etc/ssh/sshd_config will be automatically modified to its original state following any update or major upgrade to the operating system.


Command:
```bash
 /usr/bin/grep -c "^Banner /etc/banner" /etc/ssh/sshd_config 
```

Expected result: 1

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

## Rule: os_protect_dos_attacks

### Severity: 

Explanation:
 The macOS should be configured to prevent Denial of Service (DoS) attacks by enforcing rate-limiting measures on network interfaces. 
DoS attacks leave authorized users unable to access information systems, devices, or other network resources due to the actions of a malicious cyber threat actor. When this occurs, the organization must operate at degraded capacity; often resulting in an inability to accomplish its mission. 
To prevent DoS attacks by ensuring rate-limiting measures on network interfaces, many operating systems can be integrated with enterprise-level firewalls and networking equipment that meet or exceed this requirement.


Command:
```bash
 The technology does not support this requirement. This is an applicable-does not meet finding.
```

Expected result: 

## Rule: os_provide_automated_account_management

### Severity: 

Explanation:
 The organization should employ automated mechanisms to support the management of information system accounts.
The use of automated mechanisms prevents against human error and provide a faster and more efficient means of relaying time-sensitive information and account management.
To employ automated mechanisms for account management functions, many operating systems can be integrated with an enterprise-level directory service that meets or exceeds this requirement.


Command:
```bash
 The technology does not support this requirement. This is an applicable-does not meet finding.
```

Expected result: 

## Rule: os_recovery_lock_enable

### Severity: medium

Explanation:
 A recovery lock password _MUST_ be enabled and set. 
Single user mode, recovery mode, the Startup Manager, and several other tools are available on macOS by holding down specific key combinations during startup. Setting a recovery lock restricts access to these tools.
IMPORTANT: Recovery lock passwords are not supported on Intel devices. This rule is only applicable to Apple Silicon devices.


Command:
```bash
 /usr/libexec/mdmclient QuerySecurityInfo | /usr/bin/grep -c "IsRecoveryLockEnabled = 1"
```

Expected result: 1

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

## Rule: os_root_disable

### Severity: 

Explanation:
 To assure individual accountability and prevent unauthorized access, logging in as root at the login window _MUST_ be disabled.
The macOS system _MUST_ require individuals to be authenticated with an individual authenticator prior to using a group authenticator, and administrator users _MUST_ never log in directly as root. 


Command:
```bash
 /usr/bin/dscl . -read /Users/root UserShell 2>&1 | /usr/bin/grep -c "/usr/bin/false"
```

Expected result: 1

## Rule: os_screensaver_loginwindow_enforce

### Severity: low

Explanation:
 A default screen saver _MUST_ be configured to display at the login window and _MUST_ not display any sensitive information.


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.screensaver').objectForKey('loginWindowModulePath').js
EOS
```

Expected result: /System/Library/ScreenSavers/Flurry.saver

## Rule: os_secure_name_resolution

### Severity: 

Explanation:
 The information system requests and performs data origin authentication and data integrity verification on the name/address resolution responses the system receives from authoritative sources.
NOTE: macOS supports encrypted DNS settings with the com.apple.dnsSettings.managed payload, however, the system must be integrated with a DNS server that supports encrypted DNS. link:https://developer.apple.com/documentation/devicemanagement/dnssettings[]


Command:
```bash
 The technology does not support this requirement. This is an applicable-does not meet finding.
```

Expected result: 

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

## Rule: os_sip_enable

### Severity: medium

Explanation:
 System Integrity Protection (SIP) _MUST_ be enabled. 
SIP is vital to protecting the integrity of the system as it prevents malicious users and software from making unauthorized and/or unintended modifications to protected files and folders; ensures the presence of an audit record generation capability for defined auditable events for all operating system components; protects audit tools from unauthorized access, modification, and deletion; restricts the root user account and limits the actions that the root user can perform on protected parts of the macOS; and prevents non-privileged users from granting other users direct access to the contents of their home directories and folders.
NOTE: SIP is enabled by default in macOS.


Command:
```bash
 /usr/bin/csrutil status | /usr/bin/grep -c 'System Integrity Protection status: enabled.'
```

Expected result: 1

## Rule: os_siri_prompt_disable

### Severity: medium

Explanation:
 The prompt for Siri during Setup Assistant _MUST_ be disabled.
Organizations _MUST_ apply organization-wide configuration settings. The macOS Siri Assistant Setup prompt guides new users through enabling their own specific Siri settings; this is not essential and, therefore, _MUST_ be disabled to prevent against the risk of individuals electing Siri settings with the potential to override organization-wide settings.


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.SetupAssistant.managed').objectForKey('SkipSiriSetup').js
EOS
```

Expected result: true

## Rule: os_skip_unlock_with_watch_enable

### Severity: medium

Explanation:
 The prompt for Apple Watch unlock setup during Setup Assistant _MUST_ be disabled. 
Disabling Apple watches is a necessary step to ensuring that the information system retains a session lock until the user reestablishes access using an authorized identification and authentication procedures.


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.SetupAssistant.managed').objectForKey('SkipUnlockWithWatch').js
EOS
```

Expected result: true

## Rule: os_sshd_client_alive_count_max_configure

### Severity: medium

Explanation:
 If SSHD is enabled it _MUST_ be configured with an Active Client Alive Maximum Count set to $ODV. Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session or an incomplete login attempt will also free up resources committed by the managed network element.
NOTE: /etc/ssh/sshd_config will be automatically modified to its original state following any update or major upgrade to the operating system.


Command:
```bash
 /usr/sbin/sshd -T | /usr/bin/awk '/clientalivecountmax/{print $2}'
```

Expected result: 0

## Rule: os_sshd_client_alive_interval_configure

### Severity: medium

Explanation:
 If SSHD is enabled then it _MUST_ be configured with an Active Client Alive Maximum Count set to $ODV. 
Setting the Active Client Alive Maximum Count to $ODV (seconds) will log users out after an organizational defined interval of inactivity.
NOTE: /etc/ssh/sshd_config will be automatically modified to its original state following any update or major upgrade to the operating system.


Command:
```bash
 /usr/sbin/sshd -T | /usr/bin/awk '/clientaliveinterval/{print $2}'
```

Expected result: 900

## Rule: os_sshd_fips_compliant

### Severity: medium

Explanation:
 If SSHD is enabled then it _MUST_ be configured to limit the Ciphers, HostbasedAcceptedAlgorithms, HostKeyAlgorithms, KexAlgorithms, MACs, PubkeyAcceptedAlgorithms, CASignatureAlgorithms to algorithms that are FIPS 140 validated.
FIPS 140-2 is the current standard for validating that mechanisms used to access cryptographic modules utilize authentication that meet federal requirements.
Operating systems utilizing encryption _MUST_ use FIPS validated mechanisms for authenticating to cryptographic modules. 
NOTE: For more information on FIPS compliance with the version of SSHD included in the macOS, the manual page apple_ssh_and_fips has additional information.


Command:
```bash
 fips_sshd_config=("Ciphers aes128-gcm@openssh.com" "HostbasedAcceptedAlgorithms ecdsa-sha2-nistp256,ecdsa-sha2-nistp256-cert-v01@openssh.com" "HostKeyAlgorithms ecdsa-sha2-nistp256,ecdsa-sha2-nistp256-cert-v01@openssh.com" "KexAlgorithms ecdh-sha2-nistp256" "MACs hmac-sha2-256" "PubkeyAcceptedAlgorithms ecdsa-sha2-nistp256,ecdsa-sha2-nistp256-cert-v01@openssh.com" "CASignatureAlgorithms ecdsa-sha2-nistp256")
total=0
for config in $fips_sshd_config; do
  total=$(expr $(/usr/sbin/sshd -T | /usr/bin/grep -i -c "$config") + $total)
done

echo $total
```

Expected result: 7

## Rule: os_ssh_fips_compliant

### Severity: 

Explanation:
 SSH _MUST_ be configured to limit the Ciphers, HostbasedAcceptedAlgorithms, HostKeyAlgorithms, KexAlgorithms, MACs, PubkeyAcceptedAlgorithms, CASignatureAlgorithms to algorithms that are FIPS 140 validated.
FIPS 140-2 is the current standard for validating that mechanisms used to access cryptographic modules utilize authentication that meet federal requirements.
Operating systems utilizing encryption _MUST_ use FIPS validated mechanisms for authenticating to cryptographic modules. 
NOTE: For more information on FIPS compliance with the version of SSH included in the macOS, the manual page apple_ssh_and_fips has additional information.


Command:
```bash
 fips_ssh_config="Host *
Ciphers aes128-gcm@openssh.com
HostbasedAcceptedAlgorithms ecdsa-sha2-nistp256,ecdsa-sha2-nistp256-cert-v01@openssh.com
HostKeyAlgorithms ecdsa-sha2-nistp256,ecdsa-sha2-nistp256-cert-v01@openssh.com
KexAlgorithms ecdh-sha2-nistp256
MACs hmac-sha2-256
PubkeyAcceptedAlgorithms ecdsa-sha2-nistp256,ecdsa-sha2-nistp256-cert-v01@openssh.com
CASignatureAlgorithms ecdsa-sha2-nistp256"
/usr/bin/grep -c "$fips_ssh_config" /etc/ssh/ssh_config.d/fips_ssh_config
```

Expected result: 8

## Rule: os_ssh_server_alive_count_max_configure

### Severity: 

Explanation:
 SSH _MUST_ be configured with an Active Server Alive Maximum Count set to $ODV. Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session or an incomplete login attempt will also free up resources committed by the managed network element.
NOTE: /etc/ssh/ssh_config will be automatically modified to its original state following any update or major upgrade to the operating system.


Command:
```bash
 ret="pass"
for u in $(/usr/bin/dscl . -list /Users UniqueID | /usr/bin/awk '$2 > 500 {print $1}'); do
  sshCheck=$(/usr/bin/sudo -u $u /usr/bin/ssh -G . | /usr/bin/grep -c "^serveralivecountmax 0")
  if [[ "$sshCheck" == "0" ]]; then
    ret="fail"
    break
  fi
done
/bin/echo $ret
```

Expected result: pass

## Rule: os_ssh_server_alive_interval_configure

### Severity: 

Explanation:
 SSH _MUST_ be configured with an Active Server Alive Maximum Count set to $ODV. 
Setting the Active Server Alive Maximum Count to $ODV will log users out after a $ODV seconds interval of inactivity.
NOTE: /etc/ssh/ssh_config will be automatically modified to its original state following any update or major upgrade to the operating system.


Command:
```bash
 ret="pass"
for u in $(/usr/bin/dscl . -list /Users UniqueID | /usr/bin/awk '$2 > 500 {print $1}'); do
  sshCheck=$(/usr/bin/sudo -u $u /usr/bin/ssh -G . | /usr/bin/grep -c "^serveraliveinterval 900")
  if [[ "$sshCheck" == "0" ]]; then
    ret="fail"
    break
  fi
done
/bin/echo $ret
```

Expected result: pass

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

## Rule: os_system_read_only

### Severity: 

Explanation:
 The System volume _MUST_ be mounted as read-only in order to ensure that configurations critical to the integrity of the macOS have not been compromised. System Integrity Protection (SIP) will prevent the system volume from being mounted as writable.
NOTE: The system volume is read only by default in macOS.


Command:
```bash
 /usr/sbin/system_profiler SPStorageDataType | /usr/bin/awk '/Mount Point: \/$/{x=NR+2}(NR==x){print $2}'
```

Expected result: No

## Rule: os_tftpd_disable

### Severity: high

Explanation:
 If the system does not require Trivial File Transfer Protocol (TFTP), support it is non-essential and _MUST_ be disabled.
The information system _MUST_ be configured to provide only essential capabilities. Disabling TFTP helps prevent the unauthorized connection of devices and the unauthorized transfer of information.  
NOTE: TFTP service is disabled at startup by default macOS.


Command:
```bash
 /bin/launchctl print-disabled system | /usr/bin/grep -c '"com.apple.tftpd" => disabled'
```

Expected result: 1

## Rule: os_time_server_enabled

### Severity: medium

Explanation:
 The macOS time synchronization daemon (timed) _MUST_ be enabled for proper time synchronization to an authorized time server.
NOTE: The time synchronization daemon is enabled by default on macOS.


Command:
```bash
 /bin/launchctl list | /usr/bin/grep -c com.apple.timed
```

Expected result: 1

## Rule: os_touchid_prompt_disable

### Severity: medium

Explanation:
 The prompt for TouchID during Setup Assistant _MUST_ be disabled.
macOS prompts new users through enabling TouchID during Setup Assistant; this is not essential and, therefore, _MUST_ be disabled to prevent against the risk of individuals electing to enable TouchID to override organization-wide settings.


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.SetupAssistant.managed').objectForKey('SkipTouchIDSetup').js
EOS
```

Expected result: true

## Rule: os_unlock_active_user_session_disable

### Severity: 

Explanation:
 The ability to log in to another user's active or locked session _MUST_ be disabled. 
macOS has a privilege that can be granted to any user that will allow that user to unlock active user's sessions. Disabling the admins and/or user's ability to log into another user's active andlocked session prevents unauthorized persons from viewing potentially sensitive and/or personal information.


Command:
```bash
 /usr/bin/security authorizationdb read system.login.screensaver 2>&1 | /usr/bin/grep -c 'use-login-window-ui'
```

Expected result: 1

## Rule: os_uucp_disable

### Severity: medium

Explanation:
 The system _MUST_ not have the Unix-to-Unix Copy Protocol (UUCP) service active.
UUCP, a set of programs that enable the sending of files between different UNIX systems as well as sending commands to be executed on another system, is not essential and _MUST_ be disabled in order to prevent the unauthorized connection of devices, transfer of information, and tunneling. 
NOTE: UUCP service is disabled at startup by default macOS.


Command:
```bash
 /bin/launchctl print-disabled system | /usr/bin/grep -c '"com.apple.uucp" => disabled'
```

Expected result: 1

## Rule: pwpolicy_50_percent

### Severity: 

Explanation:
 The macOS should be configured to require users to change at least 50% of the characters when setting a new password. 
If the operating system allows users to consecutively reuse extensive portions of passwords, this increases the window of opportunity for a malicious user to guess the password. The number of changed characters refers to the number of changes required with respect to the total number of positions in the current password. In other words, characters may be the same within the two passwords; however, the positions of the like characters must be different.
To enforce a 50% character change when new passwords are created, many operating systems can be integrated with an enterprise-level directory service that meets or exceeds this requirement. 


Command:
```bash
 The technology does not support this requirement. This is an applicable-does not meet finding.
```

Expected result: 

## Rule: pwpolicy_account_inactivity_enforce

### Severity: 

Explanation:
 The macOS _MUST_ be configured to disable accounts after $ODV days of inactivity.
This rule prevents malicious users from making use of unused accounts to gain access to the system while avoiding detection. 


Command:
```bash
 /usr/bin/pwpolicy -getaccountpolicies 2> /dev/null | /usr/bin/tail +2 | /usr/bin/xmllint --xpath '//dict/key[text()="policyAttributeInactiveDays"]/following-sibling::integer[1]/text()' -
```

Expected result: 35

## Rule: pwpolicy_account_lockout_enforce

### Severity: medium

Explanation:
 The macOS _MUST_ be configured to limit the number of failed login attempts to a maximum of $ODV. When the maximum number of failed attempts is reached, the account _MUST_ be locked for a period of time after.
This rule protects against malicious users attempting to gain access to the system via brute-force hacking methods. 


Command:
```bash
 /usr/bin/pwpolicy -getaccountpolicies 2> /dev/null | /usr/bin/tail +2 | /usr/bin/xmllint --xpath '//dict/key[text()="policyAttributeMaximumFailedAuthentications"]/following-sibling::integer[1]/text()' - | /usr/bin/awk '{ if ($1 <= 3) {print "yes"} else {print "no"}}'
```

Expected result: yes

## Rule: pwpolicy_account_lockout_timeout_enforce

### Severity: 

Explanation:
 The macOS _MUST_ be configured to enforce a lockout time period of at least $ODV minutes when the maximum number of failed logon attempts is reached.
This rule protects against malicious users attempting to gain access to the system via brute-force hacking methods. 


Command:
```bash
 /usr/bin/pwpolicy -getaccountpolicies 2> /dev/null | /usr/bin/tail +2 | /usr/bin/xmllint --xpath '//dict/key[text()="autoEnableInSeconds"]/following-sibling::integer[1]/text()' - | /usr/bin/awk '{ if ($1/60 >= 15 ) {print "yes"} else {print "no"}}' 
```

Expected result: yes

## Rule: pwpolicy_alpha_numeric_enforce

### Severity: medium

Explanation:
 The macOS _MUST_ be configured to require at least one numeric character be used when a password is created.
This rule enforces password complexity by requiring users to set passwords that are less vulnerable to malicious users. 
NOTE: The guidance for password based authentication in NIST 800-53 (Rev 5) and NIST 800-63B state that complexity rules should be organizationally defined. The values defined are based off of common complexity values. But your organization may define its own password complexity rules.


Command:
```bash
 /usr/bin/pwpolicy -getaccountpolicies 2> /dev/null | /usr/bin/tail +2 | /usr/bin/xmllint --xpath '//dict/key[text()="policyIdentifier"]/following-sibling::*[1]/text()' - | /usr/bin/grep "requireAlphanumeric" -c
```

Expected result: 1

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

## Rule: pwpolicy_history_enforce

### Severity: medium

Explanation:
 The macOS _MUST_ be configured to enforce a password history of at least $ODV previous passwords when a password is created. 
This rule ensures that users are  not allowed to re-use a password that was used in any of the $ODV previous password generations. 
Limiting password reuse protects against malicious users attempting to gain access to the system via brute-force hacking methods.
NOTE: The guidance for password based authentication in NIST 800-53 (Rev 5) and NIST 800-63B state that complexity rules should be organizationally defined. The values defined are based off of common complexity values. But your organization may define its own password complexity rules.


Command:
```bash
 /usr/bin/pwpolicy -getaccountpolicies 2> /dev/null | /usr/bin/tail +2 | /usr/bin/xmllint --xpath '//dict/key[text()="policyAttributePasswordHistoryDepth"]/following-sibling::*[1]/text()' - | /usr/bin/awk '{ if ($1 >= 5 ) {print "yes"} else {print "no"}}'
```

Expected result: yes

## Rule: pwpolicy_lower_case_character_enforce

### Severity: 

Explanation:
 The macOS _MUST_ be configured to require at least one lower-case character be used when a password is created.
This rule enforces password complexity by requiring users to set passwords that are less vulnerable to malicious users. 
NOTE: The guidance for password based authentication in NIST 800-53 (Rev 5) and NIST 800-63B state that complexity rules should be organizationally defined. The values defined are based off of common complexity values. But your organization may define its own password complexity rules.


Command:
```bash
 /usr/bin/pwpolicy -getaccountpolicies 2> /dev/null | /usr/bin/tail +2 | /usr/bin/xmllint --xpath '//dict/key[text()="minimumAlphaCharactersLowerCase"]/following-sibling::integer[1]/text()' - | /usr/bin/awk '{ if ($1 >= 1 ) {print "yes"} else {print "no"}}' 
```

Expected result: yes

## Rule: pwpolicy_max_lifetime_enforce

### Severity: medium

Explanation:
 The macOS _MUST_ be configured to enforce a maximum password lifetime limit of at least $ODV days. 
This rule ensures that users are forced to change their passwords frequently enough to prevent malicious users from gaining and maintaining access to the system.
NOTE: The guidance for password based authentication in NIST 800-53 (Rev 5) and NIST 800-63B state that complexity rules should be organizationally defined. The values defined are based off of common complexity values. But your organization may define its own password complexity rules.


Command:
```bash
 /usr/bin/pwpolicy -getaccountpolicies 2> /dev/null | /usr/bin/tail +2 | /usr/bin/xmllint --xpath '//dict/key[text()="policyAttributeExpiresEveryNDays"]/following-sibling::*[1]/text()' -
```

Expected result: 60

## Rule: pwpolicy_minimum_length_enforce

### Severity: medium

Explanation:
 The macOS _MUST_ be configured to require a minimum of $ODV characters be used when a password is created.
This rule enforces password complexity by requiring users to set passwords that are less vulnerable to malicious users. 
NOTE: The guidance for password based authentication in NIST 800-53 (Rev 5) and NIST 800-63B state that complexity rules should be organizationally defined. The values defined are based off of common complexity values. But your organization may define its own password complexity rules.


Command:
```bash
 /usr/bin/pwpolicy -getaccountpolicies 2> /dev/null | /usr/bin/tail +2 | /usr/bin/xmllint --xpath 'boolean(//*[contains(text(),"policyAttributePassword matches '\''.{15,}'\''")])' -    
```

Expected result: true

## Rule: pwpolicy_minimum_lifetime_enforce

### Severity: 

Explanation:
 The macOS _MUST_ be configured to enforce a minimum password lifetime limit of $ODV hours.
This rule discourages users from cycling through their previous passwords to get back to a preferred one.
NOTE: The guidance for password based authentication in NIST 800-53 (Rev 5) and NIST 800-63B state that complexity rules should be organizationally defined. The values defined are based off of common complexity values. But your organization may define its own password complexity rules.


Command:
```bash
 /usr/bin/pwpolicy -getaccountpolicies 2> /dev/null | /usr/bin/tail +2 | /usr/bin/xmllint --xpath '//dict/key[text()="policyAttributeMinimumLifetimeHours"]/following-sibling::integer[1]/text()' - | /usr/bin/awk '{ if ($1 >= 24 ) {print "yes"} else {print "no"}}'
```

Expected result: yes

## Rule: pwpolicy_simple_sequence_disable

### Severity: 

Explanation:
 The macOS _MUST_ be configured to prohibit the use of repeating, ascending, and descending character sequences when a password is created.
This rule enforces password complexity by requiring users to set passwords that are less vulnerable to malicious users.
NOTE: The guidance for password based authentication in NIST 800-53 (Rev 5) and NIST 800-63B state that complexity rules should be organizationally defined. The values defined are based off of common complexity values. But your organization may define its own password complexity rules.


Command:
```bash
 /usr/bin/pwpolicy -getaccountpolicies 2> /dev/null | /usr/bin/tail +2 | /usr/bin/xmllint --xpath '//dict/key[text()="policyIdentifier"]/following-sibling::*[1]/text()' - | /usr/bin/grep "allowSimple" -c
```

Expected result: 1

## Rule: pwpolicy_special_character_enforce

### Severity: medium

Explanation:
 The macOS _MUST_ be configured to require at least one special character be used when a password is created.
Special characters are those characters that are not alphanumeric. Examples include: ~ ! @ # $ % ^ *.
This rule enforces password complexity by requiring users to set passwords that are less vulnerable to malicious users.
NOTE: The guidance for password based authentication in NIST 800-53 (Rev 5) and NIST 800-63B state that complexity rules should be organizationally defined. The values defined are based off of common complexity values. But your organization may define its own password complexity rules.


Command:
```bash
 /usr/bin/pwpolicy -getaccountpolicies 2> /dev/null | /usr/bin/tail +2 | /usr/bin/xmllint --xpath 'boolean(//*[contains(text(),"policyAttributePassword matches '\''(.*[^a-zA-Z0-9].*){1,}'\''")])' -  
```

Expected result: true

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

## Rule: pwpolicy_temporary_or_emergency_accounts_disable

### Severity: medium

Explanation:
 The macOS is able to be configured to set an automated termination for 72 hours or less for all temporary or emergency accounts upon account creation. 
Emergency administrator accounts are privileged accounts established in response to crisis situations where the need for rapid account activation is required. Therefore, emergency account activation may bypass normal account authorization processes. If these accounts are disabled, system maintenance during emergencies may not be possible, thus adversely affecting system availability.
Although the ability to create and use emergency administrator accounts is necessary for performing system maintenance during emergencies, these accounts present vulnerabilities to the system if they are not disabled and removed when they are no longer needed. Configuring the macOS to automatically remove or disable emergency accounts within 72 hours of creation mitigates the risks posed if one were to be created and accidentally left active once the crisis is resolved. 
Emergency administrator accounts are different from infrequently used accounts (i.e., local logon accounts used by system administrators when network or normal logon is not available). Infrequently used accounts also remain available and are not subject to automatic termination dates. However, an emergency administrator account is normally a different account created for use by vendors or system maintainers.
To address access requirements, many operating systems can be integrated with enterprise-level authentication/access mechanisms that meet or exceed access control policy requirements.
If temporary or emergency user accounts remain active when no longer needed or for an excessive period, these accounts may be targeted by attackers to gain unauthorized access. To mitigate this risk, automated termination of all temporary or emergency accounts _MUST_ be set to 72 hours (or less) when the temporary or emergency account is created.
If no policy is enforced by a directory service, a password policy can be set with the "pwpolicy" utility. The variable names may vary depending on how the policy was set.
If there are no temporary or emergency accounts defined on the system, this is Not Applicable.


Command:
```bash
 Verify if a password policy is enforced by a directory service by asking the System Administrator (SA) or Information System Security Officer (ISSO). 

If no policy is enforced by a directory service, a password policy can be set with the "pwpolicy" utility. The variable names may vary depending on how the policy was set. 

If there are no temporary or emergency accounts defined on the system, this is Not Applicable.

To check if the password policy is configured to disable a temporary or emergency account after 72 hours, run the following command to output the password policy to the screen, substituting the correct user name in place of username:

/usr/bin/pwpolicy -u username getaccountpolicies | tail -n +2

If there is no output, and password policy is not controlled by a directory service, this is a finding.

Otherwise, look for the line "<key>policyCategoryAuthentication</key>".

In the array that follows, there should be a <dict> section that contains a check <string> that allows users to log in if "policyAttributeCurrentTime" is less than the result of adding "policyAttributeCreationTime" to 72 hours (259299 seconds). The check might use a variable defined in its "policyParameters" section.

If the check does not exist or if the check adds too great an amount of time to "policyAttributeCreationTime", this is a finding.
```

Expected result: 

## Rule: pwpolicy_upper_case_character_enforce

### Severity: 

Explanation:
 The macOS _MUST_ be configured to require at least one uppercase character be used when a password is created.
This rule enforces password complexity by requiring users to set passwords that are less vulnerable to malicious users. 
NOTE: The guidance for password based authentication in NIST 800-53 (Rev 5) and NIST 800-63B state that complexity rules should be organizationally defined. The values defined are based off of common complexity values. But your organization may define its own password complexity rules.


Command:
```bash
 /usr/bin/pwpolicy -getaccountpolicies 2> /dev/null | /usr/bin/tail +2 | /usr/bin/xmllint --xpath '//dict/key[text()="minimumAlphaCharactersUpperCase"]/following-sibling::integer[1]/text()' - | /usr/bin/awk '{ if ($1 >= $ODV ) {print "yes"} else {print "no"}}' 
```

Expected result: yes

## Rule: system_settings_apple_watch_unlock_disable

### Severity: medium

Explanation:
 Apple Watches are not an approved authenticator and their use _MUST_ be disabled.
Disabling Apple watches is a necessary step to ensuring that the information system retains a session lock until the user reestablishes access using an authorized identification and authentication procedures.


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess').objectForKey('allowAutoUnlock').js
EOS
```

Expected result: false

## Rule: system_settings_automatic_login_disable

### Severity: medium

Explanation:
 Automatic logon _MUST_ be disabled.
When automatic logons are enabled, the default user account is automatically logged on at boot time without prompting the user for a password. Even if the screen is later locked, a malicious user would be able to reboot the computer and find it already logged in. Disabling automatic logons mitigates this risk.


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.loginwindow').objectForKey('com.apple.login.mcx.DisableAutoLoginClient').js
EOS
```

Expected result: true

## Rule: system_settings_automatic_logout_enforce

### Severity: 

Explanation:
 Auto logout _MUST_ be configured to automatically terminate a user session and log out the after $ODV seconds of inactivity. 
NOTE:The maximum that macOS can be configured for autologoff is $ODV seconds.
[IMPORTANT]
 ====
 The automatic logout may cause disruptions to an organization's workflow and/or loss of data. Information System Security Officers (ISSOs) are advised to first fully weigh the potential risks posed to their organization before opting to disable the automatic logout setting.
 ====


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('.GlobalPreferences').objectForKey('com.apple.autologout.AutoLogOutDelay').js
EOS
```

Expected result: 86400

## Rule: system_settings_bluetooth_disable

### Severity: low

Explanation:
 The macOS system _MUST_ be configured to disable Bluetooth unless there is an approved device connected.
[IMPORTANT]
 ====
 Information System Security Officers (ISSOs) may make the risk-based decision not to disable Bluetooth, so as to maintain necessary functionality, but they are advised to first fully weigh the potential risks posed to their organization. 
 ====


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.MCXBluetooth').objectForKey('DisableBluetooth').js
EOS
```

Expected result: true

## Rule: system_settings_bluetooth_sharing_disable

### Severity: 

Explanation:
 Bluetooth Sharing _MUST_ be disabled. 
Bluetooth Sharing allows users to wirelessly transmit files between the macOS and Bluetooth-enabled devices, including personally owned cellphones and tablets. A malicious user might introduce viruses or malware onto the system or extract sensitive files via Bluetooth Sharing. When Bluetooth Sharing is disabled, this risk is mitigated. 
[NOTE] 
 ====
 The check and fix are for the currently logged in user. To get the currently logged in user, run the following.
 [source,bash]
 ----
 CURRENT_USER=$( /usr/sbin/scutil <<< "show State:/Users/ConsoleUser" | /usr/bin/awk '/Name :/ && ! /loginwindow/ { print $3 }' )
 ----
 ====


Command:
```bash
 /usr/bin/sudo -u "$CURRENT_USER" /usr/bin/defaults -currentHost read com.apple.Bluetooth PrefKeyServicesEnabled
```

Expected result: 0

## Rule: system_settings_cd_dvd_sharing_disable

### Severity: 

Explanation:
 CD/DVD Sharing _MUST_ be disabled. 


Command:
```bash
 /usr/bin/pgrep -q ODSAgent; /bin/echo $?
```

Expected result: 1

## Rule: system_settings_content_caching_disable

### Severity: 

Explanation:
 Content caching _MUST_ be disabled. 
Content caching is a macOS service that helps reduce Internet data usage and speed up software installation on Mac computers. It is not recommended for devices furnished to employees to act as a caching server. 


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess').objectForKey('allowContentCaching').js
EOS
```

Expected result: false

## Rule: system_settings_diagnostics_reports_disable

### Severity: medium

Explanation:
 The ability to submit diagnostic data to Apple _MUST_ be disabled.
The information system _MUST_ be configured to provide only essential capabilities. Disabling the submission of diagnostic and usage information will mitigate the risk of unwanted data being sent to Apple. 


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
function run() {
let pref1 = $.NSUserDefaults.alloc.initWithSuiteName('com.apple.SubmitDiagInfo').objectForKey('AutoSubmit').js
let pref2 = $.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess').objectForKey('allowDiagnosticSubmission').js
if ( pref1 == false && pref2 == false ){
    return("true")
} else {
    return("false")
}
}
EOS
```

Expected result: true

## Rule: system_settings_filevault_enforce

### Severity: medium

Explanation:
 FileVault _MUST_ be enforced.
The information system implements cryptographic mechanisms to protect the confidentiality and integrity of information stored on digital media during transport outside of controlled areas.


Command:
```bash
 /usr/bin/fdesetup status | /usr/bin/grep -c "FileVault is On."
```

Expected result: 1

## Rule: system_settings_find_my_disable

### Severity: 

Explanation:
 The Find My service _MUST_ be disabled.
A Mobile Device Management (MDM) solution _MUST_ be used to carry out remote locking and wiping instead of Apple's Find My service.
Apple's Find My service uses a personal AppleID for authentication. Organizations should rely on MDM solutions, which have much more secure authentication requirements, to perform remote lock and remote wipe.


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
function run() {
  let pref1 = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess').objectForKey('allowFindMyDevice'))
  let pref2 = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess').objectForKey('allowFindMyFriends'))
  let pref3 = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.icloud.managed').objectForKey('DisableFMMiCloudSetting'))
  if ( pref1 == false && pref2 == false && pref3 == true ) {
    return("true")
  } else {
    return("false")
  }
}
EOS
```

Expected result: true

## Rule: system_settings_firewall_enable

### Severity: medium

Explanation:
 The macOS Application Firewall is the built-in firewall that comes with macOS, and it _MUST_ be enabled. 
When the macOS Application Firewall is enabled, the flow of information within the information system and between interconnected systems will be controlled by approved authorizations.


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.security.firewall').objectForKey('EnableFirewall').js
EOS
```

Expected result: true

## Rule: system_settings_firewall_stealth_mode_enable

### Severity: medium

Explanation:
 Firewall Stealth Mode _MUST_ be enabled. 
When stealth mode is enabled, the Mac will not respond to any probing requests, and only requests from authorized applications will still be authorized.
[IMPORTANT]
 ====
 Enabling firewall stealth mode may prevent certain remote mechanisms used for maintenance and compliance scanning from properly functioning. Information System Security Officers (ISSOs) are advised to first fully weigh the potential risks posed to their organization before opting not to enable stealth mode.
 ====


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.security.firewall').objectForKey('EnableStealthMode').js
EOS
```

Expected result: true

## Rule: system_settings_gatekeeper_identified_developers_allowed

### Severity: medium

Explanation:
 The information system implements cryptographic mechanisms to authenticate software prior to installation.
Gatekeeper settings must be configured correctly to only allow the system to run applications downloaded from the Mac App Store or applications signed with a valid Apple Developer ID code. Administrator users will still have the option to override these settings on a per-app basis. Gatekeeper is a security feature that ensures that applications must be digitally signed by an Apple-issued certificate in order to run. Digital signatures allow the macOS to verify that the application has not been modified by a malicious third party.


Command:
```bash
 /usr/sbin/spctl --status --verbose | /usr/bin/grep -c "developer id enabled"
```

Expected result: 1

## Rule: system_settings_gatekeeper_override_disallow

### Severity: medium

Explanation:
 Gatekeeper _MUST_ be configured with a configuration profile to prevent normal users from overriding its settings. 
If users are allowed to disable Gatekeeper or set it to a less restrictive setting, malware could be introduced into the system. 


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.systempolicy.managed').objectForKey('DisableOverride').js
EOS
```

Expected result: true

## Rule: system_settings_guest_access_smb_disable

### Severity: 

Explanation:
 Guest access to shared Server Message Block (SMB) folders _MUST_ be disabled. 
Turning off guest access prevents anonymous users from accessing files shared via SMB.


Command:
```bash
 /usr/bin/defaults read /Library/Preferences/SystemConfiguration/com.apple.smb.server AllowGuestAccess
```

Expected result: 0

## Rule: system_settings_guest_account_disable

### Severity: high

Explanation:
 Guest access _MUST_ be disabled. 
Turning off guest access prevents anonymous users from accessing files.


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.MCX').objectForKey('DisableGuestAccount').js
EOS
```

Expected result: true

## Rule: system_settings_hot_corners_disable

### Severity: medium

Explanation:
 Hot corners _MUST_ be disabled. 
The information system conceals, via the session lock, information previously visible on the display with a publicly viewable image. Although hot comers can be used to initiate a session lock or to launch useful applications, they can also be configured to disable an automatic session lock from initiating. Such a configuration introduces the risk that a user might forget to manually lock the screen before stepping away from the computer.


Command:
```bash
 /usr/bin/profiles -P -o stdout | /usr/bin/grep -Ec '"wvous-bl-corner" = 0|"wvous-br-corner" = 0|"wvous-tl-corner" = 0|"wvous-tr-corner" = 0'
```

Expected result: 4

## Rule: system_settings_improve_siri_dictation_disable

### Severity: 

Explanation:
 The ability for Apple to store and review audio of your Siri and Dictation interactions _MUST_ be disabled.
The information system _MUST_ be configured to provide only essential capabilities. Disabling the submission of Siri and Dictation information will mitigate the risk of unwanted data being sent to Apple. 


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.assistant.support').objectForKey('Siri Data Sharing Opt-In Status').js
EOS
```

Expected result: 2

## Rule: system_settings_internet_accounts_disable

### Severity: medium

Explanation:
 The Internet Accounts System Setting _MUST_ be disabled to prevent the addition of unauthorized internet accounts.
[IMPORTANT]
 ====
 Some organizations may allow the use and configuration of the built-in Mail.app, Calendar.app, and Contacts.app for organizational communication. Information System Security Officers (ISSOs) may make the risk-based decision not to disable the Internet Accounts System Preference pane to avoid losing this functionality, but they are advised to first fully weigh the potential risks posed to their organization.
 ====


Command:
```bash
 /usr/bin/profiles show -output stdout-xml | /usr/bin/xmllint --xpath '//key[text()="DisabledSystemSettings"]/following-sibling::*[1]' - | /usr/bin/grep -c com.apple.Internet-Accounts-Settings.extension
```

Expected result: 1

## Rule: system_settings_internet_sharing_disable

### Severity: medium

Explanation:
 If the system does not require Internet sharing, support for it is non-essential and _MUST_ be disabled.
The information system _MUST_ be configured to provide only essential capabilities. Disabling Internet sharing helps prevent the unauthorized connection of devices, unauthorized transfer of information, and unauthorized tunneling.


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.MCX').objectForKey('forceInternetSharingOff').js
EOS
```

Expected result: true

## Rule: system_settings_location_services_disable

### Severity: medium

Explanation:
 Location Services _MUST_ be disabled. 
The information system _MUST_ be configured to provide only essential capabilities.  Disabling Location Services helps prevent the unauthorized connection of devices, unauthorized transfer of information, and unauthorized tunneling.


Command:
```bash
 /usr/bin/sudo -u _locationd /usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.locationd').objectForKey('LocationServicesEnabled').js
EOS
```

Expected result: false

## Rule: system_settings_loginwindow_prompt_username_password_enforce

### Severity: low

Explanation:
 The login window _MUST_ be configured to prompt all users for both a username and a password. 
By default, the system displays a list of known users on the login window, which can make it easier for a malicious user to gain access to someone else's account. Requiring users to type in both their username and password mitigates the risk of unauthorized users gaining access to the information system. 


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.loginwindow').objectForKey('SHOWFULLNAME').js
EOS
```

Expected result: true

## Rule: system_settings_media_sharing_disabled

### Severity: 

Explanation:
 Media sharing _MUST_ be disabled.
When Media Sharing is enabled, the computer starts a network listening service that shares the contents of the user's music collection with other users in the same subnet. 
The information system _MUST_ be configured to provide only essential capabilities. Disabling Media Sharing helps prevent the unauthorized connection of devices and the unauthorized transfer of information. Disabling Media Sharing mitigates this risk.
NOTE: The Media Sharing preference panel will still allow "Home Sharing" and "Share media with guests" to be checked but the service will not be enabled.


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
function run() {
  let pref1 = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.preferences.sharing.SharingPrefsExtension')  .objectForKey('homeSharingUIStatus'))
  let pref2 = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.preferences.sharing.SharingPrefsExtension')  .objectForKey('legacySharingUIStatus'))
  let pref3 = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.preferences.sharing.SharingPrefsExtension')  .objectForKey('mediaSharingUIStatus'))
  if ( pref1 == 0 && pref2 == 0 && pref3 == 0 ) {
    return("true")
  } else {
    return("false")
  }
}
EOS
```

Expected result: true

## Rule: system_settings_password_hints_disable

### Severity: medium

Explanation:
 Password hints _MUST_ be disabled.
Password hints leak information about passwords that are currently in use and can lead to loss of confidentiality. 


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.loginwindow').objectForKey('RetriesUntilHint').js
EOS
```

Expected result: 0

## Rule: system_settings_personalized_advertising_disable

### Severity: 

Explanation:
 Ad tracking and targeted ads _MUST_ be disabled.
The information system _MUST_ be configured to provide only essential capabilities. Disabling ad tracking ensures that applications and advertisers are unable to track users' interests and deliver targeted advertisements.  


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess').objectForKey('allowApplePersonalizedAdvertising').js
EOS
```

Expected result: false

## Rule: system_settings_printer_sharing_disable

### Severity: 

Explanation:
 Printer Sharing _MUST_ be disabled. 


Command:
```bash
 /usr/sbin/cupsctl | /usr/bin/grep -c "_share_printers=0"
```

Expected result: 1

## Rule: system_settings_rae_disable

### Severity: medium

Explanation:
 If the system does not require Remote Apple Events, support for Apple Remote Events is non-essential and _MUST_ be disabled.
The information system _MUST_ be configured to provide only essential capabilities. Disabling Remote Apple Events helps prevent the unauthorized connection of devices, the unauthorized transfer of information, and unauthorized tunneling. 


Command:
```bash
 /bin/launchctl print-disabled system | /usr/bin/grep -c '"com.apple.AEServer" => disabled'
```

Expected result: 1

## Rule: system_settings_remote_management_disable

### Severity: 

Explanation:
 Remote Management _MUST_ be disabled. 


Command:
```bash
 /usr/libexec/mdmclient QuerySecurityInfo | /usr/bin/grep -c "RemoteDesktopEnabled = 0"
```

Expected result: 1

## Rule: system_settings_screensaver_ask_for_password_delay_enforce

### Severity: medium

Explanation:
 A screen saver _MUST_ be enabled and the system _MUST_ be configured to require a password to unlock once the screensaver has been on for a maximum of $ODV seconds. 
An unattended system with an excessive grace period is vulnerable to a malicious user. 


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
function run() {
  let delay = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.screensaver').objectForKey('askForPasswordDelay'))
  if ( delay <= 5 ) {
    return("true")
  } else {
    return("false")
  }
}
EOS
```

Expected result: true

## Rule: system_settings_screensaver_password_enforce

### Severity: medium

Explanation:
 Users _MUST_ authenticate when unlocking the screen saver. 
The screen saver acts as a session lock and prevents unauthorized users from accessing the current user's account.


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.screensaver').objectForKey('askForPassword').js
EOS
```

Expected result: true

## Rule: system_settings_screensaver_timeout_enforce

### Severity: medium

Explanation:
 The screen saver timeout _MUST_ be set to $ODV seconds or a shorter length of time. 
This rule ensures that a full session lock is triggered within no more than $ODV seconds of inactivity.


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
function run() {
  let timeout = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.screensaver').objectForKey('idleTime'))
  if ( timeout <= 1200 ) {
    return("true")
  } else {
    return("false")
  }
}
EOS
```

Expected result: true

## Rule: system_settings_screen_sharing_disable

### Severity: medium

Explanation:
 Support for both Screen Sharing and Apple Remote Desktop (ARD) is non-essential and _MUST_ be disabled.
The information system _MUST_ be configured to provide only essential capabilities. Disabling screen sharing and ARD helps prevent the unauthorized connection of devices, the unauthorized transfer of information, and unauthorized tunneling.


Command:
```bash
 /bin/launchctl print-disabled system | /usr/bin/grep -c '"com.apple.screensharing" => disabled'
```

Expected result: 1

## Rule: system_settings_siri_disable

### Severity: medium

Explanation:
 Support for Siri is non-essential and _MUST_ be disabled.
The information system _MUST_ be configured to provide only essential capabilities.


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.ironwood.support').objectForKey('Ironwood Allowed').js
EOS
```

Expected result: false

## Rule: system_settings_smbd_disable

### Severity: medium

Explanation:
 Support for Server Message Block (SMB) file sharing is non-essential and _MUST_ be disabled.
The information system _MUST_ be configured to provide only essential capabilities.


Command:
```bash
 /bin/launchctl print-disabled system | /usr/bin/grep -c '"com.apple.smbd" => disabled'
```

Expected result: 1

## Rule: system_settings_ssh_enable

### Severity: 

Explanation:
 Remote access sessions _MUST_ use encrypted methods to protect unauthorized individuals from gaining access. 


Command:
```bash
 /bin/launchctl print-disabled system | /usr/bin/grep -c '"com.openssh.sshd" => enabled'
```

Expected result: 1

## Rule: system_settings_system_wide_preferences_configure

### Severity: medium

Explanation:
 The system _MUST_ be configured to require an administrator password in order to modify the system-wide preferences in System Settings. 
Some Preference Panes in System Settings contain settings that affect the entire system. Requiring a password to unlock these system-wide settings reduces the risk of a non-authorized user modifying system configurations.


Command:
```bash
 authDBs=("system.preferences" "system.preferences.energysaver" "system.preferences.network" "system.preferences.printing" "system.preferences.sharing" "system.preferences.softwareupdate" "system.preferences.startupdisk" "system.preferences.timemachine")
result="1"
for section in ${authDBs[@]}; do
  if [[ $(/usr/bin/security -q authorizationdb read "$section" | /usr/bin/xmllint -xpath 'name(//*[contains(text(), "shared")]/following-sibling::*[1])' -) != "false" ]]; then
    result="0"
  fi
done
echo $result
```

Expected result: 1

## Rule: system_settings_time_server_configure

### Severity: medium

Explanation:
 Approved time servers _MUST_ be the only servers configured for use.
This rule ensures the uniformity of time stamps for information systems with multiple system clocks and systems connected over a network.


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.MCX').objectForKey('timeServer').js
EOS
```

Expected result: time-a.nist.gov,time-b.nist.gov

## Rule: system_settings_time_server_enforce

### Severity: medium

Explanation:
 Time synchronization _MUST_ be enforced on all networked systems.
This rule ensures the uniformity of time stamps for information systems with multiple system clocks and systems connected over a network.


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.timed').objectForKey('TMAutomaticTimeOnlyEnabled').js
EOS
```

Expected result: true

## Rule: system_settings_token_removal_enforce

### Severity: medium

Explanation:
 The screen lock _MUST_ be configured to initiate automatically when the smart token is removed from the system.
Session locks are temporary actions taken when users stop work and move away from the immediate vicinity of the information system but do not want to log out because of the temporary nature of their absences. While a session lock is not an acceptable substitute for logging out of an information system for longer periods of time, they prevent a malicious user from accessing the information system when a user has removed their smart token. 
[IMPORTANT]
 ====
 Information System Security Officers (ISSOs) may make the risk-based decision not to enforce a session lock when a smart token is removed, so as to maintain necessary workflow capabilities, but they are advised to first fully weigh the potential risks posed to their organization. 
 ====


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.security.smartcard').objectForKey('tokenRemovalAction').js
EOS
```

Expected result: 1

## Rule: system_settings_touchid_unlock_disable

### Severity: 

Explanation:
 TouchID enables the ability to unlock a Mac system with a user's fingerprint. 
TouchID _MUST_ be disabled for "Unlocking your Mac" on all macOS devices that are capable of using Touch ID. 
The system _MUST_ remain locked until the user establishes access using an authorized identification and authentication method. 


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess').objectForKey('allowFingerprintForUnlock').js
EOS
```

Expected result: false

## Rule: system_settings_wifi_disable

### Severity: medium

Explanation:
 The macOS system must be configured with Wi-Fi support software disabled if not connected to an authorized trusted network. 
Allowing devices and users to connect to or from the system without first authenticating them allows untrusted access and can lead to a compromise or attack. Since wireless communications can be intercepted  it is necessary to use encryption to protect the confidentiality of information in transit.Wireless technologies include  for example  microwave  packet radio (UHF/VHF)  802.11x  and Bluetooth. Wireless networks use authentication protocols (e.g.  EAP/TLS  PEAP)  which provide credential protection and mutual authentication.
NOTE: If the system requires Wi-Fi to connect to an authorized network, this is not applicable.


Command:
```bash
 /usr/sbin/networksetup -listallnetworkservices | /usr/bin/grep -c "*Wi-Fi"
```

Expected result: 1

## Rule: system_settings_wifi_disable_when_connected_to_ethernet

### Severity: 

Explanation:
 The macOS should be configured to automatically disable Wi-Fi when connected to ethernet. 
The use of Wi-Fi to connect to unauthorized networks may facilitate the exfiltration of mission data. Therefore, wireless networking capabilities internally embedded within information system components should be disabled when not intended to be used. 
NOTE: If the system requires Wi-Fi to connect to an authorized network, this is not applicable.


Command:
```bash
 The technology does not support this requirement. This is an applicable-does not meet finding.
```

Expected result: 

