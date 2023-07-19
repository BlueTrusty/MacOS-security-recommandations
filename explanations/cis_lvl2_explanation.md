# Explanation of the rules for cis_lvl2

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

## Rule: audit_control_acls_configure

### Severity: 

Explanation:
 /etc/security/audit_control _MUST_ not contain Access Control Lists (ACLs).


Command:
```bash
 /bin/ls -le /etc/security/audit_control | /usr/bin/awk '{print $1}' | /usr/bin/grep -c ":"
```

Expected result: 0

## Rule: audit_control_group_configure

### Severity: 

Explanation:
 /etc/security/audit_control _MUST_ have the group set to wheel.


Command:
```bash
 /bin/ls -dn /etc/security/audit_control | /usr/bin/awk '{print $4}'
```

Expected result: 0

## Rule: audit_control_mode_configure

### Severity: 

Explanation:
 /etc/security/audit_control _MUST_ be configured so that it is readable only by the root user and group wheel.


Command:
```bash
 /bin/ls -l /etc/security/audit_control | awk '!/-r--r-----|current|total/{print $1}' | /usr/bin/wc -l | /usr/bin/xargs
```

Expected result: 0

## Rule: audit_control_owner_configure

### Severity: 

Explanation:
 /etc/security/audit_control _MUST_ have the owner set to root.


Command:
```bash
 /bin/ls -dn /etc/security/audit_control | /usr/bin/awk '{print $3}'
```

Expected result: 0

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

Expected result: 60d OR 5G

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

## Rule: os_config_data_install_enforce

### Severity: high

Explanation:
 Software Update _MUST_ be configured to update XProtect Remediator and Gatekeepr automatically.
This setting enforces definition updates for XProtect Remediator and Gatekeeper; with this setting in place, new malware and adware that Apple has added to the list of malware or untrusted software will not execute. These updates do not require the computer to be restarted.
link:https://support.apple.com/en-us/HT207005[]
NOTE: Software update will automatically update XProtect Remediator and Gatekeeper by default in the macOS.


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.SoftwareUpdate').objectForKey('ConfigDataInstall').js
EOS
```

Expected result: true

## Rule: os_efi_integrity_validated

### Severity: 

Explanation:
 The macOS Extensible Firmware Interface (EFI) _MUST_ be checked to ensure it is a known good version from Apple.


Command:
```bash
 if /usr/sbin/ioreg -w 0 -c AppleSEPManager | /usr/bin/grep -q AppleSEPManager; then echo "1"; else /usr/libexec/firmwarecheckers/eficheck/eficheck --integrity-check | /usr/bin/grep -c "No changes detected"; fi
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

## Rule: os_guest_folder_removed

### Severity: 

Explanation:
 The guest folder _MUST_ be deleted if present.


Command:
```bash
 /bin/ls /Users/ | /usr/bin/grep -c "Guest"
```

Expected result: 0

## Rule: os_hibernate_mode_destroyfvkeyonstandby_enable

### Severity: 

Explanation:
 DestroyFVKeyOnStandby on hibernate _MUST_ be enabled. 


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.MCX').objectForKey('DestroyFVKeyOnStandby').js
EOS
```

Expected result: true

## Rule: os_hibernate_mode_enable

### Severity: 

Explanation:
 Hibernate mode _MUST_ be enabled. 
NOTE: Hibernate mode will disable instant wake on Apple Silicon laptops.


Command:
```bash
 error_count=0
if /usr/sbin/ioreg -rd1 -c IOPlatformExpertDevice 2>&1 | /usr/bin/grep -q "MacBook"; then
  hibernateMode=$(/usr/bin/pmset -b -g | /usr/bin/grep hibernatemode 2>&1 | /usr/bin/awk '{print $2}')
  if [[ "$(/usr/sbin/sysctl -n machdep.cpu.brand_string)" =~ "Intel" ]]; then
      hibernateStandbyLowValue=$(/usr/bin/pmset -g | /usr/bin/grep standbydelaylow 2>&1 | /usr/bin/awk '{print $2}')
      hibernateStandbyHighValue=$(/usr/bin/pmset -g | /usr/bin/grep standbydelayhigh 2>&1 | /usr/bin/awk '{print $2}')
      hibernateStandbyThreshValue=$(/usr/bin/pmset -g | /usr/bin/grep highstandbythreshold 2>&1 | /usr/bin/awk '{print $2}')
      
      if [[ "$hibernateStandbyLowValue" == "" ]] || [[ "$hibernateStandbyLowValue" -gt 600 ]]; then
          ((error_count++))
      fi
      if [[ "$hibernateStandbyHighValue" == "" ]] || [[ "$hibernateStandbyHighValue" -gt 600 ]]; then
          ((error_count++))
      fi
      if [[ "$hibernateStandbyThreshValue" == "" ]] || [[ "$hibernateStandbyThreshValue" -lt 90 ]]; then
          ((error_count++))
      fi
  else
      if [[ "$(/usr/bin/pmset -g | /usr/bin/grep standbydelay 2>&1 | /usr/bin/awk '{print $2}')" -gt 900 ]]; then
          ((error_count++))
      fi
  fi
  if [[ "$hibernateMode" == "" ]] || [[ "$hibernateMode" != 25 ]]; then
    ((error_count++))
  fi
fi
echo "$error_count"
```

Expected result: 0

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

## Rule: os_install_log_retention_configure

### Severity: 

Explanation:
 The install.log _MUST_ be configured to require records be kept for a organizational defined value before deletion, unless the system uses a central audit record storage facility. 


Command:
```bash
 /usr/sbin/aslmanager -dd 2>&1 | /usr/bin/awk '/\/var\/log\/install.log/ {count++} /Processing module com.apple.install/,/Finished/ { for (i=1;i<=NR;i++) { if ($i == "TTL" && $(i+2) >= 365) { ttl="True" }; if ($i == "MAX") {max="True"}}} END{if (count > 1) { print "Multiple config files for /var/log/install, manually remove"} else if (ttl != "True") { print "TTL not configured" } else if (max == "True") { print "Max Size is configured, must be removed" } else { print "Yes" }}'
```

Expected result: Yes

## Rule: os_mobile_file_integrity_enable

### Severity: 

Explanation:
 Mobile file integrity _MUST_ be ebabled.

Command:
```bash
 /usr/sbin/nvram -p | /usr/bin/grep -c "amfi_get_out_of_my_way=1"
```

Expected result: 0

## Rule: os_nfsd_disable

### Severity: medium

Explanation:
 Support for Network File Systems (NFS) services is non-essential and, therefore, _MUST_ be disabled.


Command:
```bash
 /bin/launchctl print-disabled system | /usr/bin/grep -c '"com.apple.nfsd" => disabled'
```

Expected result: 1

## Rule: os_password_hint_remove

### Severity: 

Explanation:
 User accounts _MUST_ not contain password hints.


Command:
```bash
 /usr/bin/dscl . -list /Users hint | /usr/bin/awk '{print $2}' | /usr/bin/wc -l | /usr/bin/xargs
```

Expected result: 0

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

## Rule: os_power_nap_disable

### Severity: 

Explanation:
 Power Nap _MUST_ be disabled.
NOTE: Power Nap allows your Mac to perform actions while a Mac is asleep. This can interfere with USB power and may cause devices such as smartcards to stop functioning until a reboot and must therefore be disabled on all applicable systems. 
The following Macs support Power Nap:
* MacBook (Early 2015 and later)
 * MacBook Air (Late 2010 and later)
 * MacBook Pro (all models with Retina display)
 * Mac mini (Late 2012 and later)
 * iMac (Late 2012 and later)
 * Mac Pro (Late 2013 and later)


Command:
```bash
 /usr/bin/pmset -g custom | /usr/bin/awk '/powernap/ { sum+=$2 } END {print sum}'
```

Expected result: 0

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

## Rule: os_safari_advertising_privacy_protection_enable

### Severity: 

Explanation:
 Allow privacy-preserving measurement of ad effectiveness _MUST_ be enabled in Safari. 


Command:
```bash
 /usr/bin/profiles -P -o stdout | /usr/bin/grep -c '"WebKitPreferences.privateClickMeasurementEnabled" = 1' | /usr/bin/awk '{ if ($1 >= 1) {print "1"} else {print "0"}}'
```

Expected result: 1

## Rule: os_safari_open_safe_downloads_disable

### Severity: 

Explanation:
 Open "safe" files after downloading _MUST_ be disabled in Safari. 


Command:
```bash
 /usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'AutoOpenSafeDownloads = 0' | /usr/bin/awk '{ if ($1 >= 1) {print "1"} else {print "0"}}'
```

Expected result: 1

## Rule: os_safari_prevent_cross-site_tracking_enable

### Severity: 

Explanation:
 Prevent cross-site tracking _MUST_ be enabled in Safari.


Command:
```bash
 /usr/bin/profiles -P -o stdout | /usr/bin/grep -cE '"WebKitPreferences.storageBlockingPolicy" = 1|"WebKitStorageBlockingPolicy" = 1|"BlockStoragePolicy" =2' | /usr/bin/awk '{ if ($1 >= 1) {print "1"} else {print "0"}}'
```

Expected result: 1

## Rule: os_safari_show_full_website_address_enable

### Severity: 

Explanation:
 Show full website address _MUST_ be enabled in Safari. 


Command:
```bash
 /usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'ShowFullURLInSmartSearchField = 1' | /usr/bin/awk '{ if ($1 >= 1) {print "1"} else {print "0"}}'
```

Expected result: 1

## Rule: os_safari_warn_fraudulent_website_enable

### Severity: 

Explanation:
 Warn when visiting a fraudulent website _MUST_ be enabled in Safari. 


Command:
```bash
 /usr/bin/profiles -P -o stdout | /usr/bin/grep -c 'WarnAboutFraudulentWebsites = 1' | /usr/bin/awk '{ if ($1 >= 1) {print "1"} else {print "0"}}'
```

Expected result: 1

## Rule: os_show_filename_extensions_enable

### Severity: 

Explanation:
 Show all filename extensions _MUST_ be enabled in the Finder.
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
 /usr/bin/sudo -u "$CURRENT_USER" /usr/bin/defaults read .GlobalPreferences AppleShowAllExtensions 2>/dev/null
```

Expected result: 1

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

## Rule: os_software_update_deferral

### Severity: 

Explanation:
 Software updates _MUST_ be deferred for $ODV days or less.


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
function run() {
  let timeout = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess').objectForKey('enforcedSoftwareUpdateDelay')) || 0
  if ( timeout <= 30 ) {
    return("true")
  } else {
    return("false")
  }
}
EOS
```

Expected result: true

## Rule: os_sudoers_timestamp_type_configure

### Severity: 

Explanation:
 The file /etc/sudoers _MUST_ be configured to not include a timestamp_type of global or ppid aand be configured for timestamp record types of tty.
This rule ensures that the "sudo" command will prompt for the administrator's password at least once in each newly opened terminal window. This prevents a malicious user from taking advantage of an unlocked computer or an abandoned logon session by bypassing the normal password prompt requirement.


Command:
```bash
 /usr/bin/sudo /usr/bin/sudo -V | /usr/bin/awk -F": " '/Type of authentication timestamp record/{print $2}'
```

Expected result: tty

## Rule: os_sudo_timeout_configure

### Severity: 

Explanation:
 The file /etc/sudoers _MUST_ include a timestamp_timout of $ODV.


Command:
```bash
 /usr/bin/sudo /usr/bin/sudo -V | /usr/bin/grep -c "Authentication timestamp timeout: 0.0 minutes"
```

Expected result: 1

## Rule: os_system_wide_applications_configure

### Severity: 

Explanation:
 Applications in the System Applications Directory (/Applications) _MUST_ not be world-writable.


Command:
```bash
 /usr/bin/find /Applications -iname "*\.app" -type d -perm -2 -ls | /usr/bin/wc -l | /usr/bin/xargs
```

Expected result: 0

## Rule: os_terminal_secure_keyboard_enable

### Severity: 

Explanation:
 Secure keyboard entry _MUST_ be enabled in Terminal.app. 


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.Terminal').objectForKey('SecureKeyboardEntry').js
EOS
```

Expected result: true

## Rule: os_time_offset_limit_configure

### Severity: 

Explanation:
 The macOS system time  _MUST_ be monitored to not drift more than four minutes and thirty seconds.


Command:
```bash
 /usr/bin/sntp $(/usr/sbin/systemsetup -getnetworktimeserver | /usr/bin/awk '{print $4}') | /usr/bin/awk -F'.' '/\+\/\-/{if (substr($1,2) >= 270) {print "No"} else {print "Yes"}}'
```

Expected result: Yes

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

## Rule: os_world_writable_library_folder_configure

### Severity: 

Explanation:
 Folders in /System/Volumes/Data/Library _MUST_ not be world-writable.
NOTE: Some vendors are known to create world-writable folders to the System Library folder. You may need to add more exclusions to this check and fix to match your environment.


Command:
```bash
 /usr/bin/find /System/Volumes/Data/Library -type d -perm -2 -ls | /usr/bin/grep -v Caches | /usr/bin/grep -v /Preferences/Audio/Data | /usr/bin/wc -l | /usr/bin/xargs
```

Expected result: 0

## Rule: os_world_writable_system_folder_configure

### Severity: 

Explanation:
 Folders in /System/Volumes/Data/System _MUST_ not be world-writable.


Command:
```bash
 /usr/bin/find /System/Volumes/Data/System -type d -perm -2 -ls | /usr/bin/grep -v "Drop Box" | /usr/bin/wc -l | /usr/bin/xargs
```

Expected result: 0

## Rule: pwpolicy_account_lockout_enforce

### Severity: medium

Explanation:
 The macOS _MUST_ be configured to limit the number of failed login attempts to a maximum of $ODV. When the maximum number of failed attempts is reached, the account _MUST_ be locked for a period of time after.
This rule protects against malicious users attempting to gain access to the system via brute-force hacking methods. 


Command:
```bash
 /usr/bin/pwpolicy -getaccountpolicies 2> /dev/null | /usr/bin/tail +2 | /usr/bin/xmllint --xpath '//dict/key[text()="policyAttributeMaximumFailedAuthentications"]/following-sibling::integer[1]/text()' - | /usr/bin/awk '{ if ($1 <= 5) {print "yes"} else {print "no"}}'
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

## Rule: pwpolicy_history_enforce

### Severity: medium

Explanation:
 The macOS _MUST_ be configured to enforce a password history of at least $ODV previous passwords when a password is created. 
This rule ensures that users are  not allowed to re-use a password that was used in any of the $ODV previous password generations. 
Limiting password reuse protects against malicious users attempting to gain access to the system via brute-force hacking methods.
NOTE: The guidance for password based authentication in NIST 800-53 (Rev 5) and NIST 800-63B state that complexity rules should be organizationally defined. The values defined are based off of common complexity values. But your organization may define its own password complexity rules.


Command:
```bash
 /usr/bin/pwpolicy -getaccountpolicies 2> /dev/null | /usr/bin/tail +2 | /usr/bin/xmllint --xpath '//dict/key[text()="policyAttributePasswordHistoryDepth"]/following-sibling::*[1]/text()' - | /usr/bin/awk '{ if ($1 >= 15 ) {print "yes"} else {print "no"}}'
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

Expected result: 365

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

## Rule: system_settings_airplay_receiver_disable

### Severity: 

Explanation:
 Airplay Receiver allows you to send content from another Apple device to be displayed on the screen as it's being played from your other device.  
Support for Airplay Receiver is non-essential and _MUST_ be disabled.
The information system _MUST_ be configured to provide only essential capabilities.


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess').objectForKey('allowAirPlayIncomingRequests').js
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

## Rule: system_settings_bluetooth_menu_enable

### Severity: 

Explanation:
 The bluetooth menu _MUST_ be enabled.


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.controlcenter').objectForKey('Bluetooth').js
EOS
```

Expected result: 18

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

## Rule: system_settings_critical_update_install_enforce

### Severity: 

Explanation:
 Ensure that security updates are installed as soon as they are available from Apple. 


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.SoftwareUpdate').objectForKey('CriticalUpdateInstall').js
EOS
```

Expected result: true

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

## Rule: system_settings_hot_corners_secure

### Severity: 

Explanation:
 Hot corners _MUST_ be secured. 
The information system conceals, via the session lock, information previously visible on the display with a publicly viewable image. Although hot comers can be used to initiate a session lock or to launch useful applications, they can also be configured to disable an automatic session lock from initiating. Such a configuration introduces the risk that a user might forget to manually lock the screen before stepping away from the computer.


Command:
```bash
 bl_corner="$(/usr/bin/defaults read /Users/"$CURRENT_USER"/Library/Preferences/com.apple.dock wvous-bl-corner 2>/dev/null)"
tl_corner="$(/usr/bin/defaults read /Users/"$CURRENT_USER"/Library/Preferences/com.apple.dock wvous-tl-corner 2>/dev/null)"
tr_corner="$(/usr/bin/defaults read /Users/"$CURRENT_USER"/Library/Preferences/com.apple.dock wvous-tr-corner 2>/dev/null)"
br_corner="$(/usr/bin/defaults read /Users/"$CURRENT_USER"/Library/Preferences/com.apple.dock wvous-br-corner 2>/dev/null)"

if [[ "$bl_corner" != "6" ]] && [[ "$tl_corner" != "6" ]] && [[ "$tr_corner" != "6" ]] && [[ "$br_corner" != "6" ]]; then
  echo "0"
fi
```

Expected result: 0

## Rule: system_settings_install_macos_updates_enforce

### Severity: 

Explanation:
 Software Update _MUST_ be configured to enforce automatic installation of macOS updates is enabled.


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.SoftwareUpdate').objectForKey('AutomaticallyInstallMacOSUpdates').js
EOS
```

Expected result: true

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

## Rule: system_settings_location_services_enable

### Severity: 

Explanation:
 Location Services _MUST_ be enabled.   


Command:
```bash
 /usr/bin/sudo -u _locationd /usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.locationd').objectForKey('LocationServicesEnabled').js
EOS
```

Expected result: true

## Rule: system_settings_location_services_menu_enforce

### Severity: 

Explanation:
 Location Services menu item _MUST_ be enabled.


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.locationmenu').objectForKey('ShowSystemServices').js
EOS
```

Expected result: true

## Rule: system_settings_loginwindow_loginwindowtext_enable

### Severity: 

Explanation:
 The login window _MUST_ be configured to show a custom access warning message. 


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.loginwindow').objectForKey('LoginwindowText').js
EOS
```

Expected result: Center for Internet Security Test Message

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

## Rule: system_settings_softwareupdate_current

### Severity: medium

Explanation:
 Make sure Software Update is updated and current.
NOTE: Automatic fix can cause unplanned restarts and may lose work.


Command:
```bash
 softwareupdate_date_epoch=$(/bin/date -j -f "%Y-%m-%d" "$(/usr/bin/defaults read /Library/Preferences/com.apple.SoftwareUpdate.plist LastFullSuccessfulDate | /usr/bin/awk '{print $1}')" "+%s")
thirty_days_epoch=$(/bin/date -v -30d "+%s")
if [[ $softwareupdate_date_epoch -lt $thirty_days_epoch ]]; then
  /bin/echo "0"
else
  /bin/echo "1"
fi
```

Expected result: 1

## Rule: system_settings_software_update_app_update_enforce

### Severity: 

Explanation:
 Software Update _MUST_ be configured to enforce automatic updates of App Updates is enabled.


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.SoftwareUpdate').objectForKey('AutomaticallyInstallAppUpdates').js
EOS
```

Expected result: true

## Rule: system_settings_software_update_download_enforce

### Severity: 

Explanation:
 Software Update _MUST_ be configured to enforce automatic downloads of updates is enabled.


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.SoftwareUpdate').objectForKey('AutomaticDownload').js
EOS
```

Expected result: true

## Rule: system_settings_software_update_enforce

### Severity: 

Explanation:
 Software Update _MUST_ be configured to enforce automatic update is enabled.


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.SoftwareUpdate').objectForKey('AutomaticCheckEnabled').js
EOS
```

Expected result: true

## Rule: system_settings_ssh_disable

### Severity: medium

Explanation:
 SSH service _MUST_ be disabled for remote access.
Remote access sessions _MUST_ use FIPS validated encrypted methods to protect unauthorized individuals from gaining access. 


Command:
```bash
 /bin/launchctl print-disabled system | /usr/bin/grep -c '"com.openssh.sshd" => disabled'
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

## Rule: system_settings_time_machine_auto_backup_enable

### Severity: 

Explanation:
 Automatic backups _MUST_ be enabled when using Time Machine. 


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.TimeMachine').objectForKey('AutoBackup').js
EOS
```

Expected result: true

## Rule: system_settings_time_machine_encrypted_configure

### Severity: 

Explanation:
 Time Machine volumes _MUST_ be encrypted. 


Command:
```bash
 error_count=0
for tm in $(/usr/bin/tmutil destinationinfo 2>/dev/null| /usr/bin/awk -F': ' '/Name/{print $2}'); do
  tmMounted=$(/usr/sbin/diskutil info "${tm}" 2>/dev/null | /usr/bin/awk '/Mounted/{print $2}')
  tmEncrypted=$(/usr/sbin/diskutil info "${tm}" 2>/dev/null | /usr/bin/awk '/FileVault/{print $2}')
  if [[ "$tmMounted" = "Yes" && "$tmEncrypted" = "No" ]]; then
      ((error_count++))
  fi
done
echo "$error_count"
```

Expected result: 0

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

Expected result: time.apple.com

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

## Rule: system_settings_wake_network_access_disable

### Severity: 

Explanation:
 Wake for network access _MUST_ be disabled.


Command:
```bash
 /usr/bin/pmset -g custom | /usr/bin/awk '/womp/ { sum+=$2 } END {print sum}'
```

Expected result: 0

## Rule: system_settings_wifi_menu_enable

### Severity: 

Explanation:
 The WiFi menu _MUST_ be enabled.


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.controlcenter').objectForKey('WiFi').js
EOS
```

Expected result: 18

