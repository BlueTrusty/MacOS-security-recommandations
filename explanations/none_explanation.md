# Explanation of the rules for none

## Rule: audit_flags_fm_configure

### Severity: medium

Explanation:
 The audit system _MUST_ be configured to record enforcement actions of attempts to modify file attributes (fm). 
Enforcement actions are the methods or mechanisms used to prevent unauthorized changes to configuration settings. One common and effective enforcement action method is using access restrictions (i.e., modifications to a file by applying file permissions). 
This configuration ensures that audit lists include events in which enforcement actions attempts to modify a file. 
Without auditing the enforcement of access restrictions, it is difficult to identify attempted attacks, as there is no audit trail available for forensic investigation.


Command:
```bash
 /usr/bin/awk -F':' '/^flags/ { print $NF }' /etc/security/audit_control | /usr/bin/tr ',' '\n' | /usr/bin/grep -Ec '^fm'
```

Expected result: 1

## Rule: os_anti_virus_installed

### Severity: high

Explanation:
 An approved antivirus product _MUST_ be installed and configured to run.
Malicious software can establish a base on individual desktops and servers. Employing an automated mechanism to detect this type of software will aid in elimination of the software from the operating system.'


Command:
```bash
 /bin/launchctl list | /usr/bin/grep -cE "(com.apple.XprotectFramework.PluginService|com.apple.XProtect.daemon.scan)"
```

Expected result: 2

## Rule: os_blank_bluray_disable

### Severity: medium

Explanation:
 Blank Blu Ray media _MUST_ be disabled.
[IMPORTANT]
 ====
 Some organizations rely on the use of removable media for storing and sharing data. Information System Security Officers (ISSOs) may make the risk-based decision not to disable external hard drives to avoid losing this functionality, but they are advised to first fully weigh the potential risks posed to their organization.
 ====
[IMPORTANT]
 ====
 Apple has deprecated the use of media mount controls, using these controls may not work as expected. Third party software may be required to fullfill the compliance requirements.
 ====


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.systemuiserver').objectForKey('mount-controls'))["blankbd"]
EOS
```

Expected result: deny

## Rule: os_blank_cd_disable

### Severity: medium

Explanation:
 Blank CD media _MUST_ be disabled.
[IMPORTANT]
 ====
 Some organizations rely on the use of removable media for storing and sharing data. Information System Security Officers (ISSOs) may make the risk-based decision not to disable external hard drives to avoid losing this functionality, but they are advised to first fully weigh the potential risks posed to their organization.
 ====
[IMPORTANT]
 ====
 Apple has deprecated the use of media mount controls, using these controls may not work as expected. Third party software may be required to fullfill the compliance requirements.
 ====


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.systemuiserver').objectForKey('mount-controls'))["blankcd"]
EOS
```

Expected result: deny

## Rule: os_blank_dvd_disable

### Severity: medium

Explanation:
 Blank DVD media _MUST_ be disabled.
[IMPORTANT]
 ====
 Some organizations rely on the use of removable media for storing and sharing data. Information System Security Officers (ISSOs) may make the risk-based decision not to disable external hard drives to avoid losing this functionality, but they are advised to first fully weigh the potential risks posed to their organization.
 ====
[IMPORTANT]
 ====
 Apple has deprecated the use of media mount controls, using these controls may not work as expected. Third party software may be required to fullfill the compliance requirements.
 ====


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.systemuiserver').objectForKey('mount-controls'))["blankdvd"]
EOS
```

Expected result: deny

## Rule: os_bluray_read_only_enforce

### Severity: medium

Explanation:
 Blu Ray media _MUST_ be set to read only.
[IMPORTANT]
 ====
 Some organizations rely on the use of removable media for storing and sharing data. Information System Security Officers (ISSOs) may make the risk-based decision not to disable external hard drives to avoid losing this functionality, but they are advised to first fully weigh the potential risks posed to their organization.
 ====
[IMPORTANT]
 ====
 Apple has deprecated the use of media mount controls, using these controls may not work as expected. Third party software may be required to fullfill the compliance requirements.
 ====


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.systemuiserver').objectForKey('mount-controls'))["bd"]
EOS
```

Expected result: read-only

## Rule: os_burn_support_disable

### Severity: low

Explanation:
 Burn support _MUST_ be disabled.
[IMPORTANT]
 ====
 Some organizations rely on the use of removable media for storing and sharing data. Information System Security Officers (ISSOs) may make the risk-based decision not to disable external hard drives to avoid losing this functionality, but they are advised to first fully weigh the potential risks posed to their organization.
 ====


Command:
```bash
 /usr/bin/profiles -P -o stdout | /usr/bin/grep -Ec '(BurnSupport = off;|ProhibitBurn = 1;)'
```

Expected result: 2

## Rule: os_camera_disable

### Severity: medium

Explanation:
 macOS _MUST_ be configured to disable the camera.


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess').objectForKey('allowCamera').js
EOS
```

Expected result: false

## Rule: os_cd_read_only_enforce

### Severity: medium

Explanation:
 CD media _MUST_ be set to read only.
[IMPORTANT]
 ====
 Some organizations rely on the use of removable media for storing and sharing data. Information System Security Officers (ISSOs) may make the risk-based decision not to disable external hard drives to avoid losing this functionality, but they are advised to first fully weigh the potential risks posed to their organization.
 ====
[IMPORTANT]
 ====
 Apple has deprecated the use of media mount controls, using these controls may not work as expected. Third party software may be required to fullfill the compliance requirements.
 ====


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.systemuiserver').objectForKey('mount-controls'))["cd"]
EOS
```

Expected result: read-only

## Rule: os_disk_image_disable

### Severity: medium

Explanation:
 Disk images _MUST_ be disabled.
[IMPORTANT]
 ====
 Some organizations rely on the use of removable media for storing and sharing data. Information System Security Officers (ISSOs) may make the risk-based decision not to disable external hard drives to avoid losing this functionality, but they are advised to first fully weigh the potential risks posed to their organization.
 ====
[IMPORTANT]
 ====
 Apple has deprecated the use of media mount controls, using these controls may not work as expected. Third party software may be required to fullfill the compliance requirements.
 ====


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.systemuiserver').objectForKey('mount-controls'))["disk-image"]
EOS
```

Expected result: deny

## Rule: os_dvdram_disable

### Severity: medium

Explanation:
 DVD-RAM media _MUST_ be disabled.
[IMPORTANT]
 ====
 Some organizations rely on the use of removable media for storing and sharing data. Information System Security Officers (ISSOs) may make the risk-based decision not to disable external hard drives to avoid losing this functionality, but they are advised to first fully weigh the potential risks posed to their organization.
 ====
[IMPORTANT]
 ====
 Apple has deprecated the use of media mount controls, using these controls may not work as expected. Third party software may be required to fullfill the compliance requirements.
 ====


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.systemuiserver').objectForKey('mount-controls'))["dvdram"]
EOS
```

Expected result: deny

## Rule: os_erase_content_and_settings_disable

### Severity: medium

Explanation:
 Erase Content and Settings _MUST_ be disabled.


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess').objectForKey('allowEraseContentAndSettings').js
EOS
```

Expected result: false

## Rule: os_power_nap_enable

### Severity: 

Explanation:
 Power Nap _MUST_ be enabled.
NOTE: Power nap can interfere with USB power and may cause devices such as smartcards to stop functioning until a reboot. 
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

Expected result: 1

## Rule: os_removable_media_disable

### Severity: medium

Explanation:
 Removable media, such as USB connected external hard drives, thumb drives, and optical media, _MUST_ be disabled for users.
Disabling removable storage devices reduces the risks and known vulnerabilities of such devices (e.g., malicious code insertion)
[IMPORTANT]
 ====
 Some organizations rely on the use of removable media for storing and sharing data. Information System Security Officers (ISSOs) may make the risk-based decision not to disable external hard drives to avoid losing this functionality, but they are advised to first fully weigh the potential risks posed to their organization.
 ====
[IMPORTANT]
 ====
 Apple has deprecated the use of media mount controls, using these controls may not work as expected. Third party software may be required to fullfill the compliance requirements.
 ====


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.systemuiserver').objectForKey('mount-controls'))["harddisk-external"]
EOS
```

Expected result: deny

## Rule: os_skip_screen_time_prompt_enable

### Severity: low

Explanation:
 The prompt for Screen Time setup during Setup Assistant _MUST_ be disabled.

Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
$.NSUserDefaults.alloc.initWithSuiteName('com.apple.SetupAssistant.managed').objectForKey('SkipScreenTime').js
EOS
```

Expected result: true

## Rule: os_sshd_fips_140_ciphers

### Severity: medium

Explanation:
 If SSHD is enabled then it _MUST_ be configured to limit the ciphers to algorithms that are FIPS 140 validated.
FIPS 140-2 is the current standard for validating that mechanisms used to access cryptographic modules utilize authentication that meet federal requirements.
Operating systems utilizing encryption _MUST_ use FIPS validated mechanisms for authenticating to cryptographic modules. 
NOTE: /etc/ssh/sshd_config will be automatically modified to its original state following any update or major upgrade to the operating system.


Command:
```bash
 /usr/sbin/sshd -T | /usr/bin/grep -ci "^Ciphers aes256-ctr,aes192-ctr,aes128-ctr"
```

Expected result: 1

## Rule: os_sshd_fips_140_macs

### Severity: medium

Explanation:
 If SSHD is enabled then it _MUST_ be configured to limit the Message Authentication Codes (MACs) to algorithms that are FIPS 140 validated.
FIPS 140-2 is the current standard for validating that mechanisms used to access cryptographic modules utilize authentication that meets federal requirements.
Operating systems utilizing encryption _MUST_ use FIPS validated mechanisms for authenticating to cryptographic modules. 
NOTE: /etc/ssh/sshd_config will be automatically modified to its original state following any update or major upgrade to the operating system.


Command:
```bash
 /usr/sbin/sshd -T | /usr/bin/grep -ci "^MACs hmac-sha2-256,hmac-sha2-512"
```

Expected result: 1

## Rule: os_sshd_key_exchange_algorithm_configure

### Severity: medium

Explanation:
 Unapproved mechanisms for authentication to the cryptographic module are not verified, and therefore cannot be relied upon to provide confidentiality or integrity, resulting in the compromise of DoD data.
Operating systems using encryption are required to use FIPS-compliant mechanisms for authenticating to cryptographic modules.
The implementation of OpenSSH that is included with macOS does not utilize a FIPS 140-2 validated cryptographic module. While the listed Key Exchange Algorithms are FIPS 140-2 approved, the module implementing them has not been validated.
By specifying a Key Exchange Algorithm list with the order of hashes being in a "strongest to weakest" orientation, the system will automatically attempt to use the strongest Key Exchange Algorithm for securing SSH connections.
NOTE: /etc/ssh/sshd_config will be automatically modified to its original state following any update or major upgrade to the operating system.


Command:
```bash
 /usr/sbin/sshd -T | /usr/bin/grep -ci "^KexAlgorithms diffie-hellman-group-exchange-sha256"
```

Expected result: 1

## Rule: os_sshd_login_grace_time_configure

### Severity: medium

Explanation:
 If SSHD is enabled then it _MUST_ be configured to wait only $ODV seconds before timing out logon attempts.
NOTE: /etc/ssh/sshd_config will be automatically modified to its original state following any update or major upgrade to the operating system.


Command:
```bash
 /usr/sbin/sshd -T | /usr/bin/awk '/logingracetime/{print $2}'
```

Expected result: 30

## Rule: os_user_app_installation_prohibit

### Severity: medium

Explanation:
 Users _MUST_ not be allowed to install software into /Users/. 
Allowing regular users to install software, without explicit privileges, presents the risk of untested and potentially malicious software being installed on the system. Explicit privileges (escalated or administrative privileges) provide the regular user with explicit capabilities and control that exceeds the rights of a regular user.


Command:
```bash
 /usr/bin/osascript -l JavaScript << EOS
function run() {
  let pref1 = ObjC.unwrap($.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess.new')  .objectForKey('familyControlsEnabled'))
  let pathlist = $.NSUserDefaults.alloc.initWithSuiteName('com.apple.applicationaccess.new')  .objectForKey('pathBlackList').js
  for ( let app in pathlist ) {
      if ( ObjC.unwrap(pathlist[app]) == "/Users/" && pref1 == true ){
          return("true")
      }
  }
  return("false")
  }
EOS
```

Expected result: true

