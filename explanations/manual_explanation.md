# Explanation of the rules for manual

## Rule: os_certificate_authority_trust

### Severity: high

Explanation:
 The organization _MUST_ issue or obtain public key certificates from an organization-approved service provider and ensure only approved trust anchors are in the System Keychain.


Command:
```bash
 /usr/bin/security dump-keychain /Library/Keychains/System.keychain | /usr/bin/awk -F'"' '/labl/ {print $4}'
```

Expected result: alistcontainingapprovedrootcertificates

## Rule: os_ess_installed

### Severity: medium

Explanation:
 The approved ESS solution _MUST_ be installed and configured to run. 
The macOS system must employ automated mechanisms to determine the state of system components. The DoD requires the installation and use of an approved ESS solution to be implemented on the operating system. For additional information, reference all applicable ESS OPORDs and FRAGOs on SIPRNET.


Command:
```bash
 Ask the System Administrator (SA) or Information System Security Officer (ISSO) if the approved ESS solution is loaded on the system. 
If the installed components of the ESS solution are not at the DoD approved minimal versions, this is a finding.
```

Expected result: 

## Rule: os_filevault_authorized_users

### Severity: medium

Explanation:
 macOS _MUST_ be configured to only allow authorized users to unlock FileVault upon startup.


Command:
```bash
 /usr/bin/fdesetup list | /usr/bin/awk -F',' '{print $1}'
```

Expected result: alistcontainingauthorizedusersthatcanunlockFileVault

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

