# Explanation of the rules for permanent

## Rule: audit_alert_processing_fail

### Severity: 

Explanation:
 It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without this notification, the security personnel may be unaware of an impending failure of the audit capability, and system operation may be adversely affected. Audit processing failures include software/hardware errors, failures in the audit capturing mechanisms, and audit storage capacity being reached or exceeded. This requirement applies to each audit data storage repository (i.e., distinct information system component where audit records are stored), the centralized audit storage capacity of organizations (i.e., all audit data storage repositories combined), or both.


Command:
```bash
 The technology does not support this requirement. This is an applicable-does not meet finding.
```

Expected result: 

## Rule: audit_enforce_dual_auth

### Severity: 

Explanation:
 All bulk manipulation of audit information should be authorized via automatic processes, and any manual manipulation of audit information should require dual authorization. In addition, dual authorization mechanisms should require the approval of two authorized individuals before being executed.
An authorized user may intentionally or accidentally move or delete audit records without those specific actions being authorized, which would result in the loss of information that could, in the future, be critical for forensic investigation.
To enforce dual authorization before audit information can be moved or deleted, many operating systems can be integrated with enterprise-level auditing mechanisms that meet or exceed this requirement. 


Command:
```bash
 The technology does not support this requirement. This is an applicable-does not meet finding.
```

Expected result: 

## Rule: audit_off_load_records

### Severity: 

Explanation:
 Audit records should be off-loaded onto a different system or media from the system being audited.
Information stored in only one location is vulnerable to accidental or incidental deletion or alteration. Off-loading is a common process in information systems with limited audit storage capacity. 
To secure audit records by off-loading, many operating systems can be integrated with enterprise-level auditing mechanisms that meet or exceed this requirement. 


Command:
```bash
 The technology does not support this requirement. This is an applicable-does not meet finding.
```

Expected result: 

## Rule: audit_records_processing

### Severity: 

Explanation:
 The macOS should be configured to provide and implement the capability to process, sort, and search audit records for events of interest based on organizationally defined fields.
Events of interest can be identified by the content of audit records, including system resources involved, information objects accessed, identities of individuals, event types, event locations, event dates and times, Internet Protocol addresses involved, or event success or failure. Organizations may define event criteria to any degree of granularity required, such as locations selectable by a general networking location or by specific system component.


Command:
```bash
 The technology does not support this requirement. This is an applicable-does not meet finding.
```

Expected result: 

## Rule: os_auth_peripherals

### Severity: 

Explanation:
 Organizational devices requiring unique device-to-device identification and authentication may be defined by type, by device, or by a combination of type/device. Information systems typically use either shared known information (e.g., Media Access Control [MAC] or Transmission Control Protocol/Internet Protocol [TCP/IP] addresses) for device identification or organizational authentication solutions (e.g., IEEE 802.1x and Extensible Authentication Protocol [EAP], Radius server with EAP-Transport Layer Security [TLS] authentication, Kerberos) to identify/authenticate devices on local and/or wide area networks. Organizations determine the required strength of authentication mechanisms by the security categories of information systems. Because of the challenges of applying this control on large scale, organizations are encouraged to only apply the control to those limited number (and type) of devices that truly need to support this capability.


Command:
```bash
 The technology does support this requirement, however, third party solutions are required to implement at an infrastructure level.
```

Expected result: 

## Rule: os_continuous_monitoring

### Severity: 

Explanation:
 The macOS system _MUST_ be configured to determine the state of system components with regard to flaw remediation.


Command:
```bash
 The technology does not support this requirement. This is an applicable-does not meet finding.
```

Expected result: 

## Rule: os_limit_dos_attacks

### Severity: 

Explanation:
 The macOS should be configured to limit the impact of Denial of Service (DoS) attacks. 
DoS attacks leave authorized users unable to access information systems, devices, or other network resources due to the actions of a malicious cyber threat actor. When this occurs, the organization must operate at degraded capacity; often resulting in an inability to accomplish its mission. 
To limit the impact of DoS attacks, organizations may choose to employ increased capacity and service redundancy, which has the potential to reduce systems' susceptibility to some DoS attacks. Managing excess capacity may include, for example, establishing selected usage priorities, quotas, or partitioning. Many operating systems can be integrated with enterprise-level firewalls and networking equipment that meet or exceed this requirement.


Command:
```bash
 The technology does not support this requirement. This is an applicable-does not meet finding.
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

## Rule: os_notify_unauthorized_baseline_change

### Severity: 

Explanation:
 The macOS should be configured to automatically notify system administrators, Information System Security Officers (ISSOs), and (IMOs) when baseline configurations are modified.
Unauthorized changes to the baseline configuration could make the system vulnerable to various attacks or allow unauthorized access to the operating system. Changes to operating system configurations can have unintended side effects, some of which may  present security threats. Detecting such changes and providing an automated response can help avoid unintended, negative consequences that could ultimately affect the state of the operating system. 
To enable notifications and audit logging of changes made to baseline configurations, many operating systems can be integrated with enterprise-level auditing mechanisms that meet or exceed this requirement. 


Command:
```bash
 The technology does not support this requirement. This is an applicable-does not meet finding.
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

## Rule: os_reauth_devices_change_authenticators

### Severity: 

Explanation:
 The macOS should be configured to require users to reauthenticate when the device authenticator is changed. 
Without reauthentication, users may access resources or perform tasks for which they are not authorization. When operating systems provide the capability to change device authenticators, it is critical the device reauthenticate.


Command:
```bash
 The technology does not support this requirement. This is an applicable-does not meet finding.
```

Expected result: 

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

## Rule: pwpolicy_prevent_dictionary_words

### Severity: 

Explanation:
 The macOS should be configured to forbid users to use dictionary words for passwords. 
If the operating system allows users to select passwords based on dictionary words, this increases the window of opportunity for a malicious user to guess the password. 
To prevent users from using dictionary words for passwords, many operating systems can be integrated with an enterprise-level directory service that meets or exceeds this requirement.


Command:
```bash
 For systems not requiring mandatory smart card authentication or those that are not bound to a directory, the technology does not support this requirement. This is an applicable-does not meet finding.
```

Expected result: 

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

