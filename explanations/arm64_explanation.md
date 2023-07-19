# Explanation of the rules for arm64

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

