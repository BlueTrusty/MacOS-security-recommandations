# Explanation of the rules for i386

## Rule: os_efi_integrity_validated

### Severity: 

Explanation:
 The macOS Extensible Firmware Interface (EFI) _MUST_ be checked to ensure it is a known good version from Apple.


Command:
```bash
 if /usr/sbin/ioreg -w 0 -c AppleSEPManager | /usr/bin/grep -q AppleSEPManager; then echo "1"; else /usr/libexec/firmwarecheckers/eficheck/eficheck --integrity-check | /usr/bin/grep -c "No changes detected"; fi
```

Expected result: 1

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

