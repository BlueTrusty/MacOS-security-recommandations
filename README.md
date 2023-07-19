# MacOS-security-recommandations

This repository provides a collection of security recommendations and guidelines for macOS systems. It includes YAML files obtained from [the macOS Security Compliance Project](https://github.com/usnistgov/macos_security), a notable resource in the field of macOS security.

## Directory Structure

### rules_main Directory

The rules_main directory houses YAML files obtained from the macOS Security Compliance Project. These files contain essential security rules and configurations for macOS systems based on different recommandation choices.

### explanations Directory

The explanations directory contains Markdown files that have been generated using the generate_explanations.py script. Each Markdown file is dedicated to providing detailed explanations for a specific policy choice related to macOS security. The structure of each explanation file is as follows:

``` md
## Rule: name_of_the_rule

### Severity: severity_of_the_rule

Explanation:
Explanation of the rule.


Command: command_to_check_the_rule

Expected result: expected_result_of_the_command
```	

## Disclaimer

The rules_main directory may not be up-to-date with the latest version of the macOS Security Compliance Project. Do not hesitate to download the latest version of the macOS Security Compliance Project and extract the rules explanations using the generate_explanations.py script.