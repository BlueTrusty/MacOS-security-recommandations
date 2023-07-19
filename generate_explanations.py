import os
import yaml
import pickle

# Define the directory to search for YAML files
NIST_YAML_RULES_DIRECTORY = "./rules_main"

def get_guidance_choices():
    """
    Get the guidance choices from the YAML files in the directory and subdirectories
    """
    guidance_choices = []
    # Iterate through all YAML files in the directory and subdirectories
    for root, dirs, files in os.walk(NIST_YAML_RULES_DIRECTORY):
        for file in files:
            if file.endswith(".yaml"):
                # Open the YAML file and load its contents
                with open(os.path.join(root, file), 'r') as yaml_file:
                    yaml_data = yaml.safe_load(yaml_file)
                    for tag in yaml_data.get("tags", []):
                        if tag not in guidance_choices:
                            guidance_choices.append(tag)

    return guidance_choices

def extract_rules_yaml_to_pkl(guidance_choice):
    """
    Extract the rules from the YAML files in the directory and subdirectories
    and write them to a pkl file
    """
    rules = []
    # Iterate through all YAML files in the directory and subdirectories
    for root, dirs, files in os.walk(NIST_YAML_RULES_DIRECTORY):
        for file in files:
            if file.endswith(".yaml"):
                # Open the YAML file and load its contents
                with open(os.path.join(root, file), 'r') as yaml_file:
                    yaml_data = yaml.safe_load(yaml_file)
                    if any(tag==guidance_choice for tag in yaml_data.get("tags", [])):

                        # Extract the relevant data from the YAML file
                        rule = str(yaml_data.get('id', ''))
                        severity = str(yaml_data.get('severity', ''))
                        command = str(yaml_data.get('check', '')).replace('\\\n', '') # replace '\' to nothing from the command if it is at the end of a line
                        try:   
                            expected_result = str(yaml_data.get('result', '')).split(':')[1].split("}")[0].replace(' ', '').replace('\'', '') # remove the "{type: ", the "''" and the "}" from the expected result
                        except:
                            expected_result = ''
                        discussion = str(yaml_data.get('discussion', '')).replace('\n', '\\ ').strip() # make the discussion one line and remove the leading and trailing spaces
                        
                        if 'odv' in yaml_data:
                            try:
                                odv = str(yaml_data['odv'][guidance_choice])
                                command = command.replace('$ODV', odv)
                                expected_result = expected_result.replace('$ODV', odv)
                            except:
                                odv = str(yaml_data['odv']['recommended'])
                                command = command.replace('$ODV', odv)
                                expected_result = expected_result.replace('$ODV', odv)
                        
                        # Write the extracted data to the dictionary
                        rules.append({'rule': rule, 'severity': severity, 'command': command, 'expected_result': expected_result, 'discussion': discussion})


    # Define the pkl file to write to
    pkl_file = "./rules/" + guidance_choice + "_rules.pkl"

    # Write the dictionary to the pkl file

    with open(pkl_file, mode='wb') as pklfile:
        pickle.dump(rules, pklfile)

    return rules


def generate_rule_explanations_md(guidance_choice):
    """
    Generate the md file with the rule explanations
    """
    # Define the pkl file to read from
    pkl_file = "./rules/" + guidance_choice + "_rules.pkl"

    # Define the md file to write to
    md_file = "./explanations/" + guidance_choice + "_explanation.md"

    # Read the dictionary from the pkl file
    with open(pkl_file, mode='rb') as pklfile:
        rules = pickle.load(pklfile)


    # Generate the md file
    with open(md_file, 'w') as f:
        f.write('# Explanation of the rules for ' + guidance_choice + '\n\n')

        for rule in rules:
            f.write('## Rule: {}\n\n'.format(rule['rule']))
            f.write('### Severity: {}\n\n'.format(rule['severity']))
            f.write('Explanation:\n {}\n\n'.format(rule['discussion'].replace('\\ \\ ', '\n').replace('\\', '\n')))
            f.write('Command:\n```bash\n {}```\n\n'.format(rule['command']))
            f.write('Expected result: {}\n\n'.format(rule['expected_result']))

    return 0


if __name__ == '__main__':
    print("Gathering guidance choices...")
    guidance_choices = get_guidance_choices()
    print("Guidance choices gathered.")

    print("Extracting rules from YAML files and writing them to pkl files...")

    for guidance_choice in guidance_choices:
        extract_rules_yaml_to_pkl(guidance_choice)
        print("Rules extracted for {}.".format(guidance_choice))
        generate_rule_explanations_md(guidance_choice)
        print("Explanations generated for {}.".format(guidance_choice))

    print("Done.")
                        