import requests
import json
import os
import yaml
from datetime import datetime

def fetch_lolbas_data(url):
    """Fetches LOLBAS data from the given URL."""
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"❌ Error fetching LOLBAS data: {e}")
        return None

def load_blacklist(filename="prefetch_blacklist.txt"):
    """Loads executables from the blacklist file."""
    blacklist = set()
    if os.path.exists(filename):
        with open(filename, "r") as f:
            for line in f:
                blacklist.add(line.strip().lower())
    return blacklist

def generate_sigma_rule(lolbas_entry, blacklist):
    """Generates a Sigma rule for a given LOLBAS entry, focusing on prefetch."""
    name = lolbas_entry.get("Name")
    description = lolbas_entry.get("Description")
    mitre_id = lolbas_entry.get("Commands", [{}])[0].get("MitreID")

    if not name:
        return None

    if name.lower() in blacklist:
        return None

    rule_title = f"Prefetch - Suspicious {name} Execution"
    rule_description = f"Detects suspicious execution of {name} based on prefetch data. {description}."
    rule_tags = ["attack.lolbas"]

    if mitre_id:
        rule_tags.append(f"attack.{mitre_id.lower()}")

    sigma_rule = {
        "title": rule_title,
        "description": rule_description,
        "status": "experimental",
        "logsource": {
            "product": "velociraptor",
            "category": "execution",
            "service": "prefetch"
        },
        "detection": {
            "selection": {
                "Executable": name.upper(),
            },
            "condition": "selection"
        },
        "level": "medium",
        "tags": rule_tags,
        "references": [
            "https://lolbas-project.github.io/"
        ],
        "author": "ilo",
        "date": datetime.now().strftime("%Y/%m/%d")
    }

    return sigma_rule

def save_sigma_rule(rule, filename):
    """Saves a Sigma rule to a YAML file."""
    try:
        with open(filename, "w") as f:
            yaml.dump(rule, f, sort_keys=False)
        print(f"✅ Sigma rule saved to {filename}")
    except Exception as e:
        print(f"❌ Error saving Sigma rule to {filename}: {e}")

def main():
    """Main function to fetch LOLBAS data and generate Sigma rules."""
    lolbas_url = "https://lolbas-project.github.io/api/lolbas.json"
    lolbas_data = fetch_lolbas_data(lolbas_url)

    if lolbas_data:
        output_dir = "../execution/prefetch"
        os.makedirs(output_dir, exist_ok=True)

        blacklist = load_blacklist()

        for entry in lolbas_data:
            sigma_rule = generate_sigma_rule(entry, blacklist)
            if sigma_rule:
                filename = os.path.join(output_dir, f"detect_lolbas_{entry['Name'].lower()}.yml")
                save_sigma_rule(sigma_rule, filename)

if __name__ == "__main__":
    main()
