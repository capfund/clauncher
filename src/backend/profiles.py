import os
import json, requests
import re

# Get the directory of the current script
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

PROFILES_DIR = os.path.join(SCRIPT_DIR, "clauncher", "profiles")
os.makedirs(PROFILES_DIR, exist_ok=True)

DEFAULT_PROFILE = {
    "name": "Latest Release",
    "version": "1.21.11",
    "type": "release",
    "icon": "grass_block"
}

def sanitize_filename(filename):
    """Remove unsafe characters from filenames."""
    return re.sub(r'[^a-zA-Z0-9_-]', '_', filename)

def load_profiles():
    if not os.listdir(PROFILES_DIR):
        # Create default profile if no profiles exist
        save_profile(DEFAULT_PROFILE)
        return [DEFAULT_PROFILE]
    
    profiles = []
    for profile_file in os.listdir(PROFILES_DIR):
        if profile_file.endswith(".json"):
            with open(os.path.join(PROFILES_DIR, profile_file), "r") as file:
                profiles.append(json.load(file))
    return profiles

def save_profile(profile):
    profile_path = os.path.join(PROFILES_DIR, f"{sanitize_filename(profile['name'])}.json")
    with open(profile_path, "w") as file:
        json.dump(profile, file, indent=4)

def delete_profile(profile_name):
    profile_path = os.path.join(PROFILES_DIR, f"{sanitize_filename(profile_name)}.json")
    if os.path.exists(profile_path):
        os.remove(profile_path)