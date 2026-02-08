import os
import json
import requests
import subprocess
import threading
import zipfile
from PIL import Image, ImageTk
from profiles import load_profiles, save_profile, delete_profile
import hashlib
from urllib.parse import urlparse
import ssl
import socket
from hashlib import sha256
from concurrent.futures import ThreadPoolExecutor
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from queue import Queue

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

MINECRAFT_DIR = os.path.join(SCRIPT_DIR, "clauncher")
VERSIONS_DIR = os.path.join(MINECRAFT_DIR, "versions")
LIBRARIES_DIR = os.path.join(MINECRAFT_DIR, "libraries")
NATIVES_DIR = os.path.join(MINECRAFT_DIR, "natives")
ASSETS_DIR = os.path.join(MINECRAFT_DIR, "assets")

trusted_domains = [
    "launchermeta.mojang.com",
    "resources.download.minecraft.net",
    "piston-meta.mojang.com",
    "piston-data.mojang.com"
]

# for easier code migration
# old code is in class so self doesnt need to be migrated
class CoreInstall:
    def __init__(self):
        os.makedirs(VERSIONS_DIR, exist_ok=True)
        os.makedirs(LIBRARIES_DIR, exist_ok=True)
        os.makedirs(NATIVES_DIR, exist_ok=True)
        os.makedirs(ASSETS_DIR, exist_ok=True)

        self.session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=10, pool_maxsize=10)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # todo: use logging module?
        self.log_queue = Queue()
        
        self.latest_release = self.fetch_latest_version()