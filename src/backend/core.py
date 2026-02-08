import os
import json
import requests
import subprocess
import threading
import zipfile
import hashlib
from urllib.parse import urlparse
import ssl
import socket
from hashlib import sha256
from concurrent.futures import ThreadPoolExecutor
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from queue import Queue
from .profiles import load_profiles, save_profile, delete_profile

# Get the directory of the current script
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

class MinecraftCore:
    def __init__(self, log_queue):
        # Create a requests session with connection pooling and retries
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
        
        # Queue for thread-safe log messages
        self.log_queue = log_queue

    def core_make_dirs(self):
        os.makedirs(VERSIONS_DIR, exist_ok=True)
        os.makedirs(LIBRARIES_DIR, exist_ok=True)
        os.makedirs(NATIVES_DIR, exist_ok=True)
        os.makedirs(ASSETS_DIR, exist_ok=True)

    def is_trusted_url(self, url, trusted_domains):
        """Check if the URL belongs to a trusted domain."""
        parsed_url = urlparse(url)
        if parsed_url.netloc not in trusted_domains:
            if parsed_url.netloc.endswith(".mojang.com") or parsed_url.netloc.endswith(".minecraft.net"):
                return True
        return parsed_url.netloc in trusted_domains

    def verify_tls_certificate(self, url, expected_fingerprint):
        """Verify the TLS certificate fingerprint of the server."""
        parsed_url = urlparse(url)
        hostname = parsed_url.netloc

        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
                actual_fingerprint = sha256(der_cert).hexdigest()

                if actual_fingerprint.lower() != expected_fingerprint.lower():
                    raise ssl.SSLError("TLS certificate fingerprint mismatch!")

    def fetch_latest_version(self):
        """Fetch the latest Minecraft release version"""
        url = "https://launchermeta.mojang.com/mc/game/version_manifest.json"
        hostname = 'launchermeta.mojang.com'
        port = 443

        # Connect and get the certificate
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)

        # Calculate SHA-256 fingerprint
        fingerprint = hashlib.sha256(der_cert).hexdigest()
        formatted_fingerprint = ''.join(fingerprint[i:i+2].upper() for i in range(0, len(fingerprint), 2))

        if not self.is_trusted_url(url, trusted_domains):
            raise ValueError("Untrusted URL detected: " + url)

        self.verify_tls_certificate(url, formatted_fingerprint)

        response = requests.get(url).json()
        for version in response["versions"]:
            if version["type"] == "release":
                return version["id"]
        return "1.21.4"  

    def get_all_versions(self):
        """Fetch all Minecraft versions"""
        url = "https://launchermeta.mojang.com/mc/game/version_manifest.json"

        if not self.is_trusted_url(url, trusted_domains):
            raise ValueError("Untrusted URL detected: " + url)

        response = requests.get(url).json()
        return [version["id"] for version in response["versions"]]

    def download_version_json(self, version):
        """Download the version JSON file"""
        url = "https://launchermeta.mojang.com/mc/game/version_manifest.json"

        if not self.is_trusted_url(url, trusted_domains):
            raise ValueError("Untrusted URL detected: " + url)

        response = requests.get(url).json()

        for v in response["versions"]:
            if v["id"] == version:
                version_json_url = v["url"]

                if not self.is_trusted_url(version_json_url, trusted_domains):
                    raise ValueError("Untrusted URL detected: " + version_json_url)

                json_data = requests.get(version_json_url).json()

                version_folder = os.path.join(VERSIONS_DIR, version)
                os.makedirs(version_folder, exist_ok=True)

                json_path = os.path.join(version_folder, f"{version}.json")

                with open(json_path, "w") as file:
                    json.dump(json_data, file, indent=4)

                self.log_queue.put(f"{version}.json downloaded!\n")
                return json_data

        return None

    def verify_file_hash(self, file_path, expected_hash, hash_algorithm="sha256"):
        """Verify the hash of a file using the specified algorithm."""
        hash_func = hashlib.new(hash_algorithm)
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_func.update(chunk)
        return hash_func.hexdigest() == expected_hash

    def download_minecraft_jar(self, version):
        """Download the Minecraft client JAR file"""
        json_data = self.download_version_json(version)

        jar_url = json_data["downloads"]["client"]["url"]
        expected_hash = json_data["downloads"]["client"]["sha1"]
        jar_path = os.path.join(VERSIONS_DIR, version, f"{version}.jar")

        if not self.is_trusted_url(jar_url, trusted_domains):
            raise ValueError("Untrusted URL detected: " + jar_url)

        # Limit download size
        response = requests.get(jar_url, stream=True)
        max_size = 50 * 1024 * 1024  # 50 MB
        size = 0

        if not os.path.exists(jar_path):
            with open(jar_path, "wb") as file:
                for chunk in response.iter_content(chunk_size=65536):
                    size += len(chunk)
                    if size > max_size:
                        raise ValueError("File exceeds maximum allowed size.")
                    file.write(chunk)
            
            if not self.verify_file_hash(jar_path, expected_hash, "sha1"):
                os.remove(jar_path)
                raise ValueError("Hash mismatch for downloaded JAR file.")

            self.log_queue.put(f"{version}.jar downloaded!\n")

        return jar_path, json_data

    def _download_file(self, url, file_path, expected_hash=None, hash_type="sha256"):
        """Helper method to download a single file with hash verification"""
        if os.path.exists(file_path):
            return True
        
        if not self.is_trusted_url(url, ["launchermeta.mojang.com", "resources.download.minecraft.net"]):
            raise ValueError("Untrusted URL detected: " + url)
        
        try:
            response = self.session.get(url, stream=True, timeout=30)
            response.raise_for_status()
            
            with open(file_path, "wb") as file:
                for chunk in response.iter_content(chunk_size=65536):
                    if chunk:
                        file.write(chunk)
            
            response.close()
            
            if expected_hash and not self.verify_file_hash(file_path, expected_hash, hash_type):
                os.remove(file_path)
                raise ValueError(f"Hash mismatch for file: {file_path}")
            self.log_queue.put(f"Downloaded: {file_path}\n")
            return True
        except Exception as e:
            if os.path.exists(file_path):
                os.remove(file_path)
            raise e

    def download_libraries(self, version_json):
        """Download missing Minecraft libraries and native libraries with multithreading"""
        download_tasks = []
        
        for lib in version_json["libraries"]:
            if "downloads" in lib:
                if "artifact" in lib["downloads"]:
                    artifact = lib["downloads"]["artifact"]
                    url = artifact["url"]
                    expected_hash = artifact.get("sha256")
                    lib_path = os.path.join(LIBRARIES_DIR, os.path.basename(url))
                    
                    if not os.path.exists(lib_path):
                        download_tasks.append((url, lib_path, expected_hash, "sha256"))

                if "classifiers" in lib["downloads"]:
                    for classifier, classifier_info in lib["downloads"]["classifiers"].items():
                        if "natives-windows" in classifier:
                            url = classifier_info["url"]
                            expected_hash = classifier_info.get("sha256")
                            native_path = os.path.join(NATIVES_DIR, os.path.basename(url))
                            
                            if not os.path.exists(native_path):
                                download_tasks.append((url, native_path, expected_hash, "sha256"))

        # Download files concurrently using ThreadPoolExecutor
        if download_tasks:
            with ThreadPoolExecutor(max_workers=4) as executor:
                futures = [
                    executor.submit(self._download_file, url, file_path, expected_hash, hash_type)
                    for url, file_path, expected_hash, hash_type in download_tasks
                ]
                
                for future in futures:
                    try:
                        future.result()
                    except Exception as e:
                        self.log_queue.put(f"Error downloading library: {str(e)}\n")
                        raise ValueError(f"Failed to download library: {str(e)}")

    def extract_native_library(self, native_path):
        """Extract native libraries safely."""
        with zipfile.ZipFile(native_path, 'r') as zip_ref:
            for member in zip_ref.namelist():
                member_path = os.path.abspath(os.path.join(NATIVES_DIR, member))
                if not member_path.startswith(NATIVES_DIR):
                    raise ValueError("Unsafe path detected in ZIP file.")
                zip_ref.extract(member, NATIVES_DIR)

    def download_assets(self, version_json):
        """Download missing assets with multithreading"""
        asset_index = version_json["assetIndex"]
        asset_index_path = os.path.join(ASSETS_DIR, "indexes", f"{asset_index['id']}.json")

        # Download asset index if it doesn't exist
        if not os.path.exists(asset_index_path):
            os.makedirs(os.path.dirname(asset_index_path), exist_ok=True)
            response = self.session.get(asset_index["url"], timeout=30)
            with open(asset_index_path, "wb") as file:
                file.write(response.content)
            response.close()
            self.log_queue.put(f"Downloaded asset index: {asset_index_path}\n")

        # Load asset index
        with open(asset_index_path, "r") as file:
            asset_index_data = json.load(file)

        objects_dir = os.path.join(ASSETS_DIR, "objects")
        
        # Prepare download tasks for assets
        download_tasks = []
        for asset_name, asset_info in asset_index_data["objects"].items():
            hash = asset_info["hash"]
            sub_dir = hash[:2]
            asset_dir_path = os.path.join(objects_dir, sub_dir)
            os.makedirs(asset_dir_path, exist_ok=True)
            asset_path = os.path.join(objects_dir, sub_dir, hash)
            self.log_queue.put(f"Preparing asset: {asset_name} at {asset_path}\n")

            if not os.path.exists(asset_path):
                url = f"https://resources.download.minecraft.net/{sub_dir}/{hash}"
                download_tasks.append((url, asset_path, hash, "sha1"))

        # Download assets concurrently using ThreadPoolExecutor
        if download_tasks:
            with ThreadPoolExecutor(max_workers=4) as executor:
                futures = [
                    executor.submit(self._download_file, url, file_path, expected_hash, hash_type)
                    for url, file_path, expected_hash, hash_type in download_tasks
                ]
                
                for future in futures:
                    try:
                        future.result()
                    except Exception as e:
                        self.log_queue.put(f"Error downloading asset: {str(e)}\n")
                        raise ValueError(f"Failed to download asset: {str(e)}")

    def launch_minecraft(self, version, username, json_path, jar_path, version_json):
        """Launch Minecraft with the given parameters"""
        custom_game_dir = MINECRAFT_DIR
        native_lib_path = NATIVES_DIR

        java_command = [
            "java",
            "-Xmx2G",  
            "-Xms1G",  
            f"-Djava.library.path={native_lib_path}",
            "-cp", f"{LIBRARIES_DIR}/*;{jar_path}",
            version_json["mainClass"],
            "--username", username,  
            "--version", version,
            "--gameDir", custom_game_dir,  
            "--assetsDir", ASSETS_DIR,
            "--assetIndex", version_json["assetIndex"]["id"],
            "--accessToken", "null",  
            "--uuid", "00000000-0000-0000-0000-000000000000",  
            "--userType", "legacy"  
        ]

        process = subprocess.Popen(java_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return process