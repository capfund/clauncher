import os
import json
import requests
import subprocess
import threading
import zipfile
import customtkinter as ctk
from customtkinter import CTkImage, CTkLabel
from tkinter import ttk, Listbox, simpledialog, PhotoImage
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

os.makedirs(VERSIONS_DIR, exist_ok=True)
os.makedirs(LIBRARIES_DIR, exist_ok=True)
os.makedirs(NATIVES_DIR, exist_ok=True)
os.makedirs(ASSETS_DIR, exist_ok=True)

class MinecraftLauncher(ctk.CTk):
    def __init__(self):
        super().__init__()
        
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
        self.log_queue = Queue()
        
        self.latest_release = self.fetch_latest_version()
        self.title("CLauncher")
        self.geometry("550x550")  # Increased height to 700px
        self.resizable(True, True)

        # Configure styles
        self.configure(fg_color=("white", "#1a1a1a"))
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        # Main container
        self.main_frame = ctk.CTkFrame(self, fg_color=("white", "#2b2b2b"))
        self.main_frame.pack(fill="both", expand=True, padx=70, pady=70)

        self.pil_image = Image.open("clbg.jpg")

        # Create CTkImage (enable scaling)
        self.bg_image = CTkImage(light_image=self.pil_image, dark_image=self.pil_image, size=(self.winfo_width(), self.winfo_height()))

        # Background label
        self.bg_label = CTkLabel(master=self, image=self.bg_image, text="")
        self.bg_label.place(x=0, y=0, relwidth=1, relheight=1)
        self.bg_label.lower()  # send to back

        # Header with less padding
        self.header = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.header.pack(fill="x", padx=20, pady=(5,5))
        
        self.title_label = ctk.CTkLabel(
            self.header, 
            text="CLauncher", 
            font=("Segoe UI", 24, "bold"),
            text_color=("#2185d0"),
        )
        self.title_label.pack(side="left")

        # Version selection frame
        self.version_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.version_frame.pack(fill="x", padx=10, pady=5)

        self.version_label = ctk.CTkLabel(
            self.version_frame, 
            text="Version:", 
            font=("Segoe UI", 12)
        )
        self.version_label.pack(side="left", padx=(0,10))

        # Create custom combobox style for dropdown height
        style = ttk.Style()
        style.configure('Combobox', postoffset=(0, 10))

        # Use ttk.Combobox instead of CTkComboBox for better scrolling
        self.version_combobox = ttk.Combobox(
            self.version_frame,
            values=self.get_all_versions(),
            state="readonly",
            width=30,
            height=20  # Show 20 items in dropdown
        )
        self.version_combobox.pack(side="left", fill="x", expand=True)
        self.version_combobox.set(self.latest_release)

        # Username frame
        self.username_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.username_frame.pack(fill="x", padx=10, pady=5)

        self.username_label = ctk.CTkLabel(
            self.username_frame, 
            text="Username:", 
            font=("Segoe UI", 12)
        )
        self.username_label.pack(side="left", padx=(0,10))

        self.username_entry = ctk.CTkEntry(self.username_frame, width=30)
        self.username_entry.pack(side="left", fill="x", expand=True)
        self.username_entry.insert(0, "Player")  # Default username

        # Installations frame
        self.installations_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.installations_frame.pack(fill="x", padx=10, pady=5)

        self.installations_label = ctk.CTkLabel(
            self.installations_frame, 
            text="Installations:", 
            font=("Segoe UI", 12)
        )
        self.installations_label.pack(side="left", padx=(0,10))

        self.installations_listbox = Listbox(self.installations_frame, height=5)
        self.installations_listbox.pack(side="left", fill="x", expand=True)
        self.installations_listbox.bind("<<ListboxSelect>>", self.on_installation_select)

        self.installations_buttons_frame = ctk.CTkFrame(self.installations_frame, fg_color="transparent")
        self.installations_buttons_frame.pack(side="left", padx=(10, 0))

        self.add_installation_button = ctk.CTkButton(
            self.installations_buttons_frame,
            text="+",
            width=30,
            command=self.add_installation
        )
        self.add_installation_button.pack(side="top", pady=(0, 5))

        self.delete_installation_button = ctk.CTkButton(
            self.installations_buttons_frame,
            text="-",
            width=30,
            command=self.delete_installation
        )
        self.delete_installation_button.pack(side="top")

        self.load_installations()

        # Play button
        self.play_button = ctk.CTkButton(
            self.main_frame,
            text="PLAY",
            font=("Segoe UI", 16, "bold"),
            height=40,
            command=self.launch_minecraft
        )
        self.play_button.pack(fill="x", padx=10, pady=10)

        # Logs frame
        self.logs_frame = ctk.CTkFrame(self.main_frame, fg_color=("#f5f5f5", "#1e1e1e"))
        self.logs_frame.pack(fill="both", expand=True, padx=10, pady=(5,10))

        self.logs_text = ctk.CTkTextbox(
            self.logs_frame, 
            height=100,
            font=("Consolas", 10),
            wrap="none"
        )
        self.logs_text.pack(fill="both", expand=True, padx=5, pady=5)

        self._resize_job = None

        self.bind("<Configure>", self.on_resize)
        
        # Process log queue every 100ms
        self.process_logs_queue()

        # Status bar
        self.status_bar = ctk.CTkFrame(self.main_frame, fg_color="transparent", height=25)
        self.status_bar.pack(fill="x", padx=10, pady=(0,5))

        self.status_label = ctk.CTkLabel(
            self.status_bar, 
            text="Ready", 
            font=("Segoe UI", 10),
            text_color="gray"
        )
        self.status_label.pack(side="left")

        # Dark/Light mode toggle
        self.theme_toggle = ctk.CTkButton(
            self.status_bar,
            text="☀️ Light",
            width=80,
            height=25,
            font=("Segoe UI", 10),
            command=self.toggle_theme
        )
        self.theme_toggle.pack(side="right", padx=(10, 0))
        self.current_theme = "dark"

    def on_resize(self, event):
        if self._resize_job is not None:
            self.after_cancel(self._resize_job)
        self._resize_job = self.after(100, lambda: self.resize_bg(event.width, event.height))

    def process_logs_queue(self):
        """Process log messages from the queue (thread-safe)"""
        try:
            while True:
                msg = self.log_queue.get_nowait()
                self.logs_text.insert("end", msg)
                self.logs_text.see("end")
        except:
            pass
        # Schedule next check
        self.after(100, self.process_logs_queue)

    def resize_bg(self, width, height):
        self.bg_image = CTkImage(light_image=self.pil_image, dark_image=self.pil_image, size=(width, height))
        self.bg_label.configure(image=self.bg_image)

    def toggle_theme(self):
        """Toggle between dark and light theme"""
        if self.current_theme == "dark":
            ctk.set_appearance_mode("light")
            self.theme_toggle.configure(text="🌙 Dark")
            self.current_theme = "light"
        else:
            ctk.set_appearance_mode("dark")
            self.theme_toggle.configure(text="☀️ Light")
            self.current_theme = "dark"

    def is_trusted_url(self, url, trusted_domains):
        """Check if the URL belongs to a trusted domain."""
        parsed_url = urlparse(url)
        if parsed_url.netloc not in trusted_domains:
            if parsed_url.netloc.endswith("mojang.com") or parsed_url.netloc.endswith("minecraft.net"):
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
        #print(formatted_fingerprint) # Replace with actual fingerprint

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
        expected_hash = json_data["downloads"]["client"]["sha1"]  # Assuming SHA-1 is provided
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

    def launch_minecraft(self):
        selected_installation = self.installations_listbox.get("active")
        if not selected_installation:
            self.logs_text.insert("end", "Please select an installation to play.\n")
            return

        self.play_button.configure(state="disabled")
        threading.Thread(target=self._launch_minecraft).start()

    def _launch_minecraft(self):
        selected_installation = self.installations_listbox.get("active")
        profile_name = selected_installation.split(" (")[0]  # Extract profile name without version
        profile = next((p for p in load_profiles() if p["name"] == profile_name), None)
        if not profile:
            self.logs_text.insert("end", "Selected installation not found.\n")
            self.play_button.configure(state="normal")
            return

        version = profile.get("version")
        if not version:
            self.logs_text.insert("end", "Version not found for the selected installation, fallback is latest version.\n")
            version = self.fetch_latest_version()

        json_path = os.path.join(VERSIONS_DIR, version, f"{version}.json")
        jar_path = os.path.join(VERSIONS_DIR, version, f"{version}.jar")

        if not os.path.exists(json_path) or not os.path.exists(jar_path):
            self.logs_text.insert("end", f"Downloading Minecraft {version} files...\n")
            jar_path, version_json = self.download_minecraft_jar(version)
        else:
            with open(json_path, "r") as file:
                version_json = json.load(file)

        self.download_libraries(version_json)
        self.download_assets(version_json)

        custom_game_dir = MINECRAFT_DIR  # Use the local script directory instead of APPDATA

        # Set the native library path
        native_lib_path = NATIVES_DIR

        username = self.username_entry.get()

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

        for line in process.stdout:
            self.logs_text.insert("end", line)
            self.logs_text.see("end")

        for line in process.stderr:
            self.logs_text.insert("end", line)
            self.logs_text.see("end")

        process.wait()
        self.play_button.configure(state="normal")

    def toggle_dark_mode(self):
        if ctk.get_appearance_mode() == "dark":
            ctk.set_appearance_mode("light")
        else:
            ctk.set_appearance_mode("dark")

    def load_profiles(self):
        profiles = load_profiles()
        self.profiles_listbox.delete(0, "end")
        for profile in profiles:
            self.profiles_listbox.insert("end", profile["name"])

    def load_installations(self):
        installations = load_profiles()
        self.installations_listbox.delete(0, "end")
        for installation in installations:
            self.installations_listbox.insert("end", installation["name"] + f" ({installation['version']})")

    def on_installation_select(self, event):
        selected_installation = self.installations_listbox.get("active")
        if selected_installation:
            profile_name = selected_installation.split(" (")[0]  # Extract profile name without version
            profile = next((p for p in load_profiles() if p["name"] == profile_name), None)
            if profile and "version" in profile:
                self.version_combobox.set(profile["version"])
                if profile["version"] == self.latest_release:
                    self.icon_image = ImageTk.PhotoImage(Image.open("grassblock.jpg").resize((24, 24)))
                else:
                    self.icon_image = ImageTk.PhotoImage(Image.open("furnace.jpeg").resize((24, 24)))
                #self.icon_label.configure(image=self.icon_image)

    def add_installation(self):
        profile_name = simpledialog.askstring("Profile Name", "Enter profile name:")
        if profile_name:
            profile = {
                "name": profile_name,
                "version": self.version_combobox.get()
            }
            save_profile(profile)
            self.load_installations()

    def delete_installation(self):
        selected_profile = self.installations_listbox.get("active")
        if selected_profile:
            profile_name = selected_profile.split(" (")[0]  # Extract profile name without version
            delete_profile(profile_name)
            self.load_installations()

# Note: For enhanced security, consider implementing TLS certificate pinning using libraries like `requests_toolbelt`.

if __name__ == "__main__":
    app = MinecraftLauncher()
    app.mainloop()