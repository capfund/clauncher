import customtkinter as ctk
from customtkinter import CTkImage, CTkLabel
from tkinter import ttk, Listbox, simpledialog, PhotoImage
from PIL import Image, ImageTk
import os
import json
from backend.profiles import load_profiles, save_profile, delete_profile
from backend.core import MinecraftCore
from queue import Queue
import threading

class MinecraftLauncher(ctk.CTk):
    def __init__(self, assets_path):
        super().__init__()
        
        # Queue for thread-safe log messages
        self.log_queue = Queue()
        
        # Initialize core
        self.core = MinecraftCore(self.log_queue)
        self.core.core_make_dirs()
        self.latest_release = self.core.fetch_latest_version()

        self.iconbitmap(os.path.join(assets_path, "clauncher-logo.ico"))
        
        self.title("CLauncher")
        self.geometry("550x550")
        self.resizable(True, True)

        # Configure styles
        self.configure(fg_color=("white", "#1a1a1a"))
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        # Main container
        self.main_frame = ctk.CTkFrame(self, fg_color=("white", "#2b2b2b"))
        self.main_frame.pack(fill="both", expand=True, padx=70, pady=70)

        self.pil_image = Image.open(os.path.join(assets_path, "clbg.jpg"))

        # Create CTkImage (enable scaling)
        self.bg_image = CTkImage(light_image=self.pil_image, dark_image=self.pil_image, size=(self.winfo_width(), self.winfo_height()))

        # Background label
        self.bg_label = CTkLabel(master=self, image=self.bg_image, text="")
        self.bg_label.place(x=0, y=0, relwidth=1, relheight=1)
        self.bg_label.lower()

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
            values=self.core.get_all_versions(),
            state="readonly",
            width=30,
            height=20
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
        self.username_entry.insert(0, "Player")

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
            text="Made with ❤️ by CLauncher Team", 
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

    def launch_minecraft(self):
        selected_installation = self.installations_listbox.get("active")
        if not selected_installation:
            self.logs_text.insert("end", "Please select an installation to play.\n")
            return

        self.play_button.configure(state="disabled")
        threading.Thread(target=self._launch_minecraft).start()

    def _launch_minecraft(self):
        selected_installation = self.installations_listbox.get("active")
        profile_name = selected_installation.split(" (")[0]
        profile = next((p for p in load_profiles() if p["name"] == profile_name), None)
        if not profile:
            self.logs_text.insert("end", "Selected installation not found.\n")
            self.play_button.configure(state="normal")
            return

        # Create core with profile-specific directories
        core = MinecraftCore(self.log_queue, profile_name)
        core.core_make_dirs()

        version = profile.get("version")
        if not version:
            self.logs_text.insert("end", "Version not found for the selected installation, fallback is latest version.\n")
            version = core.fetch_latest_version()

        json_path = os.path.join(core.versions_dir, version, f"{version}.json")
        jar_path = os.path.join(core.versions_dir, version, f"{version}.jar")

        if not os.path.exists(json_path) or not os.path.exists(jar_path):
            self.logs_text.insert("end", f"Downloading Minecraft {version} files...\n")
            jar_path, version_json = core.download_minecraft_jar(version)
        else:
            with open(json_path, "r") as file:
                version_json = json.load(file)

        core.download_libraries(version_json)
        core.download_assets(version_json)

        username = self.username_entry.get()
        process = core.launch_minecraft(version, username, json_path, jar_path, version_json)

        for line in process.stdout:
            self.logs_text.insert("end", line)
            self.logs_text.see("end")

        for line in process.stderr:
            self.logs_text.insert("end", line)
            self.logs_text.see("end")

        process.wait()
        self.play_button.configure(state="normal")

    def load_installations(self):
        installations = load_profiles()
        self.installations_listbox.delete(0, "end")
        for installation in installations:
            self.installations_listbox.insert("end", installation["name"] + f" ({installation['version']})")

    def on_installation_select(self, event):
        selected_installation = self.installations_listbox.get("active")
        if selected_installation:
            profile_name = selected_installation.split(" (")[0]
            profile = next((p for p in load_profiles() if p["name"] == profile_name), None)
            if profile and "version" in profile:
                self.version_combobox.set(profile["version"])
                if profile["version"] == self.latest_release:
                    self.icon_image = ImageTk.PhotoImage(Image.open(os.path.join(self.assets_path, "grassblock.jpg")).resize((24, 24)))
                else:
                    self.icon_image = ImageTk.PhotoImage(Image.open(os.path.join(self.assets_path, "furnace.jpeg")).resize((24, 24)))

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
            profile_name = selected_profile.split(" (")[0]
            delete_profile(profile_name)
            self.load_installations()