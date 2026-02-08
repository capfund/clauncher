#from .ui import MinecraftLauncher
from ui import MinecraftLauncher
import os, ctypes

if __name__ == "__main__":
    ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("clauncher.app.1")
    app = MinecraftLauncher(os.path.abspath(os.path.join(os.path.dirname(__file__), "assets")))
    app.mainloop()
