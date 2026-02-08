#from .ui import MinecraftLauncher
from ui import MinecraftLauncher
import os

if __name__ == "__main__":
    app = MinecraftLauncher(os.path.abspath(os.path.join(os.path.dirname(__file__), "assets")))
    app.mainloop()
