import tkinter as tk
import tkinter.ttk as ttk
import tkinter.filedialog as tkFileDialog
from tkinter import messagebox
import logging
import os

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

from . import parse_elf
from . import browser

class Application:

    def __init__(self, root, project_folder=None):
        self.project_folder = project_folder
        root.title("Symbols")
        self.create_menu(root)
        self.root = root
        self.main = tk.PanedWindow(root,showhandle=True)
        self.main.pack(fill=tk.BOTH, expand=1)
        frame1 = browser.Browser(self.main)
        frame2 = ttk.Notebook(root)
        self.main.add(frame1.frame)
        self.main.add(frame2)

    def create_menu(self, root):
        menubar = tk.Menu(root)
        filemenu = tk.Menu(menubar, tearoff=0)
        filemenu.add_command(label="Create project",
                command=self.create_project
        )
        filemenu.add_command(label="Open project",
                command=self.open_project
        )
        filemenu.add_command(label="Load file", command=self.load_file)
        filemenu.add_command(label="Quit", command=self.quit)
        menubar.add_cascade(label="File", menu=filemenu)
        root.config(menu=menubar)

    def create_project(self, initialfile=None):
        path = tkFileDialog.asksaveasfilename(
                title="Create a Project folder",
                initialfile=initialfile
        )
        logger.debug("Creating project folder %s", path)
        os.mkdir(path)


    def open_project(self):
        path = tkFileDialog.askdirectory(
                title="Open a Project folder"
        )
        logger.debug("Opening project folder %s", path)


    def load_file(self):
        """Offer the User ability to load a file"""
        path = tkFileDialog.askopenfilename(
#            initialdir=self.dirname,
            filetypes = (
                ("Lib", "*.so"),
                ("All files", "*")
            )
        )
        logger.info("Loading file %s", path)
        if not self.project_folder:
            create = messagebox.askquestion(
                    "Create or open a project",
                    "No project open create a new project"
            )
            if create:
                self.create_project(path[:path.rfind(".")])
            else:
                self.open_project(self)
        parse_elf.read_elffile(path, None)

    def quit(self):
        self.root.quit()



def main():
    root = tk.Tk()
    app = Application(root)
    root.mainloop()
