import tkinter as tk
import tkinter.ttk as ttk
import tkinter.filedialog as tkFileDialog
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

from . import parse_elf

class Application:

    def __init__(self, root):
        root.title("Symbols")
        self.create_menu(root)
        self.root = root
        self.main = tk.PanedWindow(root,showhandle=True)
        self.main.pack(fill=tk.BOTH, expand=1)
        frame1 = tk.Frame(root)
        title = tk.Label(frame1, text="Browser")
        title.pack(side=tk.TOP)

        frame2 = ttk.Notebook(root)
        self.main.add(frame1)
        self.main.add(frame2)

    def create_menu(self, root):
        menubar = tk.Menu(root)
        filemenu = tk.Menu(menubar, tearoff=0)
        filemenu.add_command(label="Load file", command=self.load_file)
        filemenu.add_command(label="Quit", command=self.quit)
        menubar.add_cascade(label="File", menu=filemenu)
        root.config(menu=menubar)

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
        parse_elf.read_elffile(path, None)

    def quit(self):
        self.root.quit()



def main():
    root = tk.Tk()
    app = Application(root)
    root.mainloop()
