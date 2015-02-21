import tkinter as tk
import tkinter.ttk as ttk
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

class Browser:

    def __init__(self, root):
        frame = tk.Frame(root)
        title = tk.Label(frame, text="Browser")
        title.pack(anchor=tk.N, fill=tk.X)
        rightAndLeft = tk.Scrollbar(frame, orient=tk.HORIZONTAL)
        rightAndLeft.pack(anchor=tk.S, side=tk.BOTTOM, fill=tk.X, expand=1)
        text = tk.Text(frame)
        text.pack(anchor=tk.W,side=tk.LEFT)
        upAndDown = tk.Scrollbar(frame, orient=tk.VERTICAL)
        upAndDown.pack(anchor=tk.E, side=tk.RIGHT, fill=tk.Y, expand=1)
        self.frame = frame


