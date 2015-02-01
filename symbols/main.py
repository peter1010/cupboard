#!/usr/bin/env python3

import tkinter as tk
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


class Application:

    def __init__(self, root):
        self.root = root
        root.title("Symbols")


def main():
    root = tk.Tk()
    app = Application(root)
    root.mainloop()


def config_logging():
    fh = logging.FileHandler("log.txt")
    fh.setLevel(logging.DEBUG)
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    fh.setFormatter(formatter)

    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)
    formatter = logging.Formatter(
        '%(levelname)s - %(message)s'
    )
    ch.setFormatter(formatter)
    root = logging.getLogger()
    root.addHandler(fh)
    root.addHandler(ch)


if __name__ == "__main__":
    config_logging()
    main()
