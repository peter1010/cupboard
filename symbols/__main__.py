#!/usr/bin/env python3
import os
import logging

from . import main

def config_logging(also_to_console=True):
    """Configure logging"""
    root = logging.getLogger()
    fh = logging.FileHandler("log.txt")
    fh.setLevel(logging.DEBUG)
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    fh.setFormatter(formatter)
    root.addHandler(fh)

    if also_to_console:
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        formatter = logging.Formatter(
            '%(levelname)s - %(message)s'
        )
        ch.setFormatter(formatter)
        root.addHandler(ch)


if __name__ == "__main__":
    config_logging()
    main.main()
