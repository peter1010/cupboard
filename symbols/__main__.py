#!/usr/bin/env python3
import os
import logging

from . import main

def config_logging():
    """Configure logging"""
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
    main.main()
