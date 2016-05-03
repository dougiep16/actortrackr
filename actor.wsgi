#!/usr/bin/env python3.4
import os
import sys

# set PATH so imports are correct
TOP_DIR = os.path.dirname(os.path.realpath(__file__))

CONFIG_PATH= TOP_DIR+"/config"
LIB_PATH= TOP_DIR+"/lib"
APP_PATH = TOP_DIR+"/app"

sys.path.insert(0, TOP_DIR)
sys.path.insert(0, CONFIG_PATH)
sys.path.insert(0, LIB_PATH)
sys.path.insert(0, APP_PATH)

# Fire up our application
from app import app as application