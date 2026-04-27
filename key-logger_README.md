# Key Logger README

## Overview

it is a keylogger file

To understand this little script , it saves every key stroke that you press on your desktop/laptop or on the system which supports the python enviornment in a text file.

the text file is in append mode i.e if you keep pressing keys it will not remoev previous data it will apend keystrokes data with the existing one.

## Dependency

- pynput

## Running the file

```bash
# make a  python enviuornment 
python3 -m venv enviornemnt-name 

# activate enviornemnt 
source enviornemnt-name/bin/activate

# install dependency
pip install pynput

# run the file 
python filename.py
```

## Key Function

pynput provides the functions for capturing the keys on the keyboard 

## CAUTION

Always run it in virtual/safe enviornment. Do NOT run on your main system.

## Case Study

**In linux enviornment this python file will not work if you are using Wayland display server protocol in linux.**

But this will work only in your terminal window or on the window in which you run this script 

Modern Linux systems have security restrictions that prevent even sudo from capturing keyboard input system-wide from other windows. 



