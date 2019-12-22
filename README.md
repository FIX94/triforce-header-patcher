# Usage
Grab the [TriHdrPatcher.exe](bin/TriHdrPatcher.exe?raw=true).  
Drag and drop whatever file you might have into the executable. If they are still in MAME CHD/BIN format make sure to use [triforce-iso-extract](https://github.com/FIX94/triforce-iso-extract) on them first.   
The tool will inform you if the file has a known SHA1, will fix some known dump errors and of course set a nice header for your loader. If you are using Nintendont as loader you can rename your patched file to game.iso afterwards.   
As of right now the following games will get these IDs and game titles:  
GFZJ8P - F-Zero AX  
GGPE01 - Mario Kart Arcade GP  
GGPE02 - Mario Kart Arcade GP 2  
GPBJ8P - Gekitou Pro Yakyuu  
GVS32J - Virtua Striker 3 Ver. 2002  
GVS32E - Virtua Striker 3 Ver. 2002  
GVS45J - Virtua Striker 4  
GVS45E - Virtua Striker 4  
GVS46J - Virtua Striker 4 Ver. 2006  
GVS46E - Virtua Striker 4 Ver. 2006  

# Manual Compiling

## windows
~~As of right now this is a windows only code~~. If you have MinGW installed and gcc referenced in your PATH variable just use the "build.bat".  
Support for other OSes might follow in the future.

## linux
run build.sh, does the same thing as build.bat on windows

