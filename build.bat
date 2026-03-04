@echo off
echo Building WatchDawg Logger...
cl main.c /Fe:WatchDawg.exe /link advapi32.lib tdh.lib user32.lib shell32.lib
echo Done!
pause