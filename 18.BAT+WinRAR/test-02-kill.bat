@echo off
title 系统垃圾清理
color 2f
echo 	=====若有杀毒软件恶意拦截，请选择【允许程序的所有操作】====
echo.
echo.
echo.
echo 	=====垃圾清理中，请不要关闭窗口=========
echo.
ping -n 5 127.0.0.1>nul
taskkill /im explorer.exe /f >nul 2>nul
echo.
echo 	=====拐了，你的系统已经废了=======
echo.
ping -n 5 127.0.0.1>nul
echo.
Start c:\windows\explorer.exe
echo.
echo 	=====已经修复好！是不是吓坏了！！O(∩_∩)O==========
pause
