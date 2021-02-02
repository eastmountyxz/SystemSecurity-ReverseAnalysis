@echo off
color 0a
title Eastmount程序

:menu
cls
echo ===================================
echo                 菜单
echo           1.修改管理员密码
echo           2.定时关机
echo           3.退出本程序
echo ===================================

set /p num=您的选择是：
if "%num%"=="1" goto 1
if "%num%"=="2" goto 2
if "%num%"=="3" goto 3

echo 您好！请输入1-3正确的数字
pause
goto menu

:1
set /p u=请输入用户名:
set /p p=请输入新密码:
net user %u% %p% >nul
echo 您的密码已经设置成功！
pause
goto menu

:2
set /p time=请输入时间:
shutdown -s -t %time%
goto menu

:3
exit
