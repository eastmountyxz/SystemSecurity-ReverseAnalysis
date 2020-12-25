
#include "stdio.h"
#include "windows.h"

int main()
{
	//输入值作为修改阳光参数
	int x;
	scanf("%d", &x);

	//进程ID
	DWORD pid;

	//1.找到游戏窗口 窗口类型、窗口标题
	HWND hwnd = FindWindow(NULL,L"植物大战僵尸中文版");

	//2.通过窗口找到进程ID
	GetWindowThreadProcessId(hwnd,&pid);

	//3.通过进程ip打开进程
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

	//4.通过打开进程修改游戏内容 0x2099AE60 
	WriteProcessMemory(hProcess, (LPVOID)0x207FB5A0,
		               (LPVOID)&x,sizeof(x),&pid);

	return 0;
}
