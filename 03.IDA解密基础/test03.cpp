#include<stdio.h>
#include<string.h>

int main()
{
	int i;
	int len;
	char key[20];
	char res[20];
	char *num = "eastmount";     //密钥 
	char *right = "123456789";   //正确值 
	
	//请输入正确的密码
	printf("please input the key:");
	scanf("%s", &key);
	
	
	//判断 TS@@XYBVM
	len = strlen(key);
	if(len<6 || len>10) {
		printf("Error, The length of the key is 6~10\n");
	} 
	else {
		//加密
		for(i=0; i<len; i++) {
			res[i] = (key[i]^num[i]); //异或加密 
		}	 
		//printf("%s\n", res);
		if(strcmp(res, right)==0) {
			printf("You are right, Success.\n");
		} else {
			printf("Error, please input the right key.\n");
		}
	}
	
	return 0;
}
