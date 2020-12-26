// RE_SF.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <stdlib.h>

int main(int argc, char* argv[])
{
	if (argc > 8 )
	{
		printf("argc > 8\r\n");
	}
	else
	{
		printf("argc <= 8\r\n");
	}

	system("pause");
	return 0;
}
