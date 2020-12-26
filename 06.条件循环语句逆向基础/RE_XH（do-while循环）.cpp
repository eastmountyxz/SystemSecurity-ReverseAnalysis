// RE_XH.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <stdlib.h>

int main(int argc, char* argv[])
{
	int n = 1;
	int nSum = 0;

	//do-while Ö´ÐÐÒ»´Î
	do {
		nSum = nSum + n;
		n++;
	} while(n <= 100);
	
	printf("%d", nSum);
	system("pause");
	return 0;
}
