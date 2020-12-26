// RE_XH.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <stdlib.h>

int main(int argc, char* argv[])
{
	int nSum = 0;

	for (int n = 1; n<=100; n++)
	{
		nSum = nSum + n;
	} 
	
	printf("%d", nSum);
	system("pause");
	return 0;
}
