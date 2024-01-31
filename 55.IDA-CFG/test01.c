#include <stdio.h>

int sub_num(int a, int b) {
    int s;
    s = a + b;
    printf("函数运算结果: %d\n",s);
    return s;
}

int main() {
    int i,m,n;
    int result=0;

    scanf("%d %d",&m,&n);
    printf("输入的数字为:%d %d",m,n);

    //条件语句
    if (m>10) {
        printf("数字大于10\n");
    }
    else {
        printf("数字小于等于10\n");
    }

    //循环语句
    for (i=0; i<=10; i++) {
        result += i;
        i++;
    }
    printf("1 + 2 + ... + 10 = %d\n",result);
    
    //函数
    result = result + sub_num(m,n);
    printf("最终输出结果: %d\n",result);
    return 0;
}