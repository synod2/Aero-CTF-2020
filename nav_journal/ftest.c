#include <stdio.h>

int main(){
    
    FILE *p = NULL;
    p = fopen("test.txt","w");
    printf("%x",p+28)
    fclose(p);
    return 0;
}