#include"include/certformat.h"
int main()
{
    int mark;
    char*cert_path="/home/mutouyugi/Documents/testcer/RootCA_SM2.crt";
    mark=certformat(cert_path);
    printf("%d\n",mark);
}
