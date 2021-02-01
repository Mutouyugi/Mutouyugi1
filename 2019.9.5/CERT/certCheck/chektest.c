#include<stdio.h>
#include"certCheck.h"
int main()
{
    int mark;
    char*usercert="./03.pem";
    //char*usercert="./04.pem";
    char*rootcert="./cacert.pem";
    char*CRLfile=NULL;
    //char*CRLfile="./ca.crl";
   mark= CheckCert(usercert,rootcert,CRLfile);
    printf("%d\n",mark);
}
