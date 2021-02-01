1.make
2.cp libcertformat.so ./lib
3.export LD_LIBRARY_PATH=./lib
4.gcc -g -o test test.c -I./include -L./lib -lcertformat -lssl -lcrypto
5. ./test

/*   
            *接口:X509证书格式
            *
            *[in]*cert):用户证书路径
            *
            * [out]1:格式正确 0:格式错误 -1:NULL
*/
int  certformat(char *cert);
