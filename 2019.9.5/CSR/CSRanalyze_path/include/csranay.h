#include<stdio.h>
#include<string.h>
#include<openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>

//typedef  req_anal_st  REQ_ANAL;


struct X509_pubkey_st {
    X509_ALGOR *algor;
    ASN1_BIT_STRING *public_key;
    EVP_PKEY *pkey;
};
/*          *接口:CSR证书文件解析
            *
            *[in]*cert:证书请求文件路径
            *
            *[return]*csrdata:分号隔开的申请者信息以及公钥
*/
char *req_analysis(char *cert);
