#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/crypto.h>

#define add_error(str)  printf( ""#str" error\n")
#define SUCCESS 0
#define SignKey TRUE
#define CryptKey FALSE

#ifndef SC_BASE64_H_
#define SC_BASE64_H_

#ifndef __SC_MACRO
#define __SC_MACRO

#define SC_SUCCESS               1
#define SC_FAILED               -1
#define SC_NOMEM                -2
#define SC_BADPARAMETER -3
#define SC_SYNTAXERROR  -4
#define SC_RTNULL               -5              /* function returns NULL */
#define SC_ERROR                -6
#endif
#endif

int stringtohex(unsigned char*namestring,unsigned char namehex[1024]);
int SC_base64_encode(unsigned char *ucIn, int inLen, unsigned char *cOut);
/*          *接口:用户证书请求文件生成
            *
            *[in]*commonName:用户网址(CN): 字符型 
            *[in]*localityName:地市,区/县(L): 字符型 
            *[in]*stateOrProvinceName:省份(S) 字符型 
            *[in]*countryName:国家(C) 字符型 
	    *[in]*organizationName:组织名(O)
	    *[in]*organizationalUnitName:部门名(OU)
            *[in]*emailAddress:邮箱(E)
            *
            * [out]SM2.csr:证书请求文件
*/
void Generat_CSR(unsigned char*countryName,unsigned char*stateOrProvinceName,unsigned char*localityName,
                                            unsigned char*organizationName,unsigned char*organizationalUnitName,unsigned char*commonName,
                                            unsigned char*emailAddress);
