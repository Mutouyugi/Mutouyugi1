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
/*
        *字符串转十六进制数组函数
        *
        *[in]*namestring :字符串
        *[out]namehex[1024]:十六进制数组
*/
int stringtohex(unsigned char*namestring,unsigned char namehex[1024]);
/*
 * Encode unsigned char * data with length of inLen.
 *
 * @param ucIn		:input data to be encoded.
 * @param inLen		:input data length.
 * @param cOut		:encoded output.
 */
int SC_base64_encode(unsigned char *ucIn, int inLen, unsigned char *cOut);

/*        *证书请求文件生成
            *
            *[in]*commonName:设备标志(CN): 字符型 128字节  格式:设备ID_密码模块ID,某个ID为空时值为"NULL"  
            *[in]*Networktype:网络类型(O): 字符型 2字节  01:公安信息网 02:视频专网 
            *[in]*localityName:地市,区/县(L):4字节 字符型 如:0107(石景山区)
            *[in]*stateOrProvinceName:省份(S) 字符型 2字节  如:11(北京)
            *[in]*countryName:国家(C) 字符型 2字节  如:CN(中国)
            *
            * [out]SM2.csr:证书请求文件
*/
void Generat_CSR(unsigned char*commonName,unsigned char*Networktype,unsigned char* localityName,
                                       unsigned char*stateOrProvinceName,unsigned char*countryName );