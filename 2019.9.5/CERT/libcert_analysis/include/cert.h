#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include<string.h>
#include <time.h>
#include<stdint.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>

struct x509_st
{
	X509_CINF *cert_info;
	X509_ALGOR *sig_alg;
	ASN1_BIT_STRING *signature;
	int valid;
	int references;
	char *name;
	CRYPTO_EX_DATA ex_data;
	long ex_pathlen;
	long ex_pcpathlen;
	unsigned long ex_flags;
	unsigned long ex_kusage;
	unsigned long ex_xkusage;
	unsigned long ex_nscert;
	ASN1_OCTET_STRING *skid;
	AUTHORITY_KEYID *akid;
	X509_POLICY_CACHE *policy_cache;
	STACK_OF(DIST_POINT) *crldp;
	STACK_OF(GENERAL_NAME) *altname;
	NAME_CONSTRAINTS *nc;
#ifndef OPENSSL_NO_RFC3779
	STACK_OF(IPAddressFamily) *rfc3779_addr;
	struct ASIdentifiers_st *rfc3779_asid;
#endif
#ifndef OPENSSL_NO_SHA
	unsigned char *sha1_hash;
#endif
	X509_CERT_AUX *aux;
} ;


typedef struct	cert_analy_st{
	char	version[8];
	char 	serialNumber[128];
	char    signature[128];
	struct stu
	{
			char 	NID[8];
			char	name[512];
	}issuer_name[64],subject_name[64];
	struct tm*before_time;
	struct tm*after_time;
	unsigned char pubkey[1280];
	unsigned char signatureValue[1280];
	unsigned char	HashValue[1280];
}cert_st;

/*   
            *接口:证书解析
            *
            *[in]*cert:证书路径
            *
            * [out]*cert_verify_st:存储解析后证书数据的结构体
*/
int tX509_analysis(char *cert, cert_st *cert_verify_st);
/*   
            *接口:字符串转十六进制字符数组
            *
            *[in]*str:字符串
            *
            *[out]*out:十六进制字符数组
	    *[out]*outlen:十六进制字符数组长度
*/
int StrToHex(char *str, unsigned char *out, unsigned int outlen);
