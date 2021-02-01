#include<stdio.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

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
	unsigned char sha1_hash[SHA_DIGEST_LENGTH];
#endif
	X509_CERT_AUX *aux;
} ;
/*   
            *接口:证书根链验证
            *
            *[in]*user_path:用户证书路径
            *[in]*root_path:根证书路径
            *[in]*CRL_path:CRL证书销毁列表路径
            *
            * [out]1:验证正确 0:验证错误 -1:NULL
*/
int CheckCert(char*user_path,char*root_path,char*CRL_path);
