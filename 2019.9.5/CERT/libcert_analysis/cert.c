#include"cert.h"
int tX509_analysis(char *cert, cert_st *cert_verify_st)
{
	unsigned char derRootCert[4096];
	unsigned long derRooCertLen;
	unsigned char *pTmp = NULL;
	//X509 *m_pX509 = NULL;
	X509 *m_pX509=X509_new();
	//m_pX509=(X509*)malloc(sizeof( struct x509_st));
	FILE *fp;
	int i=0;
	
	//二进制编码格式证书转X509结构体
	fp  =  fopen(cert,"rb");
	if(fp == NULL)
	{
		return -1;
	}
	derRooCertLen = fread(derRootCert,1,4096,fp);
	fclose(fp);
	pTmp =  derRootCert;
	m_pX509 = d2i_X509(NULL,(unsigned const char **)&pTmp,derRooCertLen);
	if( NULL ==m_pX509)
	{
		//base64编码格式证书转X509结构体
		BIO * pbio = NULL;
 		pbio = BIO_new_file(cert,"r");
 		m_pX509 = PEM_read_bio_X509(pbio,NULL,NULL,NULL);
		BIO_free(pbio);
 		pbio = NULL;
		 if (m_pX509 == NULL)
			return -1;
	}
    //version
	int ver = X509_get_version(m_pX509);            
	switch(ver)  	
	{
		case 0:		//V1
		memcpy(cert_verify_st->version , "V1", 2);
		break;
		case 1:		//V2
		memcpy(cert_verify_st->version , "V2", 2);
		break;
		case 2:		//V3
		memcpy(cert_verify_st->version , "V3", 2);
		break;
		default:
		memcpy(cert_verify_st->version , "NO", 2);
		break;
	} 
	//serialnumber
    ASN1_INTEGER *asn1_i = NULL;
	BIGNUM *bignum = NULL;
	asn1_i = X509_get_serialNumber(m_pX509);
	bignum = ASN1_INTEGER_to_BN(asn1_i, NULL);
	char *serial=NULL;
	serial=BN_bn2hex(bignum);
	memcpy(cert_verify_st->serialNumber , serial, strlen(serial));
	BN_free(bignum);
	//issuer
	X509_NAME *issuer=X509_NAME_new();
	X509_NAME_ENTRY *issuer_entry;
	ASN1_STRING *issuer_name_asni;
	const ASN1_OBJECT *issuer_obj_name;
	const char *issuer_str_name;
	int i_NID;
	issuer = X509_get_issuer_name(m_pX509);
 	for (i = 0; i < X509_NAME_entry_count(issuer); i++) 
	 {
     		issuer_entry=X509_NAME_get_entry(issuer,i);
			issuer_name_asni=X509_NAME_ENTRY_get_data(issuer_entry);
			issuer_str_name=ASN1_STRING_get0_data(issuer_name_asni);
			memcpy(cert_verify_st->issuer_name[i].name ,issuer_str_name, strlen(issuer_str_name));
			issuer_obj_name=X509_NAME_ENTRY_get_object(issuer_entry);
			i_NID=OBJ_obj2nid(issuer_obj_name);
			switch(i_NID)
			{
				case	13:       memcpy(cert_verify_st->issuer_name[i].NID , "CN", 2);		break;
				case	14:       memcpy(cert_verify_st->issuer_name[i].NID , "C", 1);			break;
				case	15:       memcpy(cert_verify_st->issuer_name[i].NID , "L", 1);		break;
				case	16:       memcpy(cert_verify_st->issuer_name[i].NID , "ST", 2);		break;
				case	17:       memcpy(cert_verify_st->issuer_name[i].NID , "O", 1);			break;
				case	18:       memcpy(cert_verify_st->issuer_name[i].NID , "OU", 2);			break;
				default:		  memcpy(cert_verify_st->issuer_name[i].NID , "unknow", 6);
			}
 	}
	 X509_NAME_free(issuer);
	//validity
	int j=0;
	ASN1_TIME *before_asn1_time=NULL;
	ASN1_TIME *after_asn1_time=NULL;
	unsigned char *before_str_time;
	unsigned char *after_str_time;
	before_asn1_time= X509_get_notBefore(m_pX509);
	after_asn1_time = X509_get_notAfter(m_pX509);
	before_str_time=before_asn1_time->data;
	after_str_time=after_asn1_time->data;
	//起始时间
	cert_verify_st->before_time=malloc(sizeof( struct tm));
	//memset(cert_verify_st->before_time,0,sizeof(cert_verify_st->before_time));
	cert_verify_st->before_time->tm_year=100+10*(*(before_str_time)-'0')+(*(before_str_time+1)-'0');
	cert_verify_st->before_time->tm_mon=10*(*(before_str_time+2)-'0')+(*(before_str_time+3)-'0');
	cert_verify_st->before_time->tm_mday=10*(*(before_str_time+4)-'0')+(*(before_str_time+5)-'0');
	cert_verify_st->before_time->tm_hour=10*(*(before_str_time+6)-'0')+(*(before_str_time+7)-'0')+8;
	cert_verify_st->before_time->tm_min=10*(*(before_str_time+8)-'0')+(*(before_str_time+9)-'0');
	cert_verify_st->before_time->tm_sec=10*(*(before_str_time+10)-'0')+(*(before_str_time+11)-'0');
	//终止时间
	cert_verify_st->after_time=malloc(sizeof( struct tm));
	cert_verify_st->after_time->tm_year=100+10*(*(after_str_time)-'0')+(*(after_str_time+1)-'0');
	cert_verify_st->after_time->tm_mon=10*(*(after_str_time+2)-'0')+(*(after_str_time+3)-'0');
	cert_verify_st->after_time->tm_mday=10*(*(after_str_time+4)-'0')+(*(after_str_time+5)-'0');
	cert_verify_st->after_time->tm_hour=10*(*(after_str_time+6)-'0')+(*(after_str_time+7)-'0')+8;
	cert_verify_st->after_time->tm_min=10*(*(after_str_time+8)-'0')+(*(after_str_time+9)-'0');
	cert_verify_st->after_time->tm_sec=10*(*(after_str_time+10)-'0')+(*(after_str_time+11)-'0');

	//subject
	X509_NAME *subject=X509_NAME_new();
	X509_NAME_ENTRY *subject_entry;
	ASN1_STRING *subject_name_asni;
	const ASN1_OBJECT *subject_obj_name;
	const char *subject_str_name;
	int s_NID;
	subject = X509_get_subject_name(m_pX509);
 	for (i = 0; i < X509_NAME_entry_count(subject); i++) 
	 {
     		subject_entry=X509_NAME_get_entry(subject,i);
			subject_name_asni=X509_NAME_ENTRY_get_data(subject_entry);
			subject_str_name=ASN1_STRING_get0_data(subject_name_asni);
			memcpy(cert_verify_st->subject_name[i].name ,subject_str_name, strlen(subject_str_name));
			subject_obj_name=X509_NAME_ENTRY_get_object(subject_entry);
			s_NID=OBJ_obj2nid(subject_obj_name);
			switch(s_NID)
			{
				case	13:       memcpy(cert_verify_st->subject_name[i].NID , "CN", 2);		break;
				case	14:       memcpy(cert_verify_st->subject_name[i].NID , "C", 1);			break;
				case	15:       memcpy(cert_verify_st->subject_name[i].NID , "L", 1);		break;
				case	16:       memcpy(cert_verify_st->subject_name[i].NID , "ST", 2);		break;
				case	17:       memcpy(cert_verify_st->subject_name[i].NID , "O", 1);			break;
				case	18:       memcpy(cert_verify_st->subject_name[i].NID , "OU", 2);			break;
				case	48:       memcpy(cert_verify_st->subject_name[i].NID , "E", 1);			break;
				default:		  memcpy(cert_verify_st->subject_name[i].NID , "unknow", 6);
			}
 	}
	 X509_NAME_free(subject);
	//publickey
	BIGNUM *ret=BN_new();
	char *key_value;
	ASN1_BIT_STRING   *key   =   X509_get0_pubkey_bitstr(m_pX509);
	BN_bin2bn(key->data,key->length,ret);
	key_value=BN_bn2hex(ret);
    unsigned char pubkey_hex[1024];
	unsigned int pubkey_len;
	memcpy(pubkey_hex,key_value+2,strlen(key_value));
	StrToHex(pubkey_hex,cert_verify_st->pubkey,pubkey_len);

	//signature
	char *sig_value;
	ASN1_OBJECT *salg=NULL;
	const ASN1_BIT_STRING   *signature =NULL;
	const X509_ALGOR *palg = NULL;
	X509_get0_signature(&signature,&palg,m_pX509);
	BN_bin2bn(signature->data,signature->length,ret);
	sig_value=BN_bn2hex(ret);
	memcpy(cert_verify_st->signatureValue,sig_value,strlen(sig_value));
	salg=palg->algorithm;
	OBJ_obj2txt(cert_verify_st->signature, 128, salg,1);
/*
	//HashValue
	char *hash_value;
	X509_digest(m_pX509, EVP_sha1(), m_pX509->sha1_hash, NULL);
	BN_bin2bn(m_pX509->sha1_hash,SHA_DIGEST_LENGTH,ret);
	hash_value=BN_bn2hex(ret);
	memcpy(cert_verify_st->HashValue,hash_value,strlen(hash_value));
*/
	BN_free(ret);
	//X509_free(m_pX509);
	free(m_pX509);
}	


int StrToHex(char *str, unsigned char *out, unsigned int outlen)
{
    char *p = str;
    char high = 0, low = 0;
    int tmplen = strlen(p), cnt = 0;
    tmplen = strlen(p);
    while(cnt < (tmplen / 2))
    {
        high = ((*p > '9') && ((*p <= 'F') || (*p <= 'f'))) ? *p - 48 - 7 : *p - 48;
		low = (*(++ p) > '9' && ((*p <= 'F') || (*p <= 'f'))) ? *(p) - 48 - 7 : *(p) - 48;
        out[cnt] = ((high & 0x0f) << 4 | (low & 0x0f));
        p ++;
        cnt ++;
    }
    if(tmplen % 2 != 0) out[cnt] = ((*p > '9') && ((*p <= 'F') || (*p <= 'f'))) ? *p - 48 - 7 : *p - 48;
    
      outlen = tmplen / 2 + tmplen % 2;
    return tmplen / 2 + tmplen % 2;
}
