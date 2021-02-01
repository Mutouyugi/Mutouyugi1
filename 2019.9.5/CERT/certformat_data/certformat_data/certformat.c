#include"include/certformat.h"
int  certformat(char *cert)
{
	unsigned char *pTmp = NULL;
    X509 *m_pX509 = NULL;
	m_pX509=(X509*)malloc(sizeof( struct x509_st));
	 int i=0;
	//二进制编码格式证书转X509结构体
	pTmp =  cert;
	unsigned long derRooCertLen=strlen(cert);
	m_pX509 = d2i_X509(NULL,(unsigned const char **)&pTmp,derRooCertLen);
	if( NULL ==m_pX509)
	{
		//base64编码格式证书转X509结构体
		size_t certLen = strlen(cert);
		BIO* certBio = BIO_new(BIO_s_mem());
		BIO_write(certBio, cert, certLen);
		m_pX509 = PEM_read_bio_X509(certBio, NULL, NULL, NULL);
	}
    while(m_pX509==NULL)
    {
        return 0;
    }
    char *hash_value;
    int ver = X509_get_version(m_pX509);                                                                          //version
    if(ver!=0&&ver!=1&&ver!=2)
    {
        return 0;
    }
    ASN1_INTEGER *asn1_i = X509_get_serialNumber(m_pX509);                          //serialnumber
    X509_NAME *issuer=X509_get_issuer_name(m_pX509);                                      //issuer
    ASN1_TIME * before_asn1_time= X509_get_notBefore(m_pX509);
	ASN1_TIME *after_asn1_time = X509_get_notAfter(m_pX509);
    X509_NAME *subject = X509_get_subject_name(m_pX509);  
    ASN1_BIT_STRING   *key   =   X509_get0_pubkey_bitstr(m_pX509);
	X509_digest(m_pX509, EVP_sha1(), m_pX509->sha1_hash, NULL);
    if(asn1_i==NULL||issuer==NULL||before_asn1_time==NULL||after_asn1_time==NULL||subject==NULL||key==NULL||m_pX509->sha1_hash==NULL)
    {return 0;}
    else
    {
        return 1;
    } 
}