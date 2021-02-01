#include"include/certformat.h"
int  certformat(char *cert)
{
    unsigned char derRootCert[4096];
	unsigned long derRooCertLen;
	unsigned char *pTmp = NULL;
     X509 *m_pX509 = NULL;
	m_pX509=(X509*)malloc(sizeof( struct x509_st));
	FILE *fp;
	 int i=0;
	
	//二进制编码格式证书转X509结构体
	fp  =  fopen(cert,"rb");
	if(fp == NULL)
	{
		printf("open file failed\n");
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
	}
    if(m_pX509==NULL)
    {
        return 0;
    }
    else
    {
        return 1;
    } 
}