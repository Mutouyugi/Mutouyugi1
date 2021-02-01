#include"certCheck.h"

int CheckCert(char*user_path,char*root_path,char*CRL_path)
{
	unsigned char derCert[4096];                               //cer to x509_st
	unsigned long derCertLen;
	unsigned char *pTmp = NULL;
	X509 *pCert = NULL;                  // X509 证书结构体，保存用户证书
        X509 *pCaCert = NULL;                // X509 证书结构体，保存根证书
	pCaCert=(X509*)malloc(sizeof( struct x509_st));
	pCert=(X509*)malloc(sizeof( struct x509_st));
	X509_STORE_CTX *ctx = NULL;          // 证书存储区句柄
	X509_STORE *pCaCertStore = NULL;     // 证书存储区
	X509_CRL *Crl = NULL;                // X509_CRL 结构体，保存CRL
  	STACK_OF(X509) *CertStack = NULL;
	//user_cert
	FILE*fp1  =  fopen(user_path,"rb");
	derCertLen = fread(derCert,1,4096,fp1);
	fclose(fp1);
	pTmp =  derCert;
	pCert = d2i_X509(NULL,(unsigned const char **)&pTmp,derCertLen);
	if( NULL ==pCert)
	{
		BIO * pbio = NULL;
 		pbio = BIO_new_file(user_path,"r");
 		pCert = PEM_read_bio_X509(pbio,NULL,NULL,NULL);
		BIO_free(pbio);
 		pbio = NULL;
		if( NULL ==pCert)
		{
			  printf("%s\n","userca x509 error");
		}
	}
	//root_cert
	FILE*fp2  =  fopen(root_path,"rb");
	derCertLen = fread(derCert,1,4096,fp2);
	fclose(fp2);
	pTmp =  derCert;
	pCaCert = d2i_X509(NULL,(unsigned const char **)&pTmp,derCertLen);
	if( NULL ==pCaCert)
	{
		BIO * pbio = NULL;
 		pbio = BIO_new_file(root_path,"r");
 		pCaCert = PEM_read_bio_X509(pbio,NULL,NULL,NULL);
		BIO_free(pbio);
 		pbio = NULL;
		if( NULL ==pCaCert)
		{
			  printf("%s\n","rootca x509 error");
		}
	}
		
	//验证根证书
	pCaCertStore = X509_STORE_new();     // 新建X509 证书存储区
        ctx = X509_STORE_CTX_new();    // 新建证书存储区句柄
        X509_STORE_add_cert(pCaCertStore,pCaCert);     // 添加根证书到证书存储区
        //验证CRL
        if(CRL_path!=NULL)
        {
	    X509_STORE_set_flags(pCaCertStore,X509_V_FLAG_CRL_CHECK);	
	    BIO * pbio = NULL;
 	    pbio = BIO_new_file(CRL_path,"r");
	    X509_CRL *Crl_PEM = NULL; 
	    Crl_PEM = (X509_CRL *)malloc(sizeof(X509_CRL*) );
	    Crl_PEM=PEM_read_bio_X509_CRL(pbio,NULL,NULL,NULL);
	    Crl=Crl_PEM;
    	    if (Crl==NULL)
 	    {
        	X509_free(pCaCert);
  		printf("读取吊销列表文件失败\n");
    	    }
 	    BIO_free(pbio);
            pbio = NULL;
	    X509_STORE_add_crl(pCaCertStore,Crl);    // 添加CRL 到证书存储区
         }
        
    int ret = X509_STORE_CTX_init(ctx,pCaCertStore,pCert,CertStack);   // 初始化根证书存储区、用户证书1
	if (ret != 1)
    {
       printf("X509_STORE_CTX_init err\n");

       X509_free(pCert);
       X509_free(pCaCert);
       X509_STORE_CTX_cleanup(ctx);
       X509_STORE_CTX_free(ctx);
       X509_STORE_free(pCaCertStore);
    }
	// 验证用户证书
    ret = X509_verify_cert(ctx); 

	X509_free(pCert);
    X509_free(pCaCert);
    X509_STORE_CTX_cleanup(ctx);
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(pCaCertStore);
	return ret;
}
