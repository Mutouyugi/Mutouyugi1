#include"cert.h"

/*int function_get_publick()
{
	char *path="./1.cer";
	char publicKey[150]={0};
	cert_st  *X509_Cert;
        X509_Cert = (cert_st*)malloc(sizeof(struct cert_analy_st));
        tX509_analysis(path, X509_Cert);
        memcpy(publicKey, X509_Cert->pubkey+2, strlen(X509_Cert->pubkey));

        free(X509_Cert);
	return 0;
}*/

int main()
{
	int i;
	int indent=4;
    	cert_st  *cert_printf_st;
    	cert_printf_st=(cert_st*)malloc(sizeof(struct cert_analy_st));
    	char*cerfile="./1.cer";
	
	int m = tX509_analysis(cerfile,cert_printf_st);
	
	printf("version:%s\n",cert_printf_st->version);
	printf("serialnumber:%s\n",cert_printf_st->serialNumber);
	printf("signature:%s\n",cert_printf_st->signature);
	printf("issuer:   ");
	for(i=0;*(cert_printf_st->issuer_name[i].name)!='\0';i++)
	{
		printf("%s=%s   ",cert_printf_st->issuer_name[i].NID,cert_printf_st->issuer_name[i].name);
	}
	printf("\n");
	printf("validity:\n");
	printf("%d年%02d月%02d日%02d时%02d分%02d秒\n",1900+cert_printf_st->before_time->tm_year,
					cert_printf_st->before_time->tm_mon,cert_printf_st->before_time->tm_mday,
					cert_printf_st->before_time->tm_hour,cert_printf_st->before_time->tm_min,cert_printf_st->before_time->tm_sec);
	printf("%d年%02d月%02d日%02d时%02d分%02d秒\n",1900+cert_printf_st->after_time->tm_year,
					cert_printf_st->after_time->tm_mon,cert_printf_st->after_time->tm_mday,cert_printf_st->after_time->tm_hour,
					cert_printf_st->after_time->tm_min,cert_printf_st->after_time->tm_sec);

	printf("subject:   ");
	for(i=0;*(cert_printf_st->subject_name[i].name)!='\0';i++)
	{
		printf("%s=%s   ",cert_printf_st->subject_name[i].NID,cert_printf_st->subject_name[i].name);
	}
	printf("\n");
	printf("pubkey:\n");
//	printf("%s\n",cert_printf_st->pubkey);
	for(i =0;i<strlen(cert_printf_st->pubkey);i++)
	 printf("%02x",cert_printf_st->pubkey[i]);
       printf("\n");
	printf("signatureValue:\n");
	printf("%s\n",cert_printf_st->signatureValue);
/*	printf("HashValue:\n");
	printf("%s\n",cert_printf_st->HashValue);
*/
	free(cert_printf_st->before_time);
	free(cert_printf_st->after_time);

	free(cert_printf_st);
	return 0;


}
