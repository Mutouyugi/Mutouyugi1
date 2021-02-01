#include"cert.h"

int main ()
{
	int i;
	int indent=4;
    cert_st  *cert_printf_st;
    cert_printf_st=(cert_st*)malloc(sizeof(struct cert_analy_st));
	//memset(cert_printf_st, 0, sizeof(cert_printf_st));
    char*cerfile="./RootCA_SM2.crt";
	//"/home/mutouyugi/Documents/cs/ca.cer"
	unsigned long flags=XN_FLAG_ONELINE;
	tX509_analysis(cerfile,cert_printf_st);
	cert_printf_st->version[2]='\0';
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
	for(i=0;i<64;i++)
	{
		printf("%02x",cert_printf_st->pubkey[i]);
	}
	printf("\n");
	printf("signatureValue:\n");
	printf("%s\n",cert_printf_st->signatureValue);
	//printf("HashValue:\n");
	//printf("%s\n",cert_printf_st->HashValue);
	free(cert_printf_st);
	return 0;
}
