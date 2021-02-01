#include"certc.h"
int main()
{
	int i;
	int j;
	cert_st  *cert_printf_st = NULL;
	cert_printf_st = (cert_st*)malloc(sizeof(struct cert_analy_st));
	//const char*cerfile = "C:\\Users\\lenovo\\Desktop\\1.cer";
	const char*cerfile = "./1.cer";
	int mark = tX509_analysis(cerfile, cert_printf_st);
	//version
	printf("version:%s\n", cert_printf_st->version);
	//serialnumber
	printf("serialnumber:");
	for (i = 0; i < cert_printf_st->serialNumberlen; i++)
	{
		printf("%02x", cert_printf_st->serialNumber[i]);
	}
	printf("\n");
	//issuername
	printf("issuer:   ");
	for (i = 0; i < cert_printf_st->issuer_name_count; i++)
	{
		printf("%s=", cert_printf_st->issuer_name[i].NID);
		printf("%s	", cert_printf_st->issuer_name[i].name);
	}
	printf("\n");
	//validity
	printf("validity:\n");
	printf("%d年%02d月%02d日%02d时%02d分%02d秒\n", 1900 + cert_printf_st->before_time->tm_year,
		cert_printf_st->before_time->tm_mon, cert_printf_st->before_time->tm_mday,
		cert_printf_st->before_time->tm_hour, cert_printf_st->before_time->tm_min, cert_printf_st->before_time->tm_sec);
	printf("%d年%02d月%02d日%02d时%02d分%02d秒\n", 1900 + cert_printf_st->after_time->tm_year,
		cert_printf_st->after_time->tm_mon, cert_printf_st->after_time->tm_mday, cert_printf_st->after_time->tm_hour,
		cert_printf_st->after_time->tm_min, cert_printf_st->after_time->tm_sec);


	//subjectname
	printf("subject:   ");
	for (i = 0; i < cert_printf_st->subject_name_count; i++)
	{
		printf("%s=", cert_printf_st->subject_name[i].NID);
		printf("%s	", cert_printf_st->subject_name[i].name);
	}
	printf("\n");
	//pubkey
	printf("pubkey:");
	for (j = 0; j < cert_printf_st->pubkeylen; j++)
	{
		printf("%02x", cert_printf_st->pubkey[j]);
	}
	printf("\n");

	//signature
	printf("signature:%s\n", cert_printf_st->signature);
	//signaturevalue
	printf("signaturevalue:");
	for (j = 0; j < cert_printf_st->signatureValuelen; j++)
	{
		printf("%02x", cert_printf_st->signatureValue[j]);
	}
	printf("\n");
	free(cert_printf_st);
	return 0;
}