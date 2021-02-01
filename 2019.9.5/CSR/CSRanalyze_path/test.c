#include"csranay.h"
int main()
{
    int i=0;
    char*csrfile="-----BEGIN CERTIFICATE REQUEST-----\n"
                              "MIIBTDCB8wIBADCBkDELMAkGA1UEBhMCQ04xEDAOBgNVBAgMB0JlaWppbmcxEDAO\n"
                              "BgNVBAcMB0JlaWppbmcxDjAMBgNVBAoMBUFud2VpMQswCQYDVQQLDAJJVDEaMBgG\n"
                                "A1UEAwwRd3d3LmFud2VpdGVjaC5jb20xJDAiBgkqhkiG9w0BCQEWFXNlcnZpY2VA\n"
                                "YW53ZWl0ZWNoLmNvbTBZMBMGByqGSM49AgEGCCqBHM9VAYItA0IABAIanKEywl0d\n"
                                "E1KJYPEnI6UC6bv5L4mamsrHlPRsrchVIQuT73M7fFAkc6Pc23A+si+oOiKyc1/E\n"
                                "rhLzbTAQTF2gADAKBggqgRzPVQGDdQNIADBFAiDjrukktLntTqNqE0ouCx2g1N3j\n"
                                "tcYLqKMPuHjKd2OBrwIhAHPOPeuv+5Nx81EgnS0ijVH02BgB6T8I2gtPMmtrRHpH\n"
                                "-----END CERTIFICATE REQUEST-----";
	printf("%s\n",req_analysis(csrfile));
    /*
    printf("Name:\n");
    for(i=0;*(req_printf_st->info_name[i].name)!='\0';i++)
	{
		printf("%s=%s   ",req_printf_st->info_name[i].NID,req_printf_st->info_name[i].name);
	}
	printf("\n");
    printf("pubkey:\n");
    printf("%s\n",req_printf_st->pubkey);
    */
}