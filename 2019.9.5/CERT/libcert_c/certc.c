#include "certc.h"
static const char base64_en_table[64] = {
		'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
		'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
		'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
		'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
		'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
		'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
		'w', 'x', 'y', 'z', '0', '1', '2', '3',
		'4', '5', '6', '7', '8', '9', '+', '/',
};
/* ASCII order for BASE 64 decode, -1 in unused character */
static const signed char base64_de_table[80] = {
	/* '+', ',', '-', '.', '/', '0', '1', '2', */
		62,  -1,  -1,  -1,  63,  52,  53,  54,

		/* '3', '4', '5', '6', '7', '8', '9', ':', */
			55,  56,  57,  58,  59,  60,  61,  -1,

			/* ';', '<', '=', '>', '?', '@', 'A', 'B', */
				-1,  -1,  0,  -1,  -1,  -1,   0,   1,

				/* 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', */
					 2,   3,   4,   5,   6,   7,   8,   9,

					 /* 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', */
						 10,  11,  12,  13,  14,  15,  16,  17,

						 /* 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', */
							 18,  19,  20,  21,  22,  23,  24,  25,

							 /* '[', '\', ']', '^', '_', '`', 'a', 'b', */
								 -1,  -1,  -1,  -1,  -1,  -1,  26,  27,

								 /* 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', */
									 28,  29,  30,  31,  32,  33,  34,  35,

									 /* 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', */
										 36,  37,  38,  39,  40,  41,  42,  43,

										 /* 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', */
											 44,  45,  46,  47,  48,  49,  50,  51
};

int SC_base64_decode(char *cIn, int *outLen, unsigned char *ucOut)
{
	if (NULL == cIn || NULL == ucOut) {
		return SC_BADPARAMETER;
	}

	int cInLen = strlen(cIn);

	/* check char input validty(must be in 64 specified characters). */
	int i = 0;
	while ((i < cInLen) && SC_base64_de_isCharValid(cIn[i])) {
		i++;
	}

	int j;
	for (i = 0, j = 0; i < cInLen; i += 4) {
		int index0 = base64_de_table[cIn[i + 0] - '+'];
		int index1 = base64_de_table[cIn[i + 1] - '+'];
		int index2 = base64_de_table[cIn[i + 2] - '+'];
		int index3 = base64_de_table[cIn[i + 3] - '+'];

		ucOut[j++] = ((index0 << 2) & 0xFC) + ((index1 >> 4) & 0x03);
		if ('=' != cIn[i + 2]) {
			ucOut[j++] = ((index1 << 4) & 0xF0) + ((index2 >> 2) & 0x0F);
		}
		if ('=' != cIn[i + 3]) {
			ucOut[j++] = ((index2 << 6) & 0xC0) + ((index3 >> 0) & 0x3F);
		}
	}

	if (NULL != outLen) {
		*outLen = j;
	}

	return SC_SUCCESS;
}


int tX509_analysis(const char *cert, cert_st *cert_verify_st)
{
	//cert_verify_st = (cert_st*)malloc(sizeof(struct cert_analy_st));
	FILE *fp;
	int i = 0, j, k = 0;
	char str[32][67];
	char cert_base64[1024] = { 0 };
	fp = fopen(cert, "rt");
	if (fp == NULL)
		return -1;
	while (fgets(str[i], 66, fp) != NULL)
		i = i + 1;
	for (j = 1; j < i - 1; j++)
	{
		memcpy(cert_base64 + k, str[j], 64);
		k = k + 64;
	}
	int outLen = 0;
	unsigned char cert_hex[1024] = { 0 };
	int rv = SC_base64_decode(cert_base64, &outLen, cert_hex);

	//version
	for (i = 0; i < outLen; i++)
	{
		int ver;
		if (cert_hex[i] == 0xa0 && cert_hex[i + 1] == 0x03)
		{
			ver = cert_hex[i + 4];
			switch (ver)
			{
			case 0:		//V1
				memcpy(cert_verify_st->version, "V1", 2);
				break;
			case 1:		//V2
				memcpy(cert_verify_st->version, "V2", 2);
				break;
			case 2:		//V3
				memcpy(cert_verify_st->version, "V3", 2);
				break;
			default:
				memcpy(cert_verify_st->version, "NO", 2);
				break;
			}
			cert_verify_st->version[2] = '\0';
			break;
		}
	}
	i = i + 4;

	//serialnumber
	cert_verify_st->serialNumberlen = cert_hex[i + 2];
	memcpy(cert_verify_st->serialNumber, cert_hex + i + 3, cert_verify_st->serialNumberlen);
	cert_verify_st->serialNumber[cert_verify_st->serialNumberlen] = '\0';
	i = i + 3 + cert_verify_st->serialNumberlen;
	//signature
	if (cert_hex[i + 4] == 0x2A && cert_hex[i + 5] == 0x81 && cert_hex[i + 6] == 0x1c && cert_hex[i + 7] == 0xcf
		&& cert_hex[i + 8] == 0x55 && cert_hex[i + 9] == 0x01 && cert_hex[i + 10] == 0x83 && cert_hex[i + 11] == 0x75)
	{
		memcpy(cert_verify_st->signature, "1.2.156.10197.1.501", 19);
		cert_verify_st->signature[19] = '\0';
	}
	else
	{
		memcpy(cert_verify_st->signature, "nosm2withsm3", 12);
		cert_verify_st->signature[12] = '\0';
		/*
		cert_verify_st->signaturelen= cert_hex[i + 3];
		memcpy(cert_verify_st->signature,cert_hex+i+4,cert_verify_st->signaturelen);
		cert_verify_st->signature[cert_verify_st->signaturelen] = '\0';*/
	}
	//issuername
	int namelen = 0;
	k = 0;
	for (i = i; i < outLen; i++)
	{
		if (cert_hex[i] == 0x06 && cert_hex[i + 1] == 0x03 && cert_hex[i + 2] == 0x55 && cert_hex[i + 3] == 0x04)
		{
			int i_NID = cert_hex[i + 4];
			namelen = cert_hex[i + 6];
			switch (i_NID)
			{
			case 3:		//CN
				memcpy(cert_verify_st->issuer_name[k].NID, "CN", 2);
				cert_verify_st->issuer_name[k].NID[2] = '\0';
				memcpy(cert_verify_st->issuer_name[k].name, cert_hex + i + 7, namelen);
				cert_verify_st->issuer_name[k].name[namelen] = '\0';
				k++;
				break;
			case 6:		//C
				memcpy(cert_verify_st->issuer_name[k].NID, "C", 1);
				cert_verify_st->issuer_name[k].NID[1] = '\0';
				memcpy(cert_verify_st->issuer_name[k].name, cert_hex + i + 7, namelen);
				cert_verify_st->issuer_name[k].name[namelen] = '\0';
				k++;
				break;
			case 7:		//L
				memcpy(cert_verify_st->issuer_name[k].NID, "L", 1);
				cert_verify_st->issuer_name[k].NID[1] = '\0';
				memcpy(cert_verify_st->issuer_name[k].name, cert_hex + i + 7, namelen);
				cert_verify_st->issuer_name[k].name[namelen] = '\0';
				k++;
				break;
			case 8:		//S
				memcpy(cert_verify_st->issuer_name[k].NID, "S", 1);
				cert_verify_st->issuer_name[k].NID[1] = '\0';
				memcpy(cert_verify_st->issuer_name[k].name, cert_hex + i + 7, namelen);
				cert_verify_st->issuer_name[k].name[namelen] = '\0';
				k++;
				break;
			case 10:		//O
				memcpy(cert_verify_st->issuer_name[k].NID, "O", 1);
				cert_verify_st->issuer_name[k].NID[1] = '\0';
				memcpy(cert_verify_st->issuer_name[k].name, cert_hex + i + 7, namelen);
				cert_verify_st->issuer_name[k].name[namelen] = '\0';
				k++;
				break;
			case 11:		//OU
				memcpy(cert_verify_st->issuer_name[k].NID, "OU", 2);
				cert_verify_st->issuer_name[k].NID[2] = '\0';
				memcpy(cert_verify_st->issuer_name[k].name, cert_hex + i + 7, namelen);
				cert_verify_st->issuer_name[k].name[namelen] = '\0';
				k++;
				break;
			default:
				memcpy(cert_verify_st->issuer_name[k].NID, "NO", 2);
				cert_verify_st->issuer_name[k].NID[2] = '\0';
				memcpy(cert_verify_st->issuer_name[k].name, cert_hex + i + 7, namelen);
				cert_verify_st->issuer_name[k].name[namelen] = '\0';
				k++;
				break;
			}
		}
		else if (cert_hex[i] == 0x06 && cert_hex[i + 1] == 0x09 && cert_hex[i + 2] == 0x2A && cert_hex[i + 3] == 0x86 && cert_hex[i + 4] == 0x48)
		{
			namelen = cert_hex[i + 12];
			memcpy(cert_verify_st->issuer_name[k].NID, "E", 1);
			cert_verify_st->issuer_name[k].NID[1] = '\0';
			memcpy(cert_verify_st->issuer_name[k].name, cert_hex + i + 13, namelen);
			cert_verify_st->issuer_name[k].name[namelen] = '\0';
			k++;
		}
		//time
		if (cert_hex[i] == 0x17 && cert_hex[i + 1] == 0x0D && cert_hex[i + 14] == 0x5A)
		{
			//起始时间
			cert_verify_st->before_time=malloc(sizeof( struct tm));
			cert_verify_st->before_time->tm_year = 100 + (cert_hex[i + 2] - '0') * 10 + (cert_hex[i + 3] - '0');
			cert_verify_st->before_time->tm_mon = (cert_hex[i + 4] - '0') * 10 + (cert_hex[i + 5] - '0');
			cert_verify_st->before_time->tm_mday = (cert_hex[i + 6] - '0') * 10 + (cert_hex[i + 7] - '0');
			cert_verify_st->before_time->tm_hour = 8 + (cert_hex[i + 8] - '0') * 10 + (cert_hex[i + 9] - '0');
			cert_verify_st->before_time->tm_min = (cert_hex[i + 10] - '0') * 10 + (cert_hex[i + 11] - '0');
			cert_verify_st->before_time->tm_sec = (cert_hex[i + 12] - '0') * 10 + (cert_hex[i + 13] - '0');
			//终止时间
			cert_verify_st->after_time=malloc(sizeof( struct tm));
			cert_verify_st->after_time->tm_year = 100 + (cert_hex[i + 17] - '0') * 10 + (cert_hex[i + 18] - '0');
			cert_verify_st->after_time->tm_mon = (cert_hex[i + 19] - '0') * 10 + (cert_hex[i + 20] - '0');
			cert_verify_st->after_time->tm_mday = (cert_hex[i + 21] - '0') * 10 + (cert_hex[i + 22] - '0');
			cert_verify_st->after_time->tm_hour = 8 + (cert_hex[i + 23] - '0') * 10 + (cert_hex[i + 24] - '0');
			cert_verify_st->after_time->tm_min = (cert_hex[i + 25] - '0') * 10 + (cert_hex[i + 26] - '0');
			cert_verify_st->after_time->tm_sec = (cert_hex[i + 27] - '0') * 10 + (cert_hex[i + 28] - '0');
			break;
		}
	}
	i = i + 29;
	cert_verify_st->issuer_name_count = k;

	//subjectname
	k = 0;
	for (i = i; i < outLen; i++)
	{
		if (cert_hex[i] == 0x06 && cert_hex[i + 1] == 0x03 && cert_hex[i + 2] == 0x55 && cert_hex[i + 3] == 0x04)
		{
			int i_NID = cert_hex[i + 4];
			namelen = cert_hex[i + 6];
			switch (i_NID)
			{
			case 3:		//CN
				memcpy(cert_verify_st->subject_name[k].NID, "CN", 2);
				cert_verify_st->subject_name[k].NID[2] = '\0';
				memcpy(cert_verify_st->subject_name[k].name, cert_hex + i + 7, namelen);
				cert_verify_st->subject_name[k].name[namelen] = '\0';
				k++;
				break;
			case 6:		//C
				memcpy(cert_verify_st->subject_name[k].NID, "C", 1);
				cert_verify_st->subject_name[k].NID[1] = '\0';
				memcpy(cert_verify_st->subject_name[k].name, cert_hex + i + 7, namelen);
				cert_verify_st->subject_name[k].name[namelen] = '\0';
				k++;
				break;
			case 7:		//L
				memcpy(cert_verify_st->subject_name[k].NID, "L", 1);
				cert_verify_st->subject_name[k].NID[1] = '\0';
				memcpy(cert_verify_st->subject_name[k].name, cert_hex + i + 7, namelen);
				cert_verify_st->subject_name[k].name[namelen] = '\0';
				k++;
				break;
			case 8:		//S
				memcpy(cert_verify_st->subject_name[k].NID, "S", 1);
				cert_verify_st->subject_name[k].NID[1] = '\0';
				memcpy(cert_verify_st->subject_name[k].name, cert_hex + i + 7, namelen);
				cert_verify_st->subject_name[k].name[namelen] = '\0';
				k++;
				break;
			case 10:		//O
				memcpy(cert_verify_st->subject_name[k].NID, "O", 1);
				cert_verify_st->subject_name[k].NID[1] = '\0';
				memcpy(cert_verify_st->subject_name[k].name, cert_hex + i + 7, namelen);
				cert_verify_st->subject_name[k].name[namelen] = '\0';
				k++;
				break;
			case 11:		//OU
				memcpy(cert_verify_st->subject_name[k].NID, "OU", 2);
				cert_verify_st->subject_name[k].NID[2] = '\0';
				memcpy(cert_verify_st->subject_name[k].name, cert_hex + i + 7, namelen);
				cert_verify_st->subject_name[k].name[namelen] = '\0';
				k++;
				break;
			default:
				memcpy(cert_verify_st->subject_name[k].NID, "NO", 2);
				cert_verify_st->subject_name[k].NID[2] = '\0';
				memcpy(cert_verify_st->subject_name[k].name, cert_hex + i + 7, namelen);
				cert_verify_st->subject_name[k].name[namelen] = '\0';
				k++;
				break;
			}
		}
		else if (cert_hex[i] == 0x06 && cert_hex[i + 1] == 0x09 && cert_hex[i + 2] == 0x2A && cert_hex[i + 3] == 0x86 && cert_hex[i + 4] == 0x48)
		{
			namelen = cert_hex[i + 12];
			memcpy(cert_verify_st->subject_name[k].NID, "E", 1);
			cert_verify_st->subject_name[k].NID[1] = '\0';
			memcpy(cert_verify_st->subject_name[k].name, cert_hex + i + 13, namelen);
			cert_verify_st->subject_name[k].name[namelen] = '\0';
			k++;
		}
	}
	cert_verify_st->subject_name_count = k;
	//pubkey
	for (i = 0; i < outLen; i++)
	{
		if (cert_hex[i] == 0x03 && cert_hex[i + 1] == 0x42 && cert_hex[i + 2] == 0x00 && cert_hex[i + 3] == 0x04)
		{
			cert_verify_st->pubkeylen = cert_hex[i + 1] - 1;
			memcpy(cert_verify_st->pubkey, cert_hex + i + 3, cert_verify_st->pubkeylen);
			cert_verify_st->pubkey[cert_verify_st->pubkeylen] = '\0';
			break;
		}
	}
	//signatureValue
	for (i = i + cert_verify_st->pubkeylen; i < outLen; i++)
	{
		if (cert_hex[i] == 0x03 && cert_hex[i + 2] == 0x00 && cert_hex[i + 3] == 0x30 && cert_hex[i + 5] == 0x02)
		{
			cert_verify_st->signatureValuelen = cert_hex[i + 4] + 2;
			memcpy(cert_verify_st->signatureValue, cert_hex + i + 3, cert_verify_st->signatureValuelen);
			cert_verify_st->signatureValue[cert_verify_st->signatureValuelen] = '\0';
			break;
		}
	}
	return 0;
}


