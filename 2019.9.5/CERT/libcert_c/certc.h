#include<stdio.h>
#include <stdlib.h>
#include<string.h>
#include <time.h>
#include<stdint.h>

#ifndef SC_BASE64_H_
#define SC_BASE64_H_

#ifndef __SC_MACRO
#define __SC_MACRO

#define SC_SUCCESS 		 1
#define SC_FAILED		-1
#define SC_NOMEM		-2
#define SC_BADPARAMETER	-3
#define SC_SYNTAXERROR	-4
#define SC_RTNULL		-5		/* function returns NULL */
#define SC_ERROR		-6

#endif

typedef struct	cert_analy_st {
	unsigned char	version[2];
	int		serialNumberlen;	unsigned char 	serialNumber[128];
	unsigned char    signature[128];
	struct stu
	{
		unsigned char 	NID[8];
		unsigned char	name[512];
	}issuer_name[64], subject_name[64];
	int issuer_name_count;
	int subject_name_count;
	struct tm*before_time;
	struct tm*after_time;
	int	pubkeylen;	 unsigned char pubkey[1280];
	int	signatureValuelen;	 unsigned char signatureValue[1280];
}cert_st;
/*
 * Make sure input character is valid (must be in 64 specified characters).
 *
 * @param character		:input length when deconding.
 */
#define SC_base64_de_isCharValid(character)	(('+' <= character) && (character <= 'z') && (base64_de_table[character - '+'] != -1))
int tX509_analysis(const char *cert, cert_st *cert_verify_st);
int SC_base64_decode(char *cIn, int *outLen, unsigned char *ucOut);

#endif