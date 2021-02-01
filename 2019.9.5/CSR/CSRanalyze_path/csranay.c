#include"csranay.h"
char *req_analysis(char *cert)
{
       static unsigned char csrdata[4096];
        X509_REQ *m_req=X509_REQ_new();	   
         int i=0,j=0;
        unsigned char *pTmp = NULL;
        pTmp =  cert;
	    unsigned long derRooCertLen=strlen(cert);
	    m_req = d2i_X509_REQ(NULL,(unsigned const char **)&pTmp,derRooCertLen);
	    if( NULL ==m_req)
        {
            //base64编码格式证书转X509结构体
            size_t certLen = strlen(cert);
            BIO* certBio = BIO_new(BIO_s_mem());
            BIO_write(certBio, cert, certLen);
            m_req = PEM_read_bio_X509_REQ(certBio, NULL, NULL, NULL);
            if(m_req==NULL)
             {
                     return NULL;
            }
        }

        //info_name
        X509_NAME *infoname=X509_NAME_new();
        X509_NAME_ENTRY *infoname_entry;
        ASN1_STRING *infoname_asni;
        const ASN1_OBJECT *infoname_name;
        const char *infoname_str_name;
        int i_NID;
       infoname = X509_REQ_get_subject_name(m_req);
        for (i = 0; i < X509_NAME_entry_count(infoname); i++) 
        {
               infoname_entry=X509_NAME_get_entry(infoname,i);
                infoname_asni=X509_NAME_ENTRY_get_data(infoname_entry);
                infoname_str_name=ASN1_STRING_get0_data(infoname_asni);
                infoname_name=X509_NAME_ENTRY_get_object(infoname_entry);
                i_NID=OBJ_obj2nid(infoname_name);
                switch(i_NID)
                {
                    case	13:       memcpy(csrdata+j, "CN=", 3);	j=j+3;	break;
                    case	14:       memcpy(csrdata+j, "C=", 2);		j=j+2;		break;
                    case	15:       memcpy(csrdata+j, "L=", 2);		j=j+2;	break;
                    case	16:       memcpy(csrdata+j, "S=", 2);		j=j+2;	break;
                    case	17:       memcpy(csrdata+j, "O=", 2);			j=j+2;	break;
                    case	18:       memcpy(csrdata+j , "OU=", 3);			j=j+3;	break;
                    case	48:       memcpy(csrdata+j, "E=", 2);		j=j+2;		break;
                    default:		  memcpy(csrdata+j , "unknow=", 7);     	j=j+7;
                }
                 memcpy(csrdata+j ,infoname_str_name, strlen(infoname_str_name));
                 csrdata[j+strlen(infoname_str_name)]=';';
                 j=j+strlen(infoname_str_name)+1;
        }
        //pubkey
        char *key_value;
        BIGNUM *ret=BN_new();
        X509_PUBKEY *reqkey=X509_PUBKEY_new();
       ASN1_BIT_STRING*pubkey_asn1_string;
        reqkey=X509_REQ_get_X509_PUBKEY(m_req);
        pubkey_asn1_string=reqkey->public_key;
        BN_bin2bn( pubkey_asn1_string->data, pubkey_asn1_string->length,ret);
        key_value=BN_bn2hex(ret);
        memcpy(csrdata+j,key_value,strlen(key_value));
        csrdata[j+strlen(key_value)]='\0';
        X509_NAME_free(infoname);
        BN_free(ret);
        X509_PUBKEY_free(reqkey);
        free(m_req);
        return csrdata;
}

