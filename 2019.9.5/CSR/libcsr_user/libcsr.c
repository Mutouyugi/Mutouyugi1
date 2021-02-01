#include "fdwsf.h"
#include "libcsr.h"

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

        /* '3', '4', '5', '6', '7', '8', '9', ',0x', */
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

void Generat_CSR(unsigned char*countryName,unsigned char*stateOrProvinceName,unsigned char*localityName,
                                            unsigned char*organizationName,unsigned char*organizationalUnitName,unsigned char*commonName,
                                            unsigned char*emailAddress)
{
    int i=0;

    int mark=Device_Init();
	if(mark != SUCCESS)     add_error(Device);

    //version
    unsigned char ver[4]={0X02,0X01,0X00};


    // countryName                  PrintableString
    unsigned int name1_len=0x00;                 
    unsigned char name1[100];            
    name1_len=stringtohex(countryName,name1);
    unsigned char set1[12]={0X31,name1_len+9,0X30,name1_len+7,0X06,0X03,0X55,0X04,0X06,0x13,name1_len};  // 2.5.4.6  

    //stateOrProvinceName                     UTF8String
    unsigned int name2_len=0x00;                 
    unsigned char name2[100];        
    name2_len=stringtohex(stateOrProvinceName,name2);
    unsigned char set2[12]={0X31,name2_len+9,0X30,name2_len+7,0X06,0X03,0X55,0X04,0X08,0x0C,name2_len};

    //localityName                            UTF8String
    unsigned int name3_len=0x00;                 
    unsigned char name3[100];
    name3_len=stringtohex(localityName ,name3);
    unsigned char set3[12]={0X31,name2_len+9,0X30,name2_len+7,0X06,0X03,0X55,0X04,0X07,0x0C,name2_len};

    //organizationName                             UTF8String
    unsigned int name4_len=0x00;                 
    unsigned char name4[100];   
    name4_len=stringtohex(organizationName ,name4);
    unsigned char set4[12]={0X31,name4_len+9,0X30,name4_len+7,0X06,0X03,0X55,0X04,0X0A,0x0C,name4_len};

    //organizationUnitName                          UTF8String
    unsigned int name5_len=0x00;                 
    unsigned char name5[100];
    name5_len=stringtohex(organizationalUnitName ,name5);
    unsigned char set5[12]={0X31,name5_len+9,0X30,name5_len+7,0X06,0X03,0X55,0X04,0X0B,0x0C,name5_len};

    //commonName                              UTF8String
    unsigned int name6_len=0x00;                 
    unsigned char name6[100];
    name6_len=stringtohex(commonName,name6);
    unsigned char set6[12]={0X31,name6_len+9,0X30,name6_len+7,0X06,0X03,0X55,0X04,0X03,0x0C,name6_len};

    //emailAddress             IA5String
    unsigned int name7_len=0x00;                 
    unsigned char name7[100];
    name7_len=stringtohex(emailAddress,name7);
    unsigned char set7[18]={0X31,name7_len+15,0X30,name7_len+13,0x06,0x09,0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x01,0x16,name7_len};
    //pubkey
    unsigned char pub[28]={0x30,0x59,0x30,0x13,0x06,0x07,0x2A,0x86,0x48,0xCE,0x3D,0x02,0x01,
                                                        0x06,0x08,0x2A,0x81,0x1C,0xCF,0x55,0x01,0x82,0x2D,0x03,0x42,0x00,0x04};

                                                       // unsigned char publickey[65]={0xe7,0xf9,0xf0,0x81,0x0a,0x64,0x1a,0xed,0xac,0xf9,0x24,0xc7,0xb8,0xb8,
                                                        //0x5b,0x14,0x39,0x8e,0x96,0x0e,0xf2,0x34,0xa8,0x05,0xbf,0xe0,0x26,0xf5,0xdb,0x5a,0x46,0x1e,0x26,
                                                       // 0xbb,0x5f,0x58,0x23,0x35,0xae,0xb8,0x3a,0x35,0x3c,0xb4,0xe7,0x85,0xf4,0x49,0x71,0x81,0x38,0x6d,
                                                        //0x46,0xb1,0x44,0xc5,0xe2,0xcf,0xee,0x80,0x3f,0xea,0x73,0x31}; 
                           // publickey[64]=0x00;            
    
    unsigned char publickey[65]; 
    publickey[64]=0x00;
    mark=Export_publickey(TRUE, publickey);
    if(mark != SUCCESS)     add_error(Export_publickey);
    

    //attributes
    unsigned char att[3]={0xA0,0x00};

    //subject 
    unsigned  int sub_len=0x00;
    sub_len=name1_len+name2_len+name3_len+name4_len+name5_len+name6_len+name7_len+0x53;
    //cer_info 
    unsigned int csr_info_len=0x00; 
    csr_info_len=sub_len+0x63;

    unsigned char sub[4]={0X30,0X81,sub_len};

    unsigned char csr_info1[4]={0X30,0X81,csr_info_len};
    unsigned char csr_info2[5]={0X30,0X82,0x01,csr_info_len};

    //csr
    unsigned int csr_len = 0x00;
    
    //printf("sub_len,0x    %02x,csr_info_len,0x  %02x\n",sub_len,csr_info_len);
    //csr_info_data  
    unsigned int info_data_len=0x00;
    int j;
    unsigned char info_data[1024];
    if(csr_info_len<=255)
    {
        sprintf(info_data,"%s",csr_info1);
        j=3;
        csr_len=csr_len+3;
        info_data_len=csr_info_len+3;
    }
    else
    {
             info_data_len=csr_info_len+4;
            csr_info_len=csr_info_len-256;
            sprintf(info_data,"%s",csr_info2);
            j=4;
            csr_len=csr_len+4;
    }
    csr_len=csr_len+csr_info_len+0x56;
    csr_len=csr_len-256;
    unsigned char csr[5] = {0X30, 0X82, 0x01, csr_len};
    memcpy(info_data+j,ver,3);
    j=j+3;
    sprintf(info_data+j,"%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s",
                        sub,set1,name1,set2,name2,set3,name3,set4,name4,set5,name5,set6,name6,set7,name7);
     j=j+3+sub_len;
    memcpy(info_data+j,pub,27);
     j=j+27;
   memcpy(info_data+j,publickey,64);
     j=j+64;
    memcpy(info_data+j,att,2);
    j=j+2;
  
    //hash
    unsigned char info_Hash_Data[35];
	unsigned int  info_Hash_Data_len = 32;
    mark=Generate_Hash(info_data, csr_info_len+3, info_Hash_Data,&info_Hash_Data_len, NULL, SGD_SM3);
    if(mark != SUCCESS)     add_error(Generate_Hash);
   
    //sign
    unsigned char info_SignTure[65];
	unsigned int info_SignTure_len = 65;
    Generate_SignData_IntPrikey(info_Hash_Data, info_Hash_Data_len, info_SignTure, &info_SignTure_len);
    if(mark != SUCCESS)     add_error(Generate_SignData_IntPrikey);

    unsigned char Sign_seq[18]={0x30,0x0A,0x06,0x08,0x2A,0x81,0x1C,0xCF,0x55,0x01,0x83,0x75,0x03,0x48,0x00,0x30,0x45};
    unsigned char Sign_x[35]={0x02,0x20};
    memcpy(Sign_x+2,info_SignTure,32);
    unsigned char Sign_y[36]={0x02,0x21,0x00};
    memcpy(Sign_y+3,info_SignTure+32,32);

    //csr
    int k=0;
    unsigned char csr_data[1024];
    memcpy(csr_data,csr,4);
    k=4;
    memcpy(csr_data+k,info_data, info_data_len);
    k=k+info_data_len;
    memcpy(csr_data+k,Sign_seq,17);
    k=k+17;
    memcpy(csr_data+k,Sign_x,34);
    k=k+34;
    memcpy(csr_data+k,Sign_y,35);
    k=k+35;
    unsigned char csr_base64[1024];	
    SC_base64_encode(csr_data,k,csr_base64);
    printf("%s\n",csr_base64);
    int csr_base64len=strlen(csr_base64);
  // char csr_base64[1024] = {0};
       //	int base64_len=base64_encode(csr_data,k,csr_base64);
   
    //save
    unsigned char base64_64[65]={0};
    char  *csr_path="./SM2.csr";
    FILE*fp;
    fp  =  fopen(csr_path,"w+");
    fprintf(fp,"%s\n","-----BEGIN CERTIFICATE REQUEST-----");
    int m=csr_base64len/64;
    int n=csr_base64len%64;
    if(n!=0)
    {
    for(i=0;i<m+1;i++)
    {
	base64_64[64]=0x00;
        memcpy(base64_64,csr_base64+i*64,64);
	fprintf(fp,"%s\n",base64_64);
    }
    }
    else
    {
    for(i=0;i<m;i++)
    {
        base64_64[64]=0x00;
        memcpy(base64_64,csr_base64+i*64,64);
        fprintf(fp,"%s\n",base64_64);
    }
    }

    fprintf(fp,"%s\n","-----END CERTIFICATE REQUEST-----");
  // fp=fopen(csr_path,"wb+");
  // fwrite(csr_data,k,1,fp);
    fclose(fp);
}

int stringtohex(unsigned char*namestring,unsigned char namehex[1024])
{
        int i;
        char c;
        int string_len;
        unsigned int  temp;
        string_len=strlen(namestring);
        for(i=0;i<string_len;i++)
        {
                c=*(namestring+i);

                //sprintf(namehex+i,"%02X",c);
                //printf("%02x\n",namehex[i]);
                namehex[i]=c;
        }
        namehex[i]=0x00;
        return string_len;
}
int SC_base64_encode(unsigned char *ucIn, int inLen, unsigned char *cOut)
{
        if (NULL == ucIn || NULL == cOut || inLen <= 0) {
                return SC_BADPARAMETER;
        }

        int i, j;
        for (i = 0, j = 0; i < inLen; i++) {
                switch (i % 3) {
                        case 0: {
                                cOut[j++] = base64_en_table[ucIn[i] >> 2 & 0x3F];
                                break;
                        }
                        case 1: {
                                cOut[j++] = base64_en_table[((ucIn[i - 1] << 4) & 0x30) + ((ucIn[i] >> 4) & 0x0F)];
                                break;
                        }
                        case 2:{
                                cOut[j++] = base64_en_table[((ucIn[i - 1] << 2) & 0x3C) + ((ucIn[i] >> 6) & 0x03)];
                                cOut[j++] = base64_en_table[ucIn[i] & 0x3F];
                                break;
                        }
                }
        }

        switch (inLen % 3) {
                case 0:{
                        cOut[j] = '\0';
                        break;
                }
                case 1:{       /* Add two zero byte padding */
                        cOut[j++] = base64_en_table[(ucIn[inLen - 1] << 4) & 0x3C];
                        cOut[j++] = '=';
                        cOut[j++] = '=';
                        cOut[j] = '\0';
                        break;
                }
                case 2:{       /* Add one zero byte padding */
                        cOut[j++] = base64_en_table[(ucIn[inLen - 1] << 2) & 0x3C];
                        cOut[j++] = '=';
                        cOut[j] = '\0';
                        break;
                }
        }
        return SC_SUCCESS;

} 
