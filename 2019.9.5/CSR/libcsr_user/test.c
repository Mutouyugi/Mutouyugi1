#include<stdio.h>
#include"libcsr.h"
#include "fdwsf.h"

int main()
{
    unsigned char*m_countryName="CN";
    unsigned char*m_stateOrProvinceName="北京";
    unsigned char*m_localityName="北京";
    unsigned char*m_organizationName="安为";
    unsigned char*m_organizationalUnitName="IT";
    unsigned char*m_commonName="www.anwei.com";
    unsigned char*m_emailAddress ="service@anweitech.com";
    //int mark=Device_Init();
	//if(mark != SUCCESS)     add_error(Device);
    //unsigned char m_publickey[65]={0x2f,0x19,0x58,0x8a,0xdf,0x16,0x46,0xef,0x5b,0x7a,0xe3,0xe4,0x75,0xf3,
				                                                       //  0x19,0x1e,0x11,0xa3,0xe3,0x7c,0x57,0x65,0x90,0x47,0x20,0x22,0x1d,0x65,
                                                                        // 0x53,0xcb,0x9e,0x50,0x42,0x49,0xf2,0x06,0x4c,0xc9,0x97,0x52,0xb1,
                                                                         //0x8d,0x88,0xe1,0x53,0xbc,0x46,0x29,0xfd,0x6e,0x36,0x1b,0xbc,0x22,
                                                                       //  0x05,0x5c,0xb7,0xdd,0x41,0xb4,0x89,0x19,0xaf,0x9f}; 
     //unsigned char m_publickey[65];
     //int mark=Export_publickey(1, m_publickey);
     //m_publickey[64]=0x00;
    //if(mark != SUCCESS)     add_error(Export_publickey);
    Generat_CSR(m_countryName,m_stateOrProvinceName,m_localityName,m_organizationName,m_organizationalUnitName,m_commonName,m_emailAddress);
    return 0;
}
