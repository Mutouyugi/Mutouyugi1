#include<stdio.h>
#include"libcsr.h"
#include "fdwsf.h"

int main()
{    
    unsigned char*m_commonName="34020000001320000001_1717012015090175153911";
    unsigned char*m_Networktype="02";
    unsigned char*m_localityName="0107";
    unsigned char*m_stateOrProvinceName="11";
    unsigned char*m_countryName="CN";
    Generat_CSR(m_commonName,m_Networktype,m_localityName,m_stateOrProvinceName,m_countryName );
    return 0;
}
