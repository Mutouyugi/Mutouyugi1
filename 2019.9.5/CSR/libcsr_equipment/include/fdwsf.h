#ifndef SMDLL_H
#define SMDLL_H

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>


#define MAX_PATH            260

#ifndef TRUE
#define TRUE	0x00000001
#endif
#ifndef FALSE
#define FALSE	0x00000000
#endif


#ifdef WIN32
#include <Windows.h>
#define DEVAPI __stdcall
#define WINAPI __stdcall
#else
#define __stdcall
#define _stdcall
#define DEVAPI __attribute__ ((visibility ("default")))
#define WINAPI __attribute__ ((visibility ("default")))
#endif

//the unit is millisecond in windows and microsecond in linux
#ifndef WIN32
#define Sleep(t) usleep(t*1000)
#endif


#define __declspec(x)  
#define __cdecl 
#define max(a,b)            (((a) > (b)) ? (a) : (b))
#define min(a,b)            (((a) < (b)) ? (a) : (b))

#define IN
#define OUT

typedef void* HANDLE;
typedef HANDLE DEVHANDLE;
typedef HANDLE HAPPLICATION;
typedef HANDLE HCONTAINER;

#define SAR_OK							0X00000000
#define SAR_FAIL						0X0A000001
#define SAR_UNKNOWNERR					0X0A000002
#define SAR_NOTSUPPORTYETERR			0X0A000003
#define SAR_FILEERR						0X0A000004
#define SAR_INVALIDHANDLEERR			0X0A000005
#define SAR_INVALIDPARAMERR				0X0A000006
#define SAR_READFILEERR					0X0A000007
#define SAR_WRITEFILEERR				0X0A000008
#define SAR_NAMELENERR					0X0A000009
#define SAR_KEYUSAGEERR					0X0A00000A
#define SAR_MODULUSLENERR				0X0A00000B
#define SAR_NOTINITIALIZEERR			0X0A00000C
#define SAR_OBJERR						0X0A00000D
#define SAR_MEMORYERR					0X0A00000E
#define SAR_TIMEOUTERR					0X0A00000F
#define SAR_INDATALENERR				0X0A000010
#define SAR_INDATAERR					0X0A000011
#define SAR_GENRANDERR					0X0A000012
#define SAR_HASHOBJERR					0X0A000013
#define SAR_HASHERR						0X0A000014
#define SAR_GENRSAKEYERR				0X0A000015
#define SAR_RSAMODULUSLENERR			0X0A000016
#define SAR_CSPIMPRTPUBKEYERR			0X0A000017
#define SAR_RSAENCERR					0X0A000018
#define SAR_RSADECERR					0X0A000019
#define SAR_HASHNOTEQUALERR				0X0A00001A
#define SAR_KEYNOTFOUNTERR				0X0A00001B
#define SAR_CERTNOTFOUNTERR				0X0A00001C
#define SAR_NOTEXPORTERR				0X0A00001D
#define SAR_DECRYPTPADERR				0X0A00001E
#define SAR_MACLENERR					0X0A00001F
#define SAR_BUFFER_TOO_SMALL			0X0A000020
#define SAR_KEYINFOTYPEERR				0X0A000021
#define SAR_NOT_EVENTERR				0X0A000022
#define SAR_DEVICE_REMOVED				0X0A000023
#define SAR_PIN_INCORRECT				0X0A000024
#define SAR_PIN_LOCKED					0X0A000025
#define SAR_PIN_INVALID					0X0A000026
#define SAR_PIN_LEN_RANGE				0X0A000027
#define SAR_USER_ALREADY_LOGGED_IN		0X0A000028
#define SAR_USER_PIN_NOT_INITIALIZED	0X0A000029
#define SAR_USER_TYPE_INVALID			0X0A00002A
#define SAR_APPLICATION_NAME_INVALID	0X0A00002B
#define SAR_APPLICATION_EXISTS			0X0A00002C
#define SAR_USER_NOT_LOGGED_IN			0X0A00002D
#define SAR_APPLICATION_NOT_EXISTS		0X0A00002E
#define SAR_FILE_ALREADY_EXIST			0X0A00002F
#define SAR_NO_ROOM						0X0A000030
#define SAR_FILE_NOT_EXIST				0x0A000031
#define SAR_REACH_MAX_CONTAINER_COUNT	0x0A000032
#define SAR_AUTH_BLOCKED				0x0A000033
#define SAR_CERTNOUSAGEERR				0x0A000034
#define SAR_INVALIDCONTAINERERR			0x0A000035
#define SAR_CONTAINER_NOT_EXISTS		0X0A000036
#define SAR_CONTAINER_EXISTS			0X0A000037
#define	SAR_CERTUSAGEERR				0x0A000038
#define SAR_KEYNOUSAGEERR				0x0A000039
#define SAR_FILEATTRIBUTEERR			0x0A00003A
#define SAR_DEVNOAUTH					0x0A00003B
#define SAR_PLEASE_INSERT_SD_AGAIN		0x0A00003C
#define SAR_APP_IS_NOT_ACTIVE			0x0A00003D
#define SAR_APP_IS_OPENED				0x0A00003E

#define SAR_FW_DATA_FORMAT_INVALID		0x0A000040
#define SAR_FW_SIGNATURE_INVALID		0x0A000041

#define RANDOMLENGTH  16
#define	VKEYLENGTH    128
#define ECCPRIVATEKEYBITLENGTH 256
#define ECCPRIVATEKEYLENGTH 32

enum PerformanceAlgType
{
	P_AlG_SM1,
	P_AlG_SM4,
	P_AlG_DES,
	P_AlG_DES3_2Key,
	P_AlG_DES3_3Key,
	P_AlG_AES128,
	P_AlG_AES192,
	P_AlG_AES256
};

enum PerformanceAlgMode
{
	P_AlG_ECB,
	P_AlG_CBC,
	P_AlG_CFB,
	P_AlG_OFB
};

#define SECURE_NEVER_ACCOUNT	0x00000000
#define	 SECURE_ADM_ACCOUNT		0x00000001
#define SECURE_USER_ACCOUNT		0x00000010
#define SECURE_ANYONE_ACCOUNT	0x000000FF


// 设备状�?
#define DEV_ABSENT_STATE     0x00000000			//设备不存�?
#define DEV_PRESENT_STATE	0x00000001			//设备存在
#define DEV_UNKNOW_STATE	0x00000002			//设备状态未�?

// PIN用户类型
#define ADMIN_TYPE	0
#define USER_TYPE   1

//非对�?
#define SGD_SM2_1	0x00020100			// 椭圆曲线签名算法
#define SGD_SM2_2	0x00020200			// 椭圆曲线密钥交换协议
#define SGD_SM2_3	0x00020400			// 椭圆曲线加密算法

//杂凑算法标志
#define SGD_SM3		0x00000001

#define SKF_USE_ENCDEC	0x01  //用于加密解密
#define SKF_USE_SIGVER	0x02  //用于签名验证

#define SGD_SM1_ECB     0x00000101
#define SGD_SM1_CBC     0x00000102
#define SGD_SM1_CFB     0x00000104
#define SGD_SM1_OFB     0x00000108
#define SGD_SM1_MAC     0x00000110

#define SGD_SMS4_ECB    0x00000401
#define SGD_SMS4_CBC    0x00000402
#define SGD_SMS4_CFB    0x00000404
#define SGD_SMS4_OFB    0x00000408

#define MAX_RSA_MODULUS_LEN				256
#define MAX_RSA_EXPONENT_LEN			4
#define ECC_MAX_XCOORDINATE_BITS_LEN	512
#define ECC_MAX_YCOORDINATE_BITS_LEN	512
#define ECC_MAX_MODULUS_BITS_LEN		512
#define MAX_IV_LEN						32

extern HANDLE hDev;
extern HCONTAINER hContainer;
extern HAPPLICATION hApplication;

// 版本
typedef struct Struct_Version{
unsigned char major;
unsigned char minor;
}VERSION;

// 设备信息
typedef struct Struct_DEVINFO{
VERSION		Version;			// 版本�? 设置�?.0
unsigned char		Manufacturer[64];	        // 设备厂商信息, �?\0'为结束符的ASCII字符�?
unsigned char		Issuer[64];			// 发行厂商信息, �?\0'为结束符的ASCII字符�?
unsigned char		Label[32];			// 设备标签, �?\0'为结束符的ASCII字符�?
unsigned char		SerialNumber[32];	        // 序列�? �?\0'为结束符的ASCII字符�?
VERSION		HWVersion;			// 设备硬件版本
VERSION		FirmwareVersion;		// 设备本身固件版本
unsigned int		AlgSymCap;			// 分组密码算法标识
unsigned int		AlgAsymCap;			// 非对称密码算法标�?
unsigned int		AlgHashCap;			// 密码杂凑算法标识
unsigned int		DevAuthAlgId;			// 设备认证的分组密码算法标�?
unsigned int		TotalSpace;			// 设备总空间大�?
unsigned int		FreeSpace;			// 用户可用空间大小
unsigned int		MaxECCBufferSize;		// 能够处理的ECC加密数据大小
unsigned int		MaxBufferSize;      		// 能够处理的分组运算和杂凑运算的数据大�?
unsigned char		Reserved[64];			// 保留扩展
}DEVINFO, *PDEVINFO;


// ECC公钥数据结构
typedef struct Struct_ECCPUBLICKEYBLOB{
unsigned int BitLen;					  // 模数的实际位长度, 必须�?的倍数
unsigned char XCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN/8]; // 曲线上点的X坐标
unsigned char YCoordinate[ECC_MAX_YCOORDINATE_BITS_LEN/8]; // 曲线上点的Y坐标
}ECCPUBLICKEYBLOB, *PECCPUBLICKEYBLOB;

// ECC私钥数据结构
typedef struct Struct_ECCPRIVATEKEYBLOB{
unsigned int BitLen;					// 模数的实际位长度, 必须�?的倍数
unsigned char PrivateKey[ECC_MAX_MODULUS_BITS_LEN/8];	// 私有密钥
}ECCPRIVATEKEYBLOB, *PECCPRIVATEKEYBLOB;


// ECC密文数据结构
typedef struct Struct_ECCCIPHERBLOB{
unsigned char XCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN/8];
unsigned char YCoordinate[ECC_MAX_XCOORDINATE_BITS_LEN/8];
unsigned char HASH[32];				// 明文的杂凑�?
unsigned int CipherLen;			// 密文数据长度
unsigned char Cipher[1];				// 密文数据
} ECCCIPHERBLOB, *PECCCIPHERBLOB;

// ECC签名数据结构
typedef struct Struct_ECCSIGNATUREBLOB{
unsigned char r[ECC_MAX_XCOORDINATE_BITS_LEN/8];		// 签名结构R部分
unsigned char s[ECC_MAX_XCOORDINATE_BITS_LEN/8];		// 签名结构S部分
} ECCSIGNATUREBLOB, *PECCSIGNATUREBLOB;

// 分组密码参数
typedef struct Struct_BLOCKCIPHERPARAM{
unsigned char IV[MAX_IV_LEN];				// 初始向量IV
unsigned int IVLen;					// 初始向量的实际长�?
unsigned int PaddingType;				// 填充方式, 0表示不填�? 1表示按照PKCS#5方式进行填充
unsigned int FeedBitLen;				// 反馈值的位长�?按位计算),只针对OFB、CFB
} BLOCKCIPHERPARAM, *PBLOCKCIPHERPARAM;

// ECC加密密钥对保护结�?
typedef struct SKF_ENVELOPEDKEYBLOB{
unsigned int Version;					// 当前版本�?1
unsigned int ulSymmAlgID;				// 对称算法标识，限定ECB模式
unsigned int ulBits;					// 加密密钥对的密钥位长�?
unsigned char cbEncryptedPriKey[64];			// 加密密钥对私钥的密文
ECCPUBLICKEYBLOB PubKey;				// 加密密钥对的公钥
ECCCIPHERBLOB ECCCipherBlob;			// 用保护公钥加密的对称密钥密文�?
}ENVELOPEDKEYBLOB, *PENVELOPEDKEYBLOB;

typedef struct Struct_FILEATTRIBUTE{
unsigned char FileName[32];
unsigned int FileSize;
unsigned int ReadRights;
unsigned int WriteRights;
} FILEATTRIBUTE, *PFILEATTRIBUTE;


#ifdef __cplusplus
extern "C" {
#endif

/*
 *	方法描述：
 *		设备初始化
 *	参数描述:
 *		无
 *	返回值:
 *		成功返回0，失败返回错误码
 */
unsigned int DEVAPI Device_Init();

/*
 *	方法描述：
 *		解锁设备用户PIN,并重置用户PIN码
 *	参数描述:
 *		[I N]*AdminPin: 管理PIN码
 *		[I N]*NewUserPIN: 新用户PIN码
 *		[OUT]*RetryCount: 剩余重试次数
 *	返回值:
 *		成功返回0，失败返回错误码
 */
unsigned int Unlock_Application_PIN(unsigned char* AdminPin, unsigned char* NewUserPIN, unsigned int* RetryCount);

/*
 *	方法描述：
 *		修改用户PIN码
 *	参数描述:
 *		[I N]*old: 旧密码
 *		[I N]*new: 新密码
 *		[OUT]*RetryCount: 剩余重试次数
 *	返回值:
 *		成功返回0，失败返回错误码
 */
unsigned int Change_Application_PIN(unsigned char* old,unsigned char* new, unsigned int* RetryCount);

/*
 *	方法描述：
 *		验证PIN码有效性
 *	参数描述:
 *		[I N]*PIN: PIN码
 *		[OUT]*RetryCount: 剩余重试次数
 *	返回值:
 *		成功返回0，失败返回错误码	
 */
unsigned int Verify_Application_PIN(unsigned char* PIN,unsigned int* RetryCount);

/*
 *	方法描述：
 *		生成哈希值
 *	参数描述:
 *		[I N]*Source_Data: 待哈希数据
 *		[I N]Source_Data_Len: 待哈希数据长度
 *		[OUT]*Hash_Data: 生成的32字节哈希值
 *		[I N|OUT]*Hash_Data_Len: 输入时为Hash_Data缓冲区大小，输出时为Hash_Data长度
 *		[I N]*EccPublickey: 带公钥时为64字节公钥明文,不带公钥时为NULL
 *		[I N]Hash_Type: 使用的HASH算法，该版本支持SM3(对应SGD_SM3)
 *	返回值:
 *		成功返回0，失败返回错误码
 */
unsigned int DEVAPI Generate_Hash(unsigned char* Source_Data, unsigned int Source_Data_Len, unsigned char* Hash_Data, unsigned int *Hash_Data_Len, unsigned char* EccPublickey, unsigned int Hash_Type);

/*
 *	方法描述：
 *		生成随机数
 *	参数描述:
 *		[OUT]*ucRandom: 生成随机数
 *		[I N]ulRandomLen: 生成随机数长度
 *	返回值:
 *		成功返回0，失败返回错误码
 */
unsigned int DEVAPI Generate_Rand(unsigned char* ucRandom, unsigned int ulRandomLen);


/*
 *	方法描述：
 *		内部私钥签名函数
 *	参数描述:
 *		[I N]*SignData: 待签名数据
 *		[I N]SignDataLen: 待签名数据长度
 *		[OUT]*EccSignBlob_data: 生成签名数据
 *		[I N|OUT]*EccSignBlob_data_len: 输入时代表EccSignBlob_data缓冲区长度，输出时为EccSignBlob_data长度
 *	返回值:
 *		成功返回0，失败返回错误码
 */
unsigned int DEVAPI Generate_SignData_IntPrikey(unsigned char* SignData, unsigned int SignDataLen, unsigned char* EccSignBlob_data, unsigned int* EccSignBlob_data_len); 

/*
 *	方法描述：
 *		外部私钥签名函数
 *	参数描述:
 *		[I N]*EccPrikey: 32字节私钥明文
 *		[I N]*SignData: 待签名数据
 *		[I N]SignDataLen: 待签名数据长度
 *		[OUT]*EccSignBlob_data: 生成签名数据
 *		[I N|OUT]*EccSignBlob_data_len: 输入时代表EccSignBlob_data缓冲区长度，输出时为EccSignBlob_data长度
 *	返回值:
 *		成功返回0，失败返回错误码
 */
unsigned int DEVAPI Generate_SignData_ExtPrikey(unsigned char* EccPrikey, unsigned char* SignData, unsigned int SignDataLen, unsigned char* EccSignBlob_data, unsigned int* EccSignBlob_data_len); 

/*
 *	方法描述：
 *		外部公钥验签函数
 *	参数描述:
 *		[I N]*EccPublickey: 64字节公钥明文
 *		[I N]*Signature_Data: 待验签数据
 *		[I N]SignDataLen: 待验签数据长度
 *		[I N]*EccSignBlob_data: 待验签签名数据
 *		[I N]EccSignBlob_data_len: 待验签签名数据长度
 *	返回值:
 *		成功返回0，失败返回错误码
 */
unsigned int DEVAPI Verify_SignData_ExtPubkey(unsigned char* EccPublickey, unsigned char* Signature_Data, unsigned int SignDataLen, unsigned char* EccSignBlob_data, unsigned int EccSignBlob_data_len);

/*
 *	方法描述：
 *		外部公钥加密函数
 *	参数描述:
 *		[I N]*EPublickey: 64字节公钥明文
 *		[I N]*InData: 待加密数据
 *		[I N]InData_len: 待加密数据长度
 *		[OUT]*ECC_CIPPHER_Data: 密文数据
 *		[I N|OUT]*ECC_CIPPHER_Data_len: 输入时为密文数据缓冲区长度，输出时为密文数据长度
 *	返回值:
 *		成功返回0，失败返回错误码
 */
unsigned int DEVAPI SM2_3_Encrypt_ExtPubkey(unsigned char* EPublickey, unsigned char* InData, unsigned int InData_len, unsigned char* ECC_CIPPHER_Data, unsigned int* ECC_CIPPHER_Data_len);

/*
 *	方法描述：
 *		外部私钥解密函数
 *	参数描述:
 *		[I N]*EPrikey: 32字节私钥明文
 *		[I N]*ECC_CIPPHER_Data: 待解密密文
 *		[I N]ECC_CIPPHER_Data_len: 待解密密文长度
 *		[OUT]*OutData: 解密后明文
 *		[I N|OUT]*OutData_len: 输入时为明文数据缓冲区长度，输出时为解密后明文数据长度
 *	返回值:
 *		成功返回0，失败返回错误码
 */
unsigned int DEVAPI SM2_3_Decrypt_ExtPrikey(unsigned char* EPrikey, unsigned char* ECC_CIPPHER_Data, unsigned int ECC_CIPPHER_Data_len, unsigned char* OutData, unsigned int* OutData_len);

/*
 *	方法描述：
 *		内部私钥解密函数
 *	参数描述:
 *		[I N]*ECC_CIPPHER_Data: 待解密密文
 *		[I N]ECC_CIPPHER_Data_len: 待解密密文长度
 *		[OUT]*OutData: 解密后明文
 *		[I N|OUT]*OutData_len: 输入时为明文数据缓冲区长度，输出时为解密后明文数据长度
 *	返回值:
 *		成功返回0，失败返回错误码
 */
unsigned int DEVAPI SM2_3_Decrypt_IntPrikey(unsigned char* ECC_CIPPHER_Data, unsigned int ECC_CIPPHER_Data_len, unsigned char* OutData, unsigned int* OutData_len);


/*
 *	方法描述：
 *		SM1OFB加密
 *	参数描述:
 *		[I N]*pIv: 
 *		[I N]*Key: 加密密钥
 *		[I N]Key_len: 加密密钥长度
 *		[I N]*InData: 待加密数据
 *		[I N]InData_len: 待加密数据长度
 *		[OUT]*OutData: 加密密文
 *		[OUT]*OutData_len: 输入时为OutData缓冲区长度，输出时为加密密文长度
 *	返回值:
 *		成功返回0，失败返回错误码	
 */
unsigned int DEVAPI SM1_OFB_Encrypt(unsigned char* pIv, unsigned char* Key, unsigned int Key_len, unsigned char* InData, unsigned int InData_len, unsigned char* OutData, unsigned int* OutData_len);

/*
 *	方法描述：
 *		SM1OFB解密
 *	参数描述:
 *		[I N]*pIv: 
 *		[I N]*Key: 加密密钥
 *		[I N]Key_len: 加密密钥长度
 *		[I N]*InData: 待解密数据
 *		[I N]InData_len: 待解密数据长度
 *		[OUT]*OutData: 解密明文
 *		[OUT]*OutData_len: 输入时为OutData缓冲区长度，输出时为解密明文长度
 *	返回值:
 *		成功返回0，失败返回错误码	
 */
unsigned int DEVAPI SM1_OFB_Decrypt(unsigned char* pIv, unsigned char* Key, unsigned int Key_len, unsigned char* InData, unsigned int InData_len, unsigned char* OutData, unsigned int* OutData_len);

/*
 *	方法描述：
 *		SM4OFB加密
 *	参数描述:
 *		[I N]*pIv: 
 *		[I N]*Key: 加密密钥
 *		[I N]Key_len: 加密密钥长度
 *		[I N]*InData: 待加密数据
 *		[I N]InData_len: 待加密数据长度
 *		[OUT]*OutData: 加密密文
 *		[OUT]*OutData_len: 输入时为OutData缓冲区长度，输出时为加密密文长度
 *	返回值:
 *		成功返回0，失败返回错误码	
 */
unsigned int DEVAPI SM4_OFB_Encrypt(unsigned char* pIv, unsigned char* Key, unsigned int Key_len, unsigned char* InData, unsigned int InData_len, unsigned char* OutData, unsigned int* OutData_len);

/*
 *	方法描述：
 *		SM4OFB解密
 *	参数描述:
 *		[I N]*pIv: 
 *		[I N]*Key: 加密密钥
 *		[I N]Key_len: 加密密钥长度
 *		[I N]*InData: 待解密数据
 *		[I N]InData_len: 待解密数据长度
 *		[OUT]*OutData: 解密明文
 *		[OUT]*OutData_len: 输入时为OutData缓冲区长度，输出时为解密明文长度
 *	返回值:
 *		成功返回0，失败返回错误码	
 */
unsigned int DEVAPI SM4_OFB_Decrypt(unsigned char* pIv, unsigned char* Key, unsigned int Key_len, unsigned char* InData, unsigned int InData_len, unsigned char* OutData, unsigned int* OutData_len);


/*
 *	方法描述：
 *		生成公私钥对
 *	参数描述:
 *		无
 *	返回值:
 *		成功返回0，失败返回错误码
 */
unsigned int DEVAPI Generate_ECCKeyPair();

/*
 *	方法描述：
 *		导出公钥
 *	参数描述:
 *		[I N]KeyPairtype: 导出公钥类型,1为签名验签，2为加解密
 *		[OUT]*publickey: 64字节公钥明文
 *	返回值:
 *		成功返回0，失败返回错误码
 */
unsigned int DEVAPI Export_publickey(unsigned int KeyPairtype, unsigned char *publickey);

/*
 *	方法描述：
 *		明文导入公私钥对
 *	参数描述:
 *		[I N]KeyPairtype: 导入公钥类型,1为签名验签，2为加解密
 *		[I N]*Privatkey: 32字节私钥明文
 *		[I N]*Publickey: 64字节公钥明文
 *	返回值:
 *		成功返回0，失败返回错误码
 */
unsigned int DEVAPI Import_ECCKeyPair(unsigned int KeyPairtype, unsigned char* Privatkey, unsigned char* Publickey);

/*
 *	方法描述：
 *		导入证书
 *	参数描述:
 *		[I N]CerType: 可选【1，2，3, 4】,分别代表4个文件的编号
 *		[I N]*In_Data: 导入数据
 *		[I N]In_Data_len: 导入数据长度（不超过2048）
 *	返回值:
 *		成功返回0，失败返回错误码
 */
unsigned int DEVAPI Import_Certificate(unsigned int CerType, char* In_Data, unsigned int In_Data_len);

/*
 *	方法描述：
 * 		导出证书
 *	参数描述:
 *		[I N]CerType: 可选【1，2，3, 4】,分别代表4个文件的编号
 *		[OUT]Out_Data: 导出数据
 *		[I N|OUT]*Out_Data_len: 输入时为Out_Data缓冲区长度，输出时为导出数据长度
 *	返回值:
 *		成功返回0，失败返回错误码
 */
unsigned int DEVAPI Export_Certificate(unsigned int CerType, char* Out_Data, unsigned int* Out_Data_len);



unsigned int DEVAPI Get_Hwcode(unsigned char *HwCode);

/*
 *	方法描述： 
 *		检查设备链接状况
 *	参数描述:
 *		无
 *	返回值:
 *		0表示有设备链接，-1表示无设备连接，其他表示错误码
 */
unsigned int Device_Status();


void Close_Device();

void Clear_Device_App();

#ifdef __cplusplus
}	
#endif

#endif
