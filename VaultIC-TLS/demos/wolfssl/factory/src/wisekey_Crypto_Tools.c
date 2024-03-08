/*=======================================
SEAL SQ 2023
Zero-touch Provisioning
IoT / Tools / Provisioning / Firmware Team
=======================================*/

// System libs
#include <stdlib.h>
#include <time.h>
#include <inttypes.h>
#include <math.h>

// WolfSSL libs
#include "wolfssl/ssl.h"
#include "wolfssl/wolfcrypt/ecc.h"
#include "wolfssl/wolfcrypt/pkcs12.h"
#include "wolfssl/wolfcrypt/wc_encrypt.h"

// SEAL SQ libs
#include "wisekey_Crypto_Tools.h"
#include "wisekey_Tools.h"

#define EC256

#define LARGE_TEMP_SZ 4096

int checkCertificateValidity(const char *path_file)
{
#ifndef WIN32
    struct tm time_info = {0};
    time_t now;

    while (time_info.tm_year < (2016 - 1900))
    {
        time(&now);
        localtime_r(&now, &time_info);
    }
    localtime_r(&now, &time_info);
#else
	SYSTEMTIME sysTime;
	GetLocalTime(&sysTime);
#endif

	// Always return 0
	// TODO: check the certificate validity dates
	return 0;

    /*mbedtls_x509_crt cert;

    mbedtls_x509_crt_init(&cert);

    mbedtls_x509_crt_parse_file(&cert, path_file);

    if ((time_info.tm_mday == cert.valid_to.day) && (time_info.tm_mon == cert.valid_to.mon) && ((time_info.tm_year + 1900) == cert.valid_to.year))
    {
        mbedtls_x509_crt_free(&cert);
        return -1;
    }
    else
    {
        mbedtls_x509_crt_free(&cert);
        return 0;
    }*/
}

static void removeChar(char* s, char c)
{
 
    int j, n = strlen(s);
    for (int i = j = 0; i < n; i++)
        if (s[i] != c)
            s[j++] = s[i];
 
    s[j] = '\0';
}

char *removeCertificateHeaders(char *cert)
{
    char *cpy = strstr(cert,"-----BEGIN CERTIFICATE-----\n");
    if(cpy)
        sprintf(cert,cpy+strlen("-----BEGIN CERTIFICATE-----\n"));
    cpy = strstr(cert,"\n-----END CERTIFICATE-----");
    if(cpy)
        sprintf(cpy,"%c",'\0');
    removeChar(cert,'\n');
    return cert;
}

char *removeCSR_Headers(char *CSR)
{
    char *cpy = strstr(CSR,"-----BEGIN CERTIFICATE REQUEST-----\n");
    sprintf(CSR,cpy+strlen("-----BEGIN CERTIFICATE REQUEST-----\n"));
    cpy = strstr(CSR,"\n-----END CERTIFICATE REQUEST-----");
    sprintf(cpy,"%c",'\0');

    removeChar(CSR,'\n');

    return CSR;
}

int generateAndSavePrivateEccKey(ecc_key *ecKey, char *outFilePath)
{
    int ret;
    WC_RNG rng;
    byte *der = NULL;
    byte *pem = NULL;
    int derSz;
#ifdef WOLFSSL_DER_TO_PEM
    int pemSz;
    FILE *file = NULL;
    char outFile[255];
#endif

    der = malloc(ECC_BUFSIZE);

    pem = malloc(LARGE_TEMP_SZ);

    ret = wc_InitRng(&rng);
    if (ret != 0)
    {
        wkey_log(LOG_ERROR, "RNG initialization failed: %d\n", ret);
        free(pem);
        free(der);
        return ret;
    }

    ret = wc_ecc_init(ecKey);
    if (ret != 0)
    {
        wkey_log(LOG_ERROR, "Key initialization failed: %d\n", ret);
        free(pem);
        free(der);
        return ret;
    }

    ret = wc_ecc_make_key_ex(&rng, 32, ecKey, ECC_SECP256R1);
    if (ret != 0)
    {
        wkey_log(LOG_ERROR, "Key generation failed: %d\n", ret);
        free(pem);
        free(der);
        return ret;
    }

    ret = wc_EccKeyToDer(ecKey, der, LARGE_TEMP_SZ);
    if (ret <= 0)
    {
        wkey_log(LOG_ERROR, "Key To DER failed: %d\n", ret);
        free(pem);
        free(der);
        return ret;
    }
    derSz = ret;

    // memset(pem, 0, sizeof(pem));
    ret = wc_DerToPem(der, derSz, pem, LARGE_TEMP_SZ, ECC_PRIVATEKEY_TYPE);
    if (ret <= 0)
    {
        wkey_log(LOG_ERROR, "Key DER to PEM failed: %d\n", ret);
        free(pem);
        free(der);
        return ret;
    }
    pemSz = ret;
    snprintf(outFile, sizeof(outFile), outFilePath);

    printf("WKEY INFO : ECC KEY generated and saved into \"%s\"\n", outFile);
    file = fopen(outFile, "wb");

#ifdef _WIN32
	unsigned long err = 0;
	if (!file)
	{
		err = GetLastError();
	}
#endif

    if (file)
    {
        ret = (int)fwrite(pem, 1, pemSz, file);
        if (ret <= 0)
        {
            wkey_log(LOG_ERROR, "Saving PEM Key failed: %d\n", ret);
            free(pem);
            free(der);
            fclose(file);
            return ret;
        }

        fclose(file);
    }

    free(pem);
    free(der);

    return 1;
}

char* template = "{\"oid\": \"%s\", \"value\": \"%s\"}";

void concatenateSubject(char* strsubjects,char*oid,char *value,int*first)
{
    if(*first==FALSE)
        strcat(strsubjects,",");

    char*subject=malloc(strlen(template)+strlen(oid)+strlen(value));
    sprintf(subject,template,oid,value);
    strcat(strsubjects,subject);
    free(subject);
    *first=FALSE;
}


int countStrSubjectSize(char*oid,char *value,int*first)
{
    int size =0;
        
    if(*first==FALSE)
        size+=strlen(",");        
        
    size+= strlen(template);
    size+= strlen(oid);
    size+= strlen(value);
    *first=FALSE;

    return size;

}

char *generateSubjects(CertName *certDefaultName)
{   
    char* subjectString=NULL;
    int firstsubject=TRUE;

//Count size of the full string of subject    
    int subjectStringSize = strlen("[]")+1;

    if(certDefaultName->commonName)
        subjectStringSize+=countStrSubjectSize(OID_COMMON_NAME,certDefaultName->commonName,&firstsubject);

    if(certDefaultName->country)
        subjectStringSize+=countStrSubjectSize(OID_COUNTRY,certDefaultName->country,&firstsubject);

    /*if(certDefaultName->email)
        subjectStringSize+=countStrSubjectSize(OID_EMAIL,certDefaultName->email,&firstsubject);*/
    
    if(certDefaultName->locality)
        subjectStringSize+=countStrSubjectSize(OID_LOCALITY_NAME,certDefaultName->locality,&firstsubject);
        
    if(certDefaultName->org)
        subjectStringSize+=countStrSubjectSize(OID_ORGANIZATION_NAME,certDefaultName->org,&firstsubject);
    
    if(certDefaultName->postalCode)
        subjectStringSize+=countStrSubjectSize(OID_POSTAL_CODE,certDefaultName->postalCode,&firstsubject);
    
    if(certDefaultName->serialDev)
        subjectStringSize+=countStrSubjectSize(OID_DEVICE_SERIAL_NUMBER,certDefaultName->serialDev,&firstsubject);

    subjectString=malloc(subjectStringSize);

//Fill the string
    firstsubject=TRUE;

    sprintf(subjectString,"["); 

    if(certDefaultName->commonName)
        concatenateSubject(subjectString,OID_COMMON_NAME,certDefaultName->commonName,&firstsubject);

    if(certDefaultName->country)
        concatenateSubject(subjectString,OID_COUNTRY,certDefaultName->country,&firstsubject);
    
    /*if(certDefaultName->email)
        concatenateSubject(subjectString,OID_EMAIL,certDefaultName->email,&firstsubject);*/
    
    if(certDefaultName->locality)
        concatenateSubject(subjectString,OID_LOCALITY_NAME,certDefaultName->locality,&firstsubject);

    if(certDefaultName->org)
        concatenateSubject(subjectString,OID_ORGANIZATION_NAME,certDefaultName->org,&firstsubject);

    if(certDefaultName->postalCode)
        concatenateSubject(subjectString,OID_POSTAL_CODE,certDefaultName->postalCode,&firstsubject);
    
    if(certDefaultName->serialDev)
        concatenateSubject(subjectString,OID_DEVICE_SERIAL_NUMBER,certDefaultName->serialDev,&firstsubject);

    strcat(subjectString,"]");

    return subjectString;
}

char *generateCSR(ecc_key *ecKey, CertName* certDefaultName, int* lenCSR)
{
    int ret;
    Cert *req;

    WC_RNG rng;

    byte *der = NULL;
    int derSz;

    byte *pem = NULL;

    der = malloc(ECC_BUFSIZE);

    pem = malloc(LARGE_TEMP_SZ);

    req = malloc(sizeof(Cert));

    ret = wc_InitRng(&rng);
    if (ret != 0)
    {
        wkey_log(LOG_ERROR, "RNG initialization failed: %d\n", ret);
        free(pem);
        free(der);
        free(req);
        return "-1";
    }

    ret = wc_EccKeyToDer(ecKey, der, LARGE_TEMP_SZ);
    if (ret < 0)
    {
        wkey_log(LOG_ERROR, "wc_EccKeyToDer failed: %d\n", ret);
        free(pem);
        free(der);
        free(req);
        return "-1";
    }
    derSz = ret;

    //ret = wc_InitCert(req);
    //if (ret != 0)
    //{
    //    wkey_log(LOG_ERROR, "Init Cert failed: %d\n", ret);
    //    free(pem);
    //    free(der);
    //    free(req);
    //    return "-1";
    //}

    req->version = 0;
    req->sigType = CTC_SHA256wECDSA;

    memcpy(&req->subject, certDefaultName, sizeof(CertName));


    //ret = wc_MakeCertReq_ex(req, der, LARGE_TEMP_SZ, ECC_TYPE, ecKey);
    //if (ret <= 0)
    //{
    //    wkey_log(LOG_ERROR, "Make Cert Req failed: %d\n", ret);
    //    free(pem);
    //    free(der);
    //    free(req);
    //    return "-4";
    //}

    //// last
    //ret = wc_SignCert_ex(req->bodySz, req->sigType, der, LARGE_TEMP_SZ, ECC_TYPE, ecKey, &rng);
    //if (ret <= 0)
    //{
    //    wkey_log(LOG_ERROR, "Sign Cert failed: %d\n", ret);
    //}
    //derSz = ret;

    // memset(pem, 0, sizeof(pem));
    ret = wc_DerToPem(der, derSz, pem, LARGE_TEMP_SZ, CERTREQ_TYPE);
    if (ret <= 0)
    {
        wkey_log(LOG_ERROR, "CSR DER to PEM failed: %d\n", ret);
    }
	*lenCSR = ret;

    if(der)
        free(der);
    if(req)
        free(req);

    return (char *)pem;
}
