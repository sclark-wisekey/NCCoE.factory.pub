/*=======================================
SEAL SQ 2023
Zero-touch Provisioning
IoT / Tools / Provisioning / Firmware Team
=======================================*/

// System libs
#include <stdio.h>

// Wolfssl libs
#include "wolfssl/ssl.h"
#include "wolfssl/wolfcrypt/ecc.h"
#include "wolfssl/wolfcrypt/asn.h"
#include "wolfssl/wolfcrypt/pkcs12.h"
#include "wolfssl/wolfcrypt/settings.h"

// SEAL SQ libs
#include "wisekey_Ines_Agent.h"
#include "wisekey_Http_Request_Manager.h"
#include "wisekey_Crypto_Tools.h"
#include "wisekey_Tools.h"
#include "wisekey_Ines_settings.h"

#include "vaultic_common.h"
#include "common.h"
#include "vaultic_csr.h"


#define EC256

int inesDemo_ZeroTouchProv(config_values_t config, int protocol)
{
	printf("-------------\r\nInes Agent\r\n-------------\r\n");
	if (verifyConfigStruc(CONFIG_FILE_INES, &config) < 0)
	{
		wkey_log(LOG_ERROR, "Invalid INES config provided");
		return -1;
	}

	int ret = -1;
	int status;

	// Check if files exist
	if (checkCertificateAndKeyDisponibility(config) != 0)
	{
		wkey_log(LOG_WARNING, "Device Certificate DOES NOT exist. Launching the INeS Agent for requesting device certificate...");
		ret = createDeviceCertificateFromInes(config, protocol);
	}
	else
	{
		char *certificate = NULL;

		if (protocol == API_REST)
		{
			certificate = openFile(config.DEVICE_CERT_PATH);
			wkey_log(LOG_INFO, "Verifying with INES ...");
			status = checkCertificate(config, certificate);
		}
		else
			status = 0;

		if (status == 0)
		{
			wkey_log(LOG_SUCCESS, "Device Certificate Chain exists: %s. If you want to request a new one, please remove it and launch the INeS agent again.", config.DEVICE_CERT_PATH);
			wkey_log(LOG_SUCCESS, "Certificate validated by INES");
			ret = 0;
		}

		else if (status > 0)
		{
			wkey_log(LOG_WARNING, "Certificate is expired, restarting Ines Agent");
			ret = createDeviceCertificateFromInes(config, protocol);
		}

		else if (status < 0)
		{
			wkey_log(LOG_ERROR, "Error during checking certificate");
			ret = -1;
		}
		if (certificate)
			free(certificate);
	}

	return ret;
}

int inesDemo_IssueCert(config_values_t config, int protocol)
{
	printf("-------------\r\nInes Agent\r\n-------------\r\n");
	if (verifyConfigStruc(CONFIG_FILE_INES, &config) < 0)
	{
		wkey_log(LOG_ERROR, "Invalid INES config provided");
		return -1;
	}

	int ret = -1;

	// Send The CSR from a file to INeS and receive a certificate
	wkey_log(LOG_STEP_INDICATOR, "Launching the INeS Agent for requesting device certificate...");
	ret = createDeviceCertificateFromInes(config, protocol);

	return ret;
}

char* getCSR(config_values_t config, int* pLenCSR)
{
	char* csr = NULL;

	// Read the CSR from the certificates directory
	FILE* file;
	file = fopen(config.FACTORY_CSR_PATH, "r");
	if (file)
	{
		size_t maxCSR = MAXCSR;
		csr = malloc(maxCSR);
		//fgets(csr, maxCSR, file);
		*pLenCSR = fread(csr, sizeof(char), maxCSR, file);
		fclose(file);
	}
	return csr;
}

int createDeviceCertificateFromInes(config_values_t config, int protocol)
{
    wkey_log(LOG_STEP_INDICATOR, "INES AGENT - Starting Factory Provisioning using INeS CMS");
    wkey_log(LOG_STEP_INDICATOR, "INES AGENT - Generate ECC Key on VaultIC");

    char *deviceName = createDeviceName(config);
    static CertName certDefaultName;
    memcpy(certDefaultName.country, config.DEVICE_COUNTRY, strlen(config.DEVICE_COUNTRY));
    certDefaultName.countryEnc = CTC_PRINTABLE;
    memcpy(certDefaultName.commonName, deviceName, strlen(deviceName));
    certDefaultName.commonNameEnc = CTC_UTF8;
    memcpy(certDefaultName.serialDev, config.DEVICE_SERIAL_NUMBER, strlen(config.DEVICE_SERIAL_NUMBER));
    certDefaultName.serialDevEnc = CTC_PRINTABLE;

    if (deviceName)
        free(deviceName);

	int lenCSR = 0;

#ifdef READ_CSR 
	// Read the CSR from a file
	wkey_log(LOG_STEP_INDICATOR, "INES AGENT - Read CSR (Certificate Signing Request)");
	char *csr = getCSR(config, &lenCSR);
#else
	wkey_log(LOG_STEP_INDICATOR, "INES AGENT - Generate CSR (Certificate Signing Request)");
    	ecc_key privKey;
	int eccSize = sizeof(ecc_key);

    generateAndSavePrivateEccKey(&privKey, config.SECURE_KEY_PATH);

    if (wc_ecc_check_key(&privKey) != MP_OKAY)
    {
        wkey_log(LOG_ERROR, "Error while generating private Key");
        return -1;
    }
	// Generate the CSR using WolfSSL
	csr = generateCSR(&privKey, &certDefaultName, &lenCSR);
#endif

    char *subjects = generateSubjects(&certDefaultName);


    if (strcmp(csr, "-1") == 0)
    {
        wkey_log(LOG_ERROR, "Error while creating CSR : ");
        return -2;
    }

    wkey_log(LOG_STEP_INDICATOR, "INES AGENT - Get certificate from Ines");
    certificate_t certificate;
    char *DeviceCertpem;
	VLT_U16 lenData = BUF_LEN_MAX;
	VLT_U8 pDerCert[BUF_LEN_MAX] = { 0 };
	VLT_U16 lenBase64 = 0;
	VLT_U16 status = VLT_OK;


    switch (protocol)
    {
    case API_REST:
		certificate = apiREST_issueCertificate(config, config.INES_TEMPLATE_ID, subjects, csr, lenCSR);
        if (strcmp(certificate.certificate, "NULL") == 0)	return -1;
		// Convert the PEM to a DER buffer
		lenBase64 = (VLT_U16)strlen(certificate.certificate);
		status = Base64Decode(certificate.certificate, lenBase64, pDerCert, &lenData);

		DeviceCertpem = inesRawCartificatetoFormatedcert(certificate.certificate);
        freeResultStruct(INES_RESPONSE_TYPE_CERTIFICATE,&certificate);
        if(subjects)
            free(subjects);
        break;
    }
    if (csr) free(csr);

	// Write the PEM certificate
    writeAndSaveFile(config.DEVICE_CERT_PATH, DeviceCertpem, strlen(DeviceCertpem));

	// Write the DER certificate
	status = VltWriteDataBuffer(pDerCert, lenData,  config.DEVICE_CERT_DER_PATH, "");

    if (DeviceCertpem) free(DeviceCertpem);

    wkey_log(LOG_SUCCESS, "Certificate Saved - End of INES AGENT");

    return 0;
}


char* apiREST_process(config_values_t config, char* method,char* apiname, char* custom_suffix,char* body){

    char *rawResponse = inesApi(config.CLIENT_CERT_PATH,config.CLIENT_KEY_PATH,config.INES_REST_SERVER_URL,API_REST,IOT_API_REST_PATH_PREFIX,NULL,NULL,POST_METHOD,IOT_API_REST_AUTHENTIFICATION,NULL,NULL);

    if(!rawResponse)
    {
        wkey_log(LOG_ERROR, "NO ACCESS TOKEN");
        return NULL;
    }

    authentication_t authentication_Struct = {"NULL"};
    json_value *value = convertStringIntoJsontype(rawResponse);

    fillResultStruct(INES_RESPONSE_TYPE_AUTHENTICATION,&authentication_Struct,value);

    if(strcmp(authentication_Struct.access_token,"NULL")==0)
    {
        wkey_log(LOG_ERROR, "NO ACCESS TOKEN");
        return NULL;
    }

    wkey_log(LOG_INFO, "SENDING REQUEST");

    rawResponse = inesApi(config.CLIENT_CERT_PATH,config.CLIENT_KEY_PATH,config.INES_REST_SERVER_URL,API_REST,IOT_API_REST_PATH_PREFIX,config.INES_ORG_ID,authentication_Struct.access_token,method,apiname,custom_suffix,body);

    if(authentication_Struct.access_token)
        free(authentication_Struct.access_token);
    
    return rawResponse;
}

char* apiEST_process(config_values_t config,char* clientCert,char*clientKey,char* method,char* apiname, char* custom_suffix,char* body){

    char *rawResponse = inesApi(clientCert,clientKey,config.INES_EST_SERVER_URL,API_EST,IOT_API_EST_PATH_PREFIX,NULL,NULL,method,apiname,NULL,body);

    return rawResponse;
}

/*apiREST_getCAList functions*/
int apiREST_getCAList(config_values_t config,CA_details_t *CA_list,int CA_listSize)
{
    char *response = apiREST_process(config, GET_METHOD, IOT_API_REST_GET_CA_PREFIX, NULL, NULL);


    if (!response)
        return -1;

    char *body = extractHttpResponseBody(response);

    if (response)
        free(response);

    json_value *value = convertStringIntoJsontype(body);

    free(body);

    if(!value)
    {
        wkey_log(LOG_ERROR,"Error while converting JSON, Abord ...");
        return -1;
    }

    int numberOfItems=value->u.object.values[0].value->u.array.length;

    if(numberOfItems>(CA_listSize/((int)sizeof(CA_details_t))))
    {
        wkey_log(LOG_ERROR,"CA_list seems too low to store all CA, please improve it to at least %d",numberOfItems);
        numberOfItems=-1;
    }
    else
    {
        fillArrayList(INES_RESPONSE_TYPE_CA_LIST,CA_list,value);
    }


    json_value_free(value);

    return numberOfItems;

}
/*Get CA Chain functions*/

/*apiREST_getCAdetails functions*/

CA_details_t apiREST_getCAdetails(config_values_t config, int CA_id)
{
    CA_details_t CA_details = {"NULL", "NULL", "NULL", "NULL", "NULL", "NULL", "NULL"};
    char *customSufix = malloc(6);
    sprintf(customSufix, "/%d", CA_id);
    char *response = apiREST_process(config, GET_METHOD, IOT_API_REST_GET_CA_PREFIX, customSufix, NULL);
    
    if (customSufix)
        free(customSufix);

    if (!response)
        return CA_details;

    char *body = extractHttpResponseBody(response);

    if (response)
        free(response);

    json_value *value = convertStringIntoJsontype(body);

    free(body);

    fillResultStruct(INES_RESPONSE_TYPE_CA_DETAILS, &CA_details, value);

    json_value_free(value);

    return CA_details;
}
/*Get CA Chain functions*/

/*Get CA Chain functions*/
CA_certificat_chain_t apiREST_getCACertificateChain(config_values_t config, int CA_id)
{
    struct CA_certificat_chain_t CA_chaindetails = {{"NULL", "NULL", "NULL"}, {"NULL", "NULL", "NULL"}};
    char *customSufix = malloc(strlen("/%d/") + strlen(IOT_API_REST_GET_CA_CERTIFICATE_CHAIN) + 10 /*CA_id*/ + 1);
    sprintf(customSufix, "/%d%s", CA_id, IOT_API_REST_GET_CA_CERTIFICATE_CHAIN);

    char *response = apiREST_process(config, GET_METHOD, IOT_API_REST_GET_CA_PREFIX, customSufix, NULL);

    if (customSufix)
        free(customSufix);

    if (!response)
        return CA_chaindetails;

    char *body = extractHttpResponseBody(response);

    if (response)
        free(response);

    json_value *value = convertStringIntoJsontype(body);
    free(body);

    fillResultStruct(INES_RESPONSE_TYPE_CA_CERTIFICATE_CHAIN, &CA_chaindetails, value);
    json_value_free(value);

    return CA_chaindetails;
}
/*Get CA Chain functions*/

certificate_t apiREST_issueCertificate(config_values_t config, char *templateId, char *subjects, char *CSR, int lenCSR)
{
    certificate_t certificate = {"NULL", "NULL", "NULL", "NULL", "NULL", "NULL", "NULL", "NULL", "NULL", "NULL", "NULL", "NULL", "NULL", "NULL", "NULL", "NULL"};

    char *body = generateCSRBody(templateId, subjects, CSR, lenCSR, 90);

    char *response = apiREST_process(config, POST_METHOD, IOT_API_REST_CERTIFICATE, NULL, body);

    if (!response)
        return certificate;

    char *response_body = extractHttpResponseBody(response);

    if (response)
        free(response);

    json_value *value = convertStringIntoJsontype(response_body);

    free(body);
    free(response_body);

    fillResultStruct(INES_RESPONSE_TYPE_CERTIFICATE, &certificate, value);

    json_value_free(value);

    return certificate;
}

/*apiREST_getCAList functions*/
int apiREST_getCertificateList(config_values_t config,certificate_t* certificate_List, char* commonName, int certificate_ListSize, int pageNum)
{
    int numberOfItems=0;
    char* customPrefix = NULL;

    if(commonName)
    {
        if(pageNum>0)
            wkey_log(LOG_WARNING,"\'pageNum\' argument is useless if you use commonName filter");
        
        char* customPrefix = malloc(strlen(IOT_API_REST_CERTIFICATE_COMMON_NAME_SUFFIX)+strlen("/")+strlen(commonName)+1);
        sprintf(customPrefix,"%s/%s",IOT_API_REST_CERTIFICATE_COMMON_NAME_SUFFIX,commonName);
    }
    else
    {
        char* customPrefix = malloc(strlen("?pagenum=1&pagesize=")+4+4+1);
        sprintf(customPrefix,"?pagenum=%d&pagesize=%d",pageNum,certificate_ListSize/sizeof(certificate_t));
    }

    char *response = apiREST_process(config, GET_METHOD, IOT_API_REST_CERTIFICATE, customPrefix,NULL);

    if (customPrefix)
        free(customPrefix);

    if (!response)
        return -1;

    char *body = extractHttpResponseBody(response);

    if (response)
        free(response);

    json_value *value = convertStringIntoJsontype(body);

    free(body);

    if(!value)
    {
        wkey_log(LOG_ERROR,"Error while converting JSON, Abord ...");
        return -1;
    }

    numberOfItems=value->u.object.values[0].value->u.array.length;

    if(numberOfItems>(certificate_ListSize/((int)sizeof(certificate_t))))
    {
        wkey_log(LOG_ERROR,"certificate_List seems too low to store all CA, please improve it to at least %d",numberOfItems);
    }
    else
    {
        fillArrayList(INES_RESPONSE_TYPE_CERTIFICATE,certificate_List,value);
    }

    json_value_free(value);

    return numberOfItems;

}
/*Get Certificate List*/

certificate_t apiREST_renewCertificate(config_values_t config, int certificate_id, int revokeOriginal, char *CSR)
{
    certificate_t certficate = {"NULL", "NULL", "NULL", "NULL", "NULL", "NULL", "NULL", "NULL", "NULL", "NULL", "NULL", "NULL", "NULL", "NULL", "NULL", "NULL"};

    char *customSufix = NULL;
    char *bodytemplate = "{\r\n%s%s,\r\n\"revoke_original_certificate\":%s\r\n}";
    char *body;

    char *revokestate = (revokeOriginal == 0) ? "false" : "true";

    int bodylenght = strlen(bodytemplate) + strlen(revokestate) + 1;

    if (CSR)
    {
        customSufix = malloc(strlen("/%d/") + strlen(IOT_API_REST_CERTIFICATE_REKEY) + 10 /*CA_id*/ + 1);
        sprintf(customSufix, "/%d%s", certificate_id, IOT_API_REST_CERTIFICATE_REKEY);
        bodylenght += strlen(CSR) + strlen("\"csr\":");
    }
    else
    {
        customSufix = malloc(strlen("/%d/") + strlen(IOT_API_REST_CERTIFICATE_RENEW) + 10 /*CA_id*/ + 1);
        sprintf(customSufix, "/%d%s", certificate_id, IOT_API_REST_CERTIFICATE_RENEW);
    }
    body = malloc(bodylenght);

    sprintf(body, "{\r\n");

    if (CSR)
    {
        strcat(body, "\"csr\":\"");
        strcat(body, removeCSR_Headers(CSR));
        strcat(body, "\",\r\n");
    }

    strcat(body, "\"revoke_original_certificate\":");
    strcat(body, revokestate);
    strcat(body, "\r\n}");

    char *response = apiREST_process(config, POST_METHOD, IOT_API_REST_CERTIFICATE, customSufix, body);

    if (body)
        free(body);

    if (customSufix)
        free(customSufix);

    if (!response)
        return certficate;

    char *response_body = extractHttpResponseBody(response);

    if (response)
        free(response);

    json_value *value = convertStringIntoJsontype(response_body);

    free(response_body);

    fillResultStruct(INES_RESPONSE_TYPE_CERTIFICATE, &certficate, value);

    json_value_free(value);

    return certficate;
}

/*apiREST_getCertificateTemplateList functions*/
int apiREST_getCertificateTemplateList(config_values_t config,certificate_template_t* certificateTemplate_List, int certificateTemplate_ListSize)
{  
    char *response = apiREST_process(config, GET_METHOD, IOT_API_REST_CERTIFICATE_TEMPLATE, NULL,NULL);

    if (!response)
        return -1;

    char *body = extractHttpResponseBody(response);

    if (response)
        free(response);

    json_value *value = convertStringIntoJsontype(body);

    free(body);
        
    if(!value)
    {
        wkey_log(LOG_ERROR,"Error while converting JSON, Abord ...");
        return -1;
    }
    
    int numberOfItems=value->u.object.values[0].value->u.array.length;

    if(numberOfItems>(certificateTemplate_ListSize/((int)sizeof(certificate_template_t))))
    {
        wkey_log(LOG_ERROR,"certificate_template_t seems too low to store all CA, please improve it to at least %d",numberOfItems);
        numberOfItems=-1;
    }
    else
    {
        fillArrayList(INES_RESPONSE_TYPE_CERTIFICATE_TEMPLATE,certificateTemplate_List,value);
    }

    json_value_free(value);

    return numberOfItems;

}
/*Get Certificate template List*/

void fillArrayList(int type, void*OutputArray, json_value *value)
{

    int numberOfItems=value->u.object.values[0].value->u.array.length;

    for(int i=0;i<numberOfItems;i++)
    {

        switch (type)
        {
        case INES_RESPONSE_TYPE_CA_LIST:        
            fillResultStruct(type, (CA_details_t*)OutputArray+i, value->u.object.values[0].value->u.array.values[i]);
            break;
        
        case INES_RESPONSE_TYPE_CERTIFICATE:        
            fillResultStruct(type, (certificate_t*)OutputArray+i, value->u.object.values[0].value->u.array.values[i]);
            break;
        
        case INES_RESPONSE_TYPE_CERTIFICATE_TEMPLATE:        
            fillResultStruct(type, (certificate_template_t*)OutputArray+i, value->u.object.values[0].value->u.array.values[i]);
            break;
        
        default:
            break;
        }
    }

}

void fillResultStruct(int type, void *input_Struct, json_value *value)
{
    struct CA_certificat_chain_t *CA_certificat_chain_Struct = input_Struct;
    struct CA_details_t *CA_details_Struct = input_Struct;
    struct certificate_t *certificate_Struct = input_Struct;
    struct certificate_status_t *certificate_Status_Struct = input_Struct;
    struct authentication_t* authentication_Struct = input_Struct;
    struct certificate_template_t* certificateTemplate_Struct = input_Struct;

    switch (type)
    {
    case INES_RESPONSE_TYPE_AUTHENTICATION:
        storeJsonValueIntoStructValue(&authentication_Struct->access_token, value, "access_token",NULL);
        break;

    case INES_RESPONSE_TYPE_CA_CERTIFICATE_CHAIN:
        storeJsonValueIntoStructValue(&CA_certificat_chain_Struct->root.subject, value, "root", "subject");
        storeJsonValueIntoStructValue(&CA_certificat_chain_Struct->root.issuer, value, "root", "issuer");
        storeJsonValueIntoStructValue(&CA_certificat_chain_Struct->root.certificate, value, "root", "certificate");
        storeJsonValueIntoStructValue(&CA_certificat_chain_Struct->issuing.subject, value, "issuing", "subject");
        storeJsonValueIntoStructValue(&CA_certificat_chain_Struct->issuing.issuer, value, "issuing", "issuer");
        storeJsonValueIntoStructValue(&CA_certificat_chain_Struct->issuing.certificate, value, "issuing", "certificate");
        break;

    case INES_RESPONSE_TYPE_CA_DETAILS:
        storeJsonValueIntoStructValue(&CA_details_Struct->id, value, "ca", "id");
        storeJsonValueIntoStructValue(&CA_details_Struct->caAlias, value, "ca", "caAlias");
        storeJsonValueIntoStructValue(&CA_details_Struct->thumbprint, value, "ca", "thumbprint");
        storeJsonValueIntoStructValue(&CA_details_Struct->serverName, value, "ca", "serverName");
        storeJsonValueIntoStructValue(&CA_details_Struct->caName, value, "ca", "caName");
        storeJsonValueIntoStructValue(&CA_details_Struct->description, value, "ca", "description");
        storeJsonValueIntoStructValue(&CA_details_Struct->certificate, value, "ca", "certificate");
        break;
    
    case INES_RESPONSE_TYPE_CA_LIST:
        storeJsonValueIntoStructValue(&CA_details_Struct->id, value,"id",NULL);
        storeJsonValueIntoStructValue(&CA_details_Struct->caAlias, value, "caAlias",NULL);
        storeJsonValueIntoStructValue(&CA_details_Struct->thumbprint, value, "thumbprint",NULL);
        storeJsonValueIntoStructValue(&CA_details_Struct->serverName, value, "serverName",NULL);
        storeJsonValueIntoStructValue(&CA_details_Struct->caName, value, "caName",NULL);
        storeJsonValueIntoStructValue(&CA_details_Struct->description, value, "description",NULL);
        storeJsonValueIntoStructValue(&CA_details_Struct->certificate, value, "certificate",NULL);
        break;

    case INES_RESPONSE_TYPE_CERTIFICATE:
        storeJsonValueIntoStructValue(&certificate_Struct->certificate_id, value, "certificate_id", NULL);
        storeJsonValueIntoStructValue(&certificate_Struct->organization_id, value, "organization_id", NULL);
        storeJsonValueIntoStructValue(&certificate_Struct->common_name, value, "common_name", NULL);
        storeJsonValueIntoStructValue(&certificate_Struct->issued_dn, value, "issued_dn", NULL);
        storeJsonValueIntoStructValue(&certificate_Struct->certificate, value, "certificate", NULL);
        storeJsonValueIntoStructValue(&certificate_Struct->certificate_pkcs12, value, "certificate_pkcs12", NULL);
        storeJsonValueIntoStructValue(&certificate_Struct->passphrase, value, "passphrase", NULL);
        storeJsonValueIntoStructValue(&certificate_Struct->status, value, "status", NULL);
        storeJsonValueIntoStructValue(&certificate_Struct->issuer, value, "issuer", NULL);
        storeJsonValueIntoStructValue(&certificate_Struct->serial_number, value, "serial_number", NULL);
        storeJsonValueIntoStructValue(&certificate_Struct->valid_from, value, "valid_from", NULL);
        storeJsonValueIntoStructValue(&certificate_Struct->valid_until, value, "valid_until", NULL);
        storeJsonValueIntoStructValue(&certificate_Struct->thumbprint, value, "thumbprint", NULL);
        storeJsonValueIntoStructValue(&certificate_Struct->san, value, "san", NULL);
        storeJsonValueIntoStructValue(&certificate_Struct->revocation_reason, value, "revocation_reason",NULL);
        storeJsonValueIntoStructValue(&certificate_Struct->revocation_date, value, "revocation_date",NULL);
        break;
    
    case INES_RESPONSE_TYPE_CERTIFICATE_STATUS:
        storeJsonValueIntoStructValue(&certificate_Status_Struct->status, value, "status", NULL);
        storeJsonValueIntoStructValue(&certificate_Status_Struct->detail, value, "detail", NULL);
        storeJsonValueIntoStructValue(&certificate_Status_Struct->reason, value, "reason", NULL);
        storeJsonValueIntoStructValue(&certificate_Status_Struct->revocation_date, value, "revocationDate", NULL);
        break;

    case INES_RESPONSE_TYPE_CERTIFICATE_TEMPLATE:
        storeJsonValueIntoStructValue(&certificateTemplate_Struct->template_id, value, "template_id", NULL);
        storeJsonValueIntoStructValue(&certificateTemplate_Struct->organization_id, value, "organization_id", NULL);
        storeJsonValueIntoStructValue(&certificateTemplate_Struct->name, value, "name", NULL);
        storeJsonValueIntoStructValue(&certificateTemplate_Struct->description, value, "description", NULL);
        storeJsonValueIntoStructValue(&certificateTemplate_Struct->status, value, "status", NULL);
        break;

    default:
        wkey_log(LOG_ERROR, "Unknown Ines Type");
        break;
    }
}

void displayResults(int type, void *input_Struct)
{
    struct CA_certificat_chain_t *CA_certificat_chain_Struct = input_Struct;
    struct CA_details_t *CA_details_Struct = input_Struct;
    struct certificate_t *certificate_Struct = input_Struct;
    struct certificate_status_t *certificate_Status_Struct = input_Struct;
    struct certificate_template_t *certificate_Template_Struct = input_Struct;


    switch (type)
    {
    case INES_RESPONSE_TYPE_CA_CERTIFICATE_CHAIN:
        printf("\r\n\033[1;30;47m--- CA Chain Result ---\033[0m\r\n");
        printf("\033[1;37m- root\r\n");
        printf("|-- subject : %s\r\n", CA_certificat_chain_Struct->root.subject);
        printf("|-- issuer : %s\r\n", CA_certificat_chain_Struct->root.issuer);
        printf("|-- certificate : %s\r\n", CA_certificat_chain_Struct->root.certificate);
        printf("- issuing\r\n");
        printf("|-- subject : %s\r\n", CA_certificat_chain_Struct->issuing.subject);
        printf("|-- issuer : %s\r\n", CA_certificat_chain_Struct->issuing.issuer);
        printf("|-- certificate : %s\r\n", CA_certificat_chain_Struct->issuing.certificate);
        printf("\033[1;30;47m--- END CA Chain Result ---\033[0m\r\n");
        break;

    case INES_RESPONSE_TYPE_CA_DETAILS:
        printf("\r\n\033[1;30;47m--- CA Details Result ---\033[0m\r\n");
        printf("\033[1;37m- CA\r\n");
        printf("|-- id : %s\r\n", CA_details_Struct->id);
        printf("|-- caAlias : %s\r\n", CA_details_Struct->caAlias);
        printf("|-- thumbprint : %s\r\n", CA_details_Struct->thumbprint);
        printf("|-- serverName : %s\r\n", CA_details_Struct->serverName);
        printf("|-- caName : %s\r\n", CA_details_Struct->caName);
        printf("|-- description : %s\r\n", CA_details_Struct->description);
        printf("|-- certificate : %s\r\n", CA_details_Struct->certificate);
        printf("\033[1;30;47m--- END CA Details Result ---\033[0m\r\n");
        break;

    case INES_RESPONSE_TYPE_CERTIFICATE:
        printf("\r\n\033[1;30;47m--- Certficate Result ---\033[0m\r\n");
        printf("\033[1;37m- Certficate\r\n");
        printf("|-- certificate_id : %s\r\n", certificate_Struct->certificate_id);
        printf("|-- organization_id : %s\r\n", certificate_Struct->organization_id);
        printf("|-- common_name : %s\r\n", certificate_Struct->common_name);
        printf("|-- issued_dn : %s\r\n", certificate_Struct->issued_dn);
        printf("|-- certificate : %s\r\n", certificate_Struct->certificate);
        printf("|-- certificate_pkcs12 : %s\r\n", certificate_Struct->certificate_pkcs12);
        printf("|-- passphrase : %s\r\n", certificate_Struct->passphrase);
        printf("|-- status : %s\r\n", certificate_Struct->status);
        printf("|-- issuer : %s\r\n", certificate_Struct->issuer);
        printf("|-- serial_number : %s\r\n", certificate_Struct->serial_number);
        printf("|-- valid_from : %s\r\n", certificate_Struct->valid_from);
        printf("|-- valid_until : %s\r\n", certificate_Struct->valid_until);
        printf("|-- thumbprint : %s\r\n", certificate_Struct->thumbprint);
        printf("|-- san : %s\r\n", certificate_Struct->san);
        printf("\033[1;30;47m--- END Certficate Result ---\033[0m\r\n");
        break;

    case INES_RESPONSE_TYPE_CERTIFICATE_STATUS:
        printf("\r\n\033[1;30;47m--- Certficate Result ---\033[0m\r\n");
        printf("\033[1;37m- Certficate Status\r\n");
        printf("|-- status : %s\r\n", certificate_Status_Struct->status);
        printf("|-- detail : %s\r\n", certificate_Status_Struct->detail);
        printf("|-- recation reason : %s\r\n", certificate_Status_Struct->reason);
        printf("|-- revocationDate : %s\r\n", certificate_Status_Struct->revocation_date);
        break;

    case INES_RESPONSE_TYPE_CERTIFICATE_TEMPLATE:
        printf("\r\n\033[1;30;47m--- Certficate Template Result ---\033[0m\r\n");
        printf("\033[1;37m- Certficate Template\r\n");
        printf("|-- template_id : %s\r\n", certificate_Template_Struct->template_id);
        printf("|-- organization_id : %s\r\n", certificate_Template_Struct->organization_id);
        printf("|-- name : %s\r\n", certificate_Template_Struct->name);
        printf("|-- description : %s\r\n", certificate_Template_Struct->description);
        printf("|-- status : %s\r\n", certificate_Template_Struct->status);
        break;

    default:
        wkey_log(LOG_ERROR, "Unknown Ines Type");
        break;
    }
}

void freeResultStruct(int type, void *input_Struct)
{

    struct CA_certificat_chain_t *CA_certificat_chain_Struct = input_Struct;
    struct CA_details_t *CA_details_Struct = input_Struct;
    struct certificate_t *certificate_Struct = input_Struct;
    struct certificate_status_t *certificate_Status_Struct = input_Struct;
    struct certificate_template_t *certificate_Template_Struct = input_Struct;


    switch (type)
    {
    case INES_RESPONSE_TYPE_CA_CERTIFICATE_CHAIN:
        if((CA_certificat_chain_Struct->root.subject) && (strcmp(CA_certificat_chain_Struct->root.subject,"NULL")!=0))
            free(CA_certificat_chain_Struct->root.subject);
        if((CA_certificat_chain_Struct->root.issuer) && (strcmp(CA_certificat_chain_Struct->root.issuer,"NULL")!=0))
            free(CA_certificat_chain_Struct->root.issuer);
        if((CA_certificat_chain_Struct->root.certificate) && (strcmp(CA_certificat_chain_Struct->root.certificate,"NULL")!=0))
            free(CA_certificat_chain_Struct->root.certificate);
        if((CA_certificat_chain_Struct->issuing.subject) && (strcmp(CA_certificat_chain_Struct->issuing.subject,"NULL")!=0))
            free(CA_certificat_chain_Struct->issuing.subject);        
        if((CA_certificat_chain_Struct->issuing.issuer) && (strcmp(CA_certificat_chain_Struct->issuing.issuer,"NULL")!=0))
            free(CA_certificat_chain_Struct->issuing.issuer);   
        if((CA_certificat_chain_Struct->issuing.certificate) && (strcmp(CA_certificat_chain_Struct->issuing.certificate,"NULL")!=0))
            free(CA_certificat_chain_Struct->issuing.certificate);   
        break;

    case INES_RESPONSE_TYPE_CA_DETAILS:
        if((CA_details_Struct->id) && (strcmp(CA_details_Struct->id,"NULL")!=0))
            free(CA_details_Struct->id);
        if((CA_details_Struct->caAlias) && (strcmp(CA_details_Struct->caAlias,"NULL")!=0))
            free(CA_details_Struct->caAlias);
        if((CA_details_Struct->thumbprint) && (strcmp(CA_details_Struct->thumbprint,"NULL")!=0))
            free(CA_details_Struct->thumbprint);
        if((CA_details_Struct->serverName) && (strcmp(CA_details_Struct->serverName,"NULL")!=0))
            free(CA_details_Struct->serverName);        
        if((CA_details_Struct->caName) && (strcmp(CA_details_Struct->caName,"NULL")!=0))
            free(CA_details_Struct->caName);   
        if((CA_details_Struct->description) && (strcmp(CA_details_Struct->description,"NULL")!=0))
            free(CA_details_Struct->description); 
        if((CA_details_Struct->certificate) && (strcmp(CA_details_Struct->certificate,"NULL")!=0))
            free(CA_details_Struct->certificate); 
        break;

    case INES_RESPONSE_TYPE_CERTIFICATE:
        if((certificate_Struct->certificate_id) && (strcmp(certificate_Struct->certificate_id,"NULL")!=0))
            free(certificate_Struct->certificate_id);
        if((certificate_Struct->organization_id) && (strcmp(certificate_Struct->organization_id,"NULL")!=0))
            free(certificate_Struct->organization_id);
        if((certificate_Struct->common_name) && (strcmp(certificate_Struct->common_name,"NULL")!=0))
            free(certificate_Struct->common_name);
        if((certificate_Struct->issued_dn) && (strcmp(certificate_Struct->issued_dn,"NULL")!=0))
            free(certificate_Struct->issued_dn);
        if((certificate_Struct->certificate) && (strcmp(certificate_Struct->certificate,"NULL")!=0))
            free(certificate_Struct->certificate);
        if((certificate_Struct->certificate_pkcs12) && (strcmp(certificate_Struct->certificate_pkcs12,"NULL")!=0))
            free(certificate_Struct->certificate_pkcs12);
        if((certificate_Struct->passphrase) && (strcmp(certificate_Struct->passphrase,"NULL")!=0))
            free(certificate_Struct->passphrase);
        if((certificate_Struct->status) && (strcmp(certificate_Struct->status,"NULL")!=0))
            free(certificate_Struct->status);
        if((certificate_Struct->issuer) && (strcmp(certificate_Struct->issuer,"NULL")!=0))
            free(certificate_Struct->issuer);
        if((certificate_Struct->serial_number) && (strcmp(certificate_Struct->serial_number,"NULL")!=0))
            free(certificate_Struct->serial_number);
        if((certificate_Struct->valid_from) && (strcmp(certificate_Struct->valid_from,"NULL")!=0))
            free(certificate_Struct->valid_from);
        if((certificate_Struct->valid_until) && (strcmp(certificate_Struct->valid_until,"NULL")!=0))
            free(certificate_Struct->valid_until);
        if((certificate_Struct->thumbprint) && (strcmp(certificate_Struct->thumbprint,"NULL")!=0))
            free(certificate_Struct->thumbprint);
        if((certificate_Struct->san) && (strcmp(certificate_Struct->san,"NULL")!=0))
            free(certificate_Struct->san);
        break;

    case INES_RESPONSE_TYPE_CERTIFICATE_STATUS:
        if((certificate_Status_Struct->status) && (strcmp(certificate_Status_Struct->status,"NULL")!=0))
            free(certificate_Status_Struct->status);
        if((certificate_Status_Struct->detail) && (strcmp(certificate_Status_Struct->detail,"NULL")!=0))
            free(certificate_Status_Struct->detail);
        if((certificate_Status_Struct->reason) && (strcmp(certificate_Status_Struct->reason,"NULL")!=0))
            free(certificate_Status_Struct->reason);
        if((certificate_Struct->revocation_date) && (strcmp(certificate_Status_Struct->revocation_date,"NULL")!=0))
            free(certificate_Status_Struct->revocation_date);
        break;

    case INES_RESPONSE_TYPE_CERTIFICATE_TEMPLATE:
        if((certificate_Template_Struct->description) && (strcmp(certificate_Template_Struct->description,"NULL")!=0))
            free(certificate_Template_Struct->description);
        if((certificate_Template_Struct->name) && (strcmp(certificate_Template_Struct->name,"NULL")!=0))
            free(certificate_Template_Struct->name);
        if((certificate_Template_Struct->organization_id) && (strcmp(certificate_Template_Struct->organization_id,"NULL")!=0))
            free(certificate_Template_Struct->organization_id);
        if((certificate_Template_Struct->status) && (strcmp(certificate_Template_Struct->status,"NULL")!=0))
            free(certificate_Template_Struct->status);
        if((certificate_Template_Struct->template_id) && (strcmp(certificate_Template_Struct->template_id,"NULL")!=0))
            free(certificate_Template_Struct->template_id);
        break;

    default:
        wkey_log(LOG_ERROR, "Unknown Ines Type");
        break;
    }
}

int checkCertificate(config_values_t config, char *certificate)
{
    int ret = -1;
    certificate_status_t certstatus = apiREST_getRevocationInformation(config, removeCertificateHeaders(certificate));
    displayResults(INES_RESPONSE_TYPE_CERTIFICATE_STATUS, &certstatus);

    if (strcmp("Good", certstatus.status) == 0)
    {
        ret = 0;
    }

    else if (strcmp("Revoked", certstatus.status) == 0)
    {
        ret = 1;
    }

    else if (strcmp("Expired", certstatus.status) == 0)
    {
        ret = 2;
    }

    return ret;
}

certificate_status_t apiREST_validateCertificate(config_values_t config, char *certificate)
{
    char *body = malloc(strlen("{\r\n\"certificate_data\": \"%s\"\r\n}") + strlen(certificate) + 1);
    sprintf(body, "{\r\n\"certificate_data\": \"%s\"\r\n}", certificate);
    certificate_status_t certficate_status = {"NULL", "NULL", "NULL", "NULL"};
    char *response = apiREST_process(config, POST_METHOD, IOT_API_REST_CERTIFICATE, IOT_API_REST_CERTIFICATE_VALIDATE_SUFFIX, body);

    if (!response)
        return certficate_status;

    char *response_body = extractHttpResponseBody(response);

    if (response)
        free(response);

    json_value *value = convertStringIntoJsontype(response_body);

    free(body);
    free(response_body);

    fillResultStruct(INES_RESPONSE_TYPE_CERTIFICATE_STATUS, &certficate_status, value);

    json_value_free(value);

    return certficate_status;
}

// REST Revokation state api
certificate_status_t apiREST_getRevocationInformation(config_values_t config, char *certificate)
{
    char *body = malloc(strlen("{\r\n\"certificate_data\": \"%s\"\r\n}") + strlen(certificate) + 1);

    sprintf(body, "{\r\n\"certificate_data\": \"%s\"\r\n}", certificate);
    certificate_status_t certficate = {"NULL", "NULL", "NULL", "NULL"};

    char *response = apiREST_process(config, POST_METHOD, IOT_API_REST_CERTIFICATE, IOT_API_REST_CERTIFICATE_STATUS_SUFFIX, body);

    if (!response)
        return certficate;

    char *response_body = extractHttpResponseBody(response);

    if (response)
        free(response);

    json_value *value = convertStringIntoJsontype(response_body);

    free(body);
    free(response_body);

    fillResultStruct(INES_RESPONSE_TYPE_CERTIFICATE_STATUS, &certficate, value);

    json_value_free(value);

    return certficate;
}
// REST Revokation state api

// certificate details by Id
certificate_t apiREST_getCertificateDetails(config_values_t config, char *thumbprint, int certID)
{
    char *customSufix = "NULL";

    certificate_t certficate = {"NULL", "NULL", "NULL", "NULL", "NULL", "NULL", "NULL", "NULL", "NULL", "NULL", "NULL", "NULL", "NULL", "NULL", "NULL", "NULL"};

    if ((thumbprint) && (certID != 0))
    {
        wkey_log(LOG_ERROR, "BAD ARGUMENT, fill only one of thumbprint or certID");
        return certficate;
    }

    if (certID > 0)
    {
        customSufix = malloc(12);
        sprintf(customSufix, "/%d", certID);
    }

    else if (thumbprint)
    {
        customSufix = malloc(strlen("/thumbprint/") + strlen(thumbprint) + 2);
        sprintf(customSufix, "/thumbprint/%s", thumbprint);
    }

    char *response = apiREST_process(config, GET_METHOD, IOT_API_REST_CERTIFICATE, customSufix, NULL);

    if (customSufix)
        free(customSufix);

    if (!response)
        return certficate;

    char *response_body = extractHttpResponseBody(response);

    if (response)
        free(response);

    json_value *value = convertStringIntoJsontype(response_body);

    if (response_body)
        free(response_body);

    fillResultStruct(INES_RESPONSE_TYPE_CERTIFICATE, &certficate, value);

    json_value_free(value);

    return certficate;
}

// End certificate details by Id

// Revoke certificate by Id
int apiREST_revokeCertificate(config_values_t config, int certId, int revocation_reason, char *revocationComment)
{

    char *bodyTemplate = "{\r\n\"revocation_reason\":\"%s\",\r\n\"revocationComment\":\"%s\"\r\n}";
    int ret = -1;
    char *revokeReason;

    switch (revocation_reason)
    {
    case REVOKE_KEY_COMPROMISE:
        revokeReason = "keyCompromise";
        break;
    case REVOKE_CA_COMPROMISE:
        revokeReason = "cACompromise";
        break;

    case REVOKE_AFFILIATION_CHANGED:
        revokeReason = "affiliationChanged";
        break;

    case REVOKE_SUPERSEDED:
        revokeReason = "superseded";
        break;

    case REVOKE_CESSATION_OF_OPERATION:
        revokeReason = "cessationOfOperation";
        break;

    case REVOKE_CERTIFICATE_HOLD:
        revokeReason = "certificateHold";
        break;

    case REVOKE_REMOVE_FROM_CRL:
        revokeReason = "removeFromCRL";
        break;

    case REVOKE_PRIVILEGE_WITHDRAW:
        revokeReason = "privilegeWithdrawn";
        break;

    case REVOKE_AA_COMPROMISE:
        revokeReason = "aACompromise";
        break;

    default:
        revokeReason = "unspecified";
        break;
    }

    char *customSufix = malloc(10 + strlen(IOT_API_REST_CERTIFICATE_REVOKE) + 1);
    char *body = malloc(strlen(revokeReason) + strlen(revocationComment) + strlen(bodyTemplate) + 1);

    sprintf(customSufix, "/%d%s", certId, IOT_API_REST_CERTIFICATE_REVOKE);
    sprintf(body, bodyTemplate, revokeReason, revocationComment);

    char *response = apiREST_process(config, POST_METHOD, IOT_API_REST_CERTIFICATE, customSufix, body);

    if (customSufix)
        free(customSufix);

    if (!response)
        return -1;

    char *response_body = extractHttpResponseBody(response);

    if (response)
        free(response);

    json_value *value = convertStringIntoJsontype(response_body);

    if (strcmp(extractJsonValue(value, "message", NULL), "OK") == 0)
    {
        wkey_log(LOG_SUCCESS, "Certificate Revoked");
        ret = 0;
    }

    if (response_body)
        free(response_body);

    json_value_free(value);

    return ret;
}

// Revoke certificate Id

// End REST API

// EST API
char *apiEST(config_values_t config,char* clientCert,char*clientKey,int mode, char *body, char *arbitraryLabel)
{
    char *certificate = "NULL";
    char *api = NULL;
    char *method = NULL;

    switch (mode)
    {
    case GET_CA_CERTIFICATE:
        if ((body) || (arbitraryLabel))
        {
            wkey_log(LOG_ERROR, "EST_API : bad argument");
            return "NULL";
        }

        method = GET_METHOD;
        api = malloc(strlen(IOT_API_EST_GET_CA) + 1);
        sprintf(api, IOT_API_EST_GET_CA);
        break;

    case GET_CA_CERTIFICATE_ARBITRARY_LABEL:
        if ((body) || (!arbitraryLabel))
        {
            wkey_log(LOG_ERROR, "EST_API : bad argument");
            return "NULL";
        }

        wkey_log(LOG_ERROR, "GET_CA_CERTIFICATE_ARBITRARY_LABEL not supported now");
        return "NULL";
        break;

    case ENROLL_CERTIFICATE:
        if ((!body) || (arbitraryLabel))
        {
            wkey_log(LOG_ERROR, "EST_API : bad argument");
            return "NULL";
        }
        method = POST_METHOD;
        api = malloc(strlen(IOT_API_EST_ENROLL_CERT) + 1);
        sprintf(api, IOT_API_EST_ENROLL_CERT);
        break;

    case ENROLL_CERTIFICATE_ARBITRARY_LABEL:
        if ((!body) || (!arbitraryLabel))
        {
            wkey_log(LOG_ERROR, "EST_API : bad argument");
            return "NULL";
        }

        wkey_log(LOG_ERROR, "ENROLL_CERTIFICATE_ARBITRARY_LABEL not supported now");
        return "NULL";
        break;

    case RE_ENROLL_CERTIFICATE:
        if ((!body) || (arbitraryLabel))
        {
            wkey_log(LOG_ERROR, "EST_API : bad argument");
            return "NULL";
        }
        method = POST_METHOD;
        api = malloc(strlen(IOT_API_EST_RE_ENROLL_CERT) + 1);
        sprintf(api, IOT_API_EST_RE_ENROLL_CERT);
        break;

    case RE_ENROLL_CERTIFICATE_ARBITRARY_LABEL:
        if ((!body) || (!arbitraryLabel))
        {
            wkey_log(LOG_ERROR, "EST_API : bad argument");
            return "NULL";
        }

        wkey_log(LOG_ERROR, "RE_ENROLL_CERTIFICATE_ARBITRARY_LABEL not supported now");
        return "NULL";
        break;

    case ENROLL_CERTIFICATE_SERVER_KEY_GEN:
        if ((!body) || (arbitraryLabel))
        {
            wkey_log(LOG_ERROR, "EST_API : bad argument");
            return "NULL";
        }
        method = POST_METHOD;
        api = malloc(strlen(IOT_API_EST_SERVER_KEY_GEN) + 1);
        sprintf(api, IOT_API_EST_SERVER_KEY_GEN);
        break;

    case ENROLL_CERTIFICATE_SERVER_KEY_GEN_ARBITRARY_LABEL:
        if ((!body) || (!arbitraryLabel))
        {
            wkey_log(LOG_ERROR, "EST_API : bad argument");
            return "NULL";
        }

        wkey_log(LOG_ERROR, "ENROLL_CERTIFICATE_SERVER_KEY_GEN_ARBITRARY_LABEL not supported now");
        return "NULL";
        break;

    default:
        wkey_log(LOG_ERROR, "Unexpected EST_API");
        return "NULL";
        break;
    }

    char *rawResponse = apiEST_process(config,clientCert,clientKey,method, api, NULL, body);

    if (api)
        free(api);

    char *responseCpy;

    if (rawResponse)
    {
        responseCpy = malloc(strlen(rawResponse) + 1);
        strcpy(responseCpy, rawResponse);
        certificate = extractHttpResponseBody(responseCpy);

        if (responseCpy)
            free(responseCpy);
    }
    else
        wkey_log(LOG_ERROR, "Error while requesting INES");

    if (rawResponse)
        free(rawResponse);

    return certificate;
}