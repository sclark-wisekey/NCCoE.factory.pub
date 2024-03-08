/*=======================================
SEAL SQ 2023
Zero-touch Provisioning
IoT / Tools / Provisioning / Firmware Team
=======================================*/

/**
 * \file wisekey_Tools.c
 * \brief Useful tools to use Ines SDK
 * \author BEDIOU
 * \version 1.3
 * \date 09/10/2023
 *
 * This files implements all the basic tools function to use Ines SDK
 *
 */


// System libs
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>

#ifndef WIN32
#include <unistd.h>
#include <sys/time.h>
#endif

// SEAL SQ libs
#include "wisekey_Tools.h"
#include "wisekey_Crypto_Tools.h"

#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/pwdbased.h>

#include "../lib/ini/ini.h"
#include "../lib/json/json.h"


#define SALT_SIZE 8

char *createDeviceName(config_values_t config)
{
    int rand_value;
    char *device_name;

    if(!config.DEVICE_NAME_PREFIX)
    {
        device_name = malloc(strlen("WKEY_ZTOUCH_DEFAULT_NAME") + 1);
        wkey_log(LOG_INFO,"DEFAULT NAME");
        sprintf(device_name,"%s" ,"WKEY_ZTOUCH_DEFAULT_NAME");
        return device_name;

    }

    srand((unsigned int)time(NULL));

    for (int i = 0; i != 10; i++)
    {
        rand_value = rand() % 10001;
    }

    device_name = malloc(strlen(config.DEVICE_NAME_PREFIX) + 6 + 1);

    sprintf(device_name,"%s_%d" ,config.DEVICE_NAME_PREFIX, rand_value);

    return device_name;
}

void rebootEsp()
{    
    wkey_log(LOG_WARNING, "Restarting ESP...");
    for (int i = 5; i >= 0; i--)
    {
    }
    fflush(stdout);
    //esp_restart();
}

char *openFile(const char *path)
{
    struct stat stat_file;
    stat(path, &stat_file);
    char *buff = malloc(stat_file.st_size + 10);

    FILE *file = fopen(path, "r");

    if (file == NULL)
    {
        wkey_log(LOG_ERROR, "Invalid path file: %s", path);
        rebootEsp();
    }

    fread(buff, 1, stat_file.st_size, file);
    fclose(file);

    if (buff[stat_file.st_size - 1] == '\n')
    {
        buff[stat_file.st_size - 1] = '\0';
    }
    else
    {
        buff[stat_file.st_size] = '\0';
    }
    return buff;
}


int checkCertificateAndKeyDisponibility(config_values_t config)
{
    struct stat st;

    if (stat(config.DEVICE_CERT_PATH, &st) != 0) {
        wkey_log(LOG_ERROR, "File %s doesn't exist",config.DEVICE_CERT_PATH);
        return -1;

    }

    if (stat(config.SECURE_KEY_PATH, &st) != 0) {
        wkey_log(LOG_ERROR, "File %s doesn't exist",config.SECURE_KEY_PATH);
        return -1;
    }
    return 0;
}

char *inesRawCartificatetoFormatedcert(char *rawCert)
{
    const char *separators = "\\";
	char tempRawCert[MAXCSR] = { 0 };

    char *strseparated = strtok(rawCert, separators);
    char *template = "-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n";
    char *formatedCertificate;

    while (strseparated != NULL)
    {
        if (strseparated[0] == 'n')
        {
            strseparated[0] = '\n';
        }
        strcat(tempRawCert, strseparated);
        strseparated = strtok(NULL, separators);
    }

    formatedCertificate = malloc(strlen(template) + strlen(rawCert) + 10);
    sprintf(formatedCertificate, template, rawCert);

    return formatedCertificate;
}

char *estRawCartificatetoFormatedcert(char *rawCert)
{
    char *template = "-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n";
    char *formatedCertificate;

    char*tempcert = malloc(strlen(rawCert)+1);

    sprintf(tempcert,rawCert);
    
    char* detect = strstr(tempcert,"AADEAAAAAAAAA");
    if(detect)
    {
        sprintf(detect,"=");
    }

    detect = strstr(tempcert,"AAAxAAAAAAAAAA==");
    if(detect)
    {
        sprintf(detect,"%c",'\0');
    }

    detect = strstr(tempcert,"AAMQAAAAAAAAA=");
    if(detect)
    {
        sprintf(detect,"==");
    }

    detect = strstr(tempcert,"MII");
    if(detect)
    {
        sprintf(tempcert,"%s",detect);
    }

    formatedCertificate = malloc(strlen(template) + strlen(tempcert) + 1);
    sprintf(formatedCertificate, template, tempcert);
    free(tempcert);

    return formatedCertificate;
}

int writeAndSaveFile(char *name, char *content, int size)
{
    /* Variable to store user content */
    FILE *file = NULL;
    int ret = -1;

    file = fopen(name, "wb");
    unsigned long err = 0;
    if (file)
    {
        ret = (int)fwrite(content, 1, size, file);
        fclose(file);
    }
	else
	{
#ifdef _WIN32
		err = GetLastError();
		printf("fopen error: %i\nFile: %s\n", err, name);
#endif
	}

    return ret;
}

json_value* convertStringIntoJsontype(char* string)
{
    int file_size;
    json_value* value;

    file_size = strlen(string);
    char*cpy;

    if(string)
    {
        cpy = strstr(string,"{");
        sprintf(string,cpy);
        cpy = strrchr(string,'}');
        sprintf(cpy+1,"%c",'\0');
    }
    else
        return NULL;
        
    value = json_parse(string,file_size);

    if (value == NULL) {
            fprintf(stderr, "Unable to parse data\n");
            return NULL;
    }

    return value;
}

static char* process_value(json_value*value)
{
    char* returnvalue=NULL;

    switch (value->type)
    {
        case json_none:
                break;
        case json_null:
                returnvalue =NULL;
        case json_object:   
                break;
        case json_array:
                break;
        case json_integer:
                returnvalue = malloc(11);
                sprintf(returnvalue,"%ld",(long)value->u.integer);
                break;
        case json_double:
                returnvalue= malloc(12);
                sprintf(returnvalue,"%f",value->u.dbl);
                break;
        case json_string:
                returnvalue= malloc(strlen(value->u.string.ptr)+1);
                sprintf(returnvalue,"%s",value->u.string.ptr);
        case json_boolean:
                //wkey_log(LOG_ERROR,"Unexpected JSON type Boolean");
                break;
        default:
            break;
    }

    return returnvalue;
}

char *extractJsonValue(json_value* value, char*object,char*object2)
{
        int length,length2;

        if (value == NULL) {
                return NULL;
        }

        length = value->u.object.length;

        for (int x = 0; x < length; x++) {
                if(strcmp(value->u.object.values[x].name,object)==0)
                {
                    if(object2)
                    {

                        length2 = value->u.object.values[x].value->u.object.length; 
                        for (int y = 0; y < length2; y++) 
                        {
                            if(strcmp(value->u.object.values[x].value->u.object.values[y].name,object2)==0)
                                {      
                                    return process_value(value->u.object.values[x].value->u.object.values[y].value);
                                }
                        }
                    }
                    else
                        return process_value(value->u.object.values[x].value);
                }
        }
    
    return NULL;
}

int storeJsonValueIntoStructValue(char**structValue,json_value*value, char* object,char*object2)
{
    char *valuetostore = extractJsonValue(value, object,object2);

    if(valuetostore)
    {
        *structValue = malloc(strlen(valuetostore)+1); 
        memset(*structValue,0,strlen(valuetostore)+1);
        strncpy(*structValue,valuetostore,strlen(valuetostore));
        free(valuetostore);
        return 0;
    }
    else
    {
        *structValue="NULL";
    }
    

    return -1;
}

void wkey_log(int type, char *fmt, ...)
{

    //va_list ap; /* points to each unnamed arg in turn */
    //char *p, *sval;
    //int ival;
    //double dval;
    //va_start(ap, fmt); /* make ap point to 1st unnamed arg */

    switch (type)
    {
    case LOG_WARNING:
        printf("WKEY WARNING : %s\r\n", fmt);
        break;
    case LOG_STEP_INDICATOR:
        printf("WKEY STEP : %s\r\n", fmt);
        break;

    case LOG_ERROR:
        printf("WKEY ERROR : %s\r\n", fmt);
        break;

    case LOG_DEBUGING:
        printf("WKEY DEBUGING INFO : %s\r\n", fmt);
        break;
        
    case LOG_SUCCESS:
        printf("WKEY SUCCESS : %s\r\n", fmt);
        break;

    default:
        printf("WKEY INFO : %s\r\n", fmt);
        break;
    }

    //for (p = fmt; *p; p++)
    //{
    //    if (*p != '%')
    //    {
    //        putchar(*p);
    //        continue;
    //    }
    //    switch (*++p)
    //    {
    //    case 'd':
    //        ival = va_arg(ap, int);
    //        printf("%d", ival);
    //        break;
    //    case 'f':
    //        dval = va_arg(ap, double);
    //        printf("%f", dval);
    //        break;
    //    case 's':
    //        for (sval = va_arg(ap, char *); *sval; sval++)
    //            putchar(*sval);
    //        break;
    //    default:
    //        putchar(*p);
    //        break;
    //    }
    //}

    //printf("\e[0m\r\n");
    //va_end(ap); /* clean up when done */
}


