/*=======================================
SEAL SQ 2023
Zero-touch Provisioning
IoT / Tools / Provisioning / Firmware Team
=======================================*/

// System libs
#include <stdio.h>      /* printf, sprintf */
#include <stdlib.h>     /* exit, atoi, malloc, free */
#include <stdint.h>     /* uint8_t, ... */
#include <string.h>     /* memcpy, memset */
#include <time.h>
#include <fcntl.h>

#ifndef WIN32
#include <unistd.h>     /* read, write, close */
#include <sys/socket.h> /* socket, connect */
#include <netinet/in.h> /* struct sockaddr_in, struct sockaddr */
#include <netdb.h>      /* struct hostent, gethostbyname */

/* socket includes */
#include <arpa/inet.h>
#endif

// SEAL SQ libs
#include "wisekey_Ines_settings.h"
#include "wisekey_Tools.h"
#include "wisekey_Crypto_Tools.h"
#include "wisekey_Http_Request_Manager.h"

/* wolfSSL */
#include <wolfssl/ssl.h>
#include <wolfssl/error-ssl.h>


typedef unsigned char byte;

#define MAXLINE 32768

#define DEFAULT_PORT 11111

//byte InesCA[] = "-----BEGIN CERTIFICATE-----\n\
//MIIDtTCCAp2gAwIBAgIQdrEgUnTwhYdGs/gjGvbCwDANBgkqhkiG9w0BAQsFADBt\n\
//MQswCQYDVQQGEwJDSDEQMA4GA1UEChMHV0lTZUtleTEiMCAGA1UECxMZT0lTVEUg\n\
//Rm91bmRhdGlvbiBFbmRvcnNlZDEoMCYGA1UEAxMfT0lTVEUgV0lTZUtleSBHbG9i\n\
//YWwgUm9vdCBHQiBDQTAeFw0xNDEyMDExNTAwMzJaFw0zOTEyMDExNTEwMzFaMG0x\n\
//CzAJBgNVBAYTAkNIMRAwDgYDVQQKEwdXSVNlS2V5MSIwIAYDVQQLExlPSVNURSBG\n\
//b3VuZGF0aW9uIEVuZG9yc2VkMSgwJgYDVQQDEx9PSVNURSBXSVNlS2V5IEdsb2Jh\n\
//bCBSb290IEdCIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2Be3\n\
//HEokKtaXscriHvt9OO+Y9bI5mE4nuBFde9IllIiCFSZqGzG7qFshISvYD06fWvGx\n\
//WuR51jIjK+FTzJlFXHtPrby/h0oLS5daqPZI7H17Dc0hBt+eFf1Biki3IPShehtX\n\
//1F1Q/7pn2COZH8g/497/b1t3sWtuuMlk9+HKQUYOKXHQuSP8yYFfTvdv37+ErXNk\n\
//u7dCjmn21HYdfp2nuFeKUWdy19SouJVUQHMD9ur06/4oQnc/nSMbsrY9gBQHTC5P\n\
//99UKFg29ZkM3fiNDecNAhvVMKdqOmq0NpQSHiB6F4+lT1ZvIiwNjeOvgGUpuuy9r\n\
//M2RYk61pv48b74JIxwIDAQABo1EwTzALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUw\n\
//AwEB/zAdBgNVHQ4EFgQUNQ/INmNe4qPs+TtmFc5RUuORmj0wEAYJKwYBBAGCNxUB\n\
//BAMCAQAwDQYJKoZIhvcNAQELBQADggEBAEBM+4eymYGQfp3FsLAmzYh7KzKNbrgh\n\
//cViXfa43FK8+5/ea4n32cZiZBKpDdHij40lhPnOMTZTg+XHEthYOU3gf1qKHLwI5\n\
//gSk8rxWYITD+KJAAjNHhy/peyP34EEY7onhCkRd0VQreUGdNZtGn//3ZwLWoo4rO\n\
//ZvUPQ82nK1d7Y0Zqqi5S2PTt4W2tKZB4SLrhI6qjiey1q5bAtEuiHZeeevJuQHHf\n\
//aPFlTc58Bd9TZaml8LGXBHAVRgOY1NK/VLSgWH1Sb9pWJmLU2NuJMW8c8CLC02Ic\n\
//Nc1MaRVUGpCY3useX8p3x8uOPUNpnJpY0CQ73xtAln41rYHHTnG6iBM=\n\
//-----END CERTIFICATE-----";




//byte InesCA[] = "-----BEGIN CERTIFICATE-----\n\
//MIICaTCCAe+gAwIBAgIQISpWDK7aDKtARb8roi066jAKBggqhkjOPQQDAzBtMQsw\n\
//CQYDVQQGEwJDSDEQMA4GA1UEChMHV0lTZUtleTEiMCAGA1UECxMZT0lTVEUgRm91\n\
//bmRhdGlvbiBFbmRvcnNlZDEoMCYGA1UEAxMfT0lTVEUgV0lTZUtleSBHbG9iYWwg\n\
//Um9vdCBHQyBDQTAeFw0xNzA1MDkwOTQ4MzRaFw00MjA1MDkwOTU4MzNaMG0xCzAJ\n\
//BgNVBAYTAkNIMRAwDgYDVQQKEwdXSVNlS2V5MSIwIAYDVQQLExlPSVNURSBGb3Vu\n\
//ZGF0aW9uIEVuZG9yc2VkMSgwJgYDVQQDEx9PSVNURSBXSVNlS2V5IEdsb2JhbCBS\n\
//b290IEdDIENBMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAETOlQwMYPchi82PG6s4ni\n\
//eUqjFqdrVCTbUf/q9Akkwwsin8tqJ4KBDdLArzHkdIJuyiXZjHWd8dvQmqJLIX4W\n\
//p2OQ0jnUsYd4XxiWD1AbNTcPasbc2RNNpI6QN+a9WzGRo1QwUjAOBgNVHQ8BAf8E\n\
//BAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUSIcUrOPDnpBgOtfKie7T\n\
//rYy0UGYwEAYJKwYBBAGCNxUBBAMCAQAwCgYIKoZIzj0EAwMDaAAwZQIwJsdpW9zV\n\
//57LnyAyMjMPdeYwbY9XJUpROTYJKcx6ygISpJcBMWm1JKWB4E+J+SOtkAjEA2zQg\n\
//Mgj/mkkCtojeFK9dbJlxjRo/i9fgojaGHAeCOnZT/cKi7e97sIBPWA9LUzm9\n\
//-----END CERTIFICATE-----";

//byte InesCA[] = "-----BEGIN CERTIFICATE-----\n\
//MIIGkjCCBXqgAwIBAgIUbNtGETexHfEFQXKJsrzYzVL4bKAwDQYJKoZIhvcNAQEL\n\
//BQAwRzELMAkGA1UEBhMCQ0gxEDAOBgNVBAoTB1dJU2VLZXkxJjAkBgNVBAMTHVdJ\n\
//U2VLZXkgQ2VydGlmeUlEIFNTTCBHQiBDQSAyMB4XDTI0MDUxMDA5NTUwNloXDTI1\n\
//MDUxMDIzNTk1OVowHDEaMBgGA1UEAwwRY2VydGlmeWlkZGVtby5jb20wggEiMA0G\n\
//CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDdrFTD3ZErIvIa9aK8MBXUN8/g8TkJ\n\
//CQ4Sa3gEwSN5LOf0n29KnUKv8RNXAbPEthQVXb/fqcqgXqfblAmNFwByg+1dST57\n\
//ukZGEaSpgLtuscXBq+MGe+AYXPH5J4L9q95kofZAhVaLNPA3I2GbQCYhyISiCowo\n\
//irsrfDV4FGPnhp4eL3oP0hYQciPa2gu7O9XL6UxmrSLFX0W5edomchHpPDRg53aT\n\
//wcpGswC7fGI+8xIzYNygIi2sCl6eRKXUGwNlLuOFob+mabINx2+VI1IR1mqzM8PY\n\
//UkJ2FfNb8U+Jjx4sZkoNIehXqw3IxgE5reej8NiuzdmdqfBpj6jo3mSxAgMBAAGj\n\
//ggOfMIIDmzAMBgNVHRMBAf8EAjAAMB8GA1UdIwQYMBaAFF8bxQp7OH0+w7cxv6T7\n\
//FCNS4Y0bMG8GCCsGAQUFBwEBBGMwYTA6BggrBgEFBQcwAoYuaHR0cDovL3B1Ymxp\n\
//Yy53aXNla2V5LmNvbS9jcnQvd2NpZHNzbGdiY2EyLmNlcjAjBggrBgEFBQcwAYYX\n\
//aHR0cDovL29jc3Aud2lzZWtleS5jb20wgZ8GA1UdEQSBlzCBlIIRY2VydGlmeWlk\n\
//ZGVtby5jb22CEyouY2VydGlmeWlkZGVtby5jb22CEGNlcnRpZnlpZGRldi5jb22C\n\
//EiouY2VydGlmeWlkZGV2LmNvbYIOd2lzZWtleWRldi5jb22CECoud2lzZWtleWRl\n\
//di5jb22CD3dpc2VrZXlkZW1vLmNvbYIRKi53aXNla2V5ZGVtby5jb20wRQYDVR0g\n\
//BD4wPDA6BgZngQwBAgEwMDAuBggrBgEFBQcCARYiaHR0cDovL3d3dy53aXNla2V5\n\
//LmNvbS9yZXBvc2l0b3J5LzAdBgNVHSUEFjAUBggrBgEFBQcDAgYIKwYBBQUHAwEw\n\
//PwYDVR0fBDgwNjA0oDKgMIYuaHR0cDovL3B1YmxpYy53aXNla2V5LmNvbS9jcmwv\n\
//d2NpZHNzbGdiY2EyLmNybDAdBgNVHQ4EFgQUVNpJd6vglmL0KoSLpPx2bMNzkN4w\n\
//DgYDVR0PAQH/BAQDAgWgMIIBfwYKKwYBBAHWeQIEAgSCAW8EggFrAWkAdgDPEVbu\n\
//1S58r/OHW9lpLpvpGnFnSrAX7KwB0lt3zsw7CAAAAY9h7YiQAAAEAwBHMEUCIQCs\n\
//QQu6zN2mqV+eYhaoCKw67G62Lj4tco/p0c66WeGgFAIgbO1Y2H0PhPqE+FoL+HPb\n\
//nf3/5iwUu2Unym1T0Y7AgAQAdgBOdaMnXJoQwzhbbNTfP1LrHfDgjhuNacCx+mSx\n\
//Ypo53wAAAY9h7YjCAAAEAwBHMEUCICU0Rbq5WY8M+IKo2Kh6zD0v9CQRNhNrm1It\n\
//UMzSrfjjAiEAllxdCpKFzLoq3W16V2oW0pCHDM9wJUOKRtJexOi1ZVIAdwATSt8a\n\
//tZhCCXgMb+9MepGkFrcjSc5YV2rfrtqnwqvgIgAAAY9h7YjiAAAEAwBIMEYCIQDd\n\
//y3utnddEIXAZO3Z0bgzMv9/ZjtZFYCGw/PFCAFUUGwIhAIYIXZBPEU/jql7npCHg\n\
//UQVS2iBHz0hsiC0sngrgrgrOMA0GCSqGSIb3DQEBCwUAA4IBAQAINCoLBdiiGOEZ\n\
//N5Srm9HXjvIsUJpE/7XxWEsXwIIHDVno8rKcgNTMU/98rLwOy3//+/elVgE8cXnb\n\
//RwuCig5FOi868905t+mXVzW5gUnck0wAU2TUVF/k0HSEvNl1c0TgMmY+gPkRECPP\n\
//NIptgn4AIz9QeI6D3y/2ka4Qe1jSprkzGXpMwHg55d3aR4Li9iTNUHDRDr05Ian1\n\
//KRrWPPhw4XUyklqHvXNIB/ehxOfMiXQU7jBniB8cJgPpS1rx6tkg/Cv0GdVlUzEA\n\
//BcGKPP5B1ZkFdUUfEtSxkgJH/55b1jLDck0PMWF8ggVxeamMhXM838sMJcCCOYXd\n\
//a4/707LQ\n\
//-----END CERTIFICATE-----";


/* Constants that aren't configurable in menuconfig */
#define WEB_PORT "443"

struct https_handler{
    int status;
    char* response;
    char *host;
    char *message;
}Handler_https;

//extern const uint8_t client_cert_pem_start[] asm("_binary_client_cert_pem_start");
//extern const uint8_t client_cert_pem_end[]   asm("_binary_client_cert_pem_end");
//
//extern const uint8_t client_key_pem_start[] asm("_binary_client_key_pem_start");
//extern const uint8_t client_key_pem_end[]   asm("_binary_client_key_pem_end");

#define BUFFER_SIZE 16000

int httpsRequestWolf(char*clientCertPath,char*clientKeyPath)
{
    int                sockfd;
    struct sockaddr_in servAddr;
	struct hostent     *he;
    int                ret;
    /* declare wolfSSL objects */
    WOLFSSL_CTX* ctx;
    WOLFSSL*     ssl;


	// Start TCP to enable socket connection
	StartTCP();

    /* Check for proper calling convention */

    /* Create a socket that uses an internet IPv4 address,
     * Sets the socket to be stream based (TCP),
     * 0 means choose the default protocol. */
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        fprintf(stderr, "ERROR: failed to create the socket\n");
        ret = -1;
        return -1;
    }

	/* Initialize the server address struct with zeros */
    memset(&servAddr, 0, sizeof(servAddr));

	/* resolve hostname */
	if ((he = gethostbyname(Handler_https.host)) == NULL) {
		wkey_log(LOG_ERROR, "ERROR: gethostbyname\n");
	}

	/* copy the network address to sockaddr_in structure */
	memcpy(&servAddr.sin_addr, he->h_addr_list[0], he->h_length);
	servAddr.sin_family = AF_INET;             /* using IPv4      */
	servAddr.sin_port = htons(443); /* on DEFAULT_PORT */

	/* Connect to the server */
	if ((ret = connect(sockfd, (struct sockaddr*) &servAddr, sizeof(servAddr)))
		== -1) {
		fprintf(stderr, "ERROR: failed to connect\n");
		ret = -1;
		return ret;
	}
	wolfSSL_Debugging_ON();
    

    /*---------------------------------*/
    /* Start of wolfSSL initialization and configuration */
    /*---------------------------------*/
    /* Initialize wolfSSL */
    if ((ret = wolfSSL_Init()) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "ERROR: Failed to initialize the library\n");
        close(sockfd);          /* Close the connection to the server       */;
        ret = -1;
        return ret;
    }

    /* Create and initialize WOLFSSL_CTX */
    if ((ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method())) == NULL) {
        fprintf(stderr, "ERROR: failed to create WOLFSSL_CTX\n");
        ret = -1;
        close(sockfd);          /* Close the connection to the server       */;
        return ret;
    }

    // Load the Trusted Root CAs from the OS (stored in the Certificate Manager on Windows)
	if ((ret = wolfSSL_CTX_load_system_CA_certs(ctx)) != SSL_SUCCESS) {
		fprintf(stderr, "ERROR: failed to load CA err !%d\n", ret);
		wolfSSL_CTX_free(ctx);
		wolfSSL_Cleanup();
		ret = -1;
		return ret;
	}

    //if ((ret = wolfSSL_CTX_load_verify_locations(ctx, CA_FILE, NULL))
    //if ((ret = wolfSSL_CTX_load_verify_buffer(ctx, InesCA, sizeof(InesCA),SSL_FILETYPE_PEM))!= SSL_SUCCESS) {
    //    fprintf(stderr, "ERROR: failed to load CA err !%d\n",ret);
    //    wolfSSL_CTX_free(ctx);  /* Free the wolfSSL context object          */
    //    wolfSSL_Cleanup();
    //    ret = -1;
    //    return ret;
    //}

    // Load client certificates into WOLFSSL_CTX
    if ((ret =  wolfSSL_CTX_use_certificate_file(ctx, clientCertPath,SSL_FILETYPE_PEM)) != SSL_SUCCESS) {
        fprintf(stderr, "ERROR: %d failed to load client certificate %s, please check the file.\n", ret,clientCertPath);
        wolfSSL_CTX_free(ctx);  /* Free the wolfSSL context object          */
        wolfSSL_Cleanup();
        ret = -1;
        return ret;
    }

    if ((ret =  wolfSSL_CTX_use_PrivateKey_file(ctx, clientKeyPath,SSL_FILETYPE_PEM)) != SSL_SUCCESS) {
        fprintf(stderr, "ERROR: %d failed to load client key %s, please check the file.\n", ret,clientKeyPath);
        wolfSSL_CTX_free(ctx);  /* Free the wolfSSL context object          */
        wolfSSL_Cleanup();
        ret = -1;
        return ret;
    }

	//// Set Context to use renegotiation
	//if ((ret = wolfSSL_CTX_UseSecureRenegotiation(ctx))
	//	!= SSL_SUCCESS) {
	//	fprintf(stderr, "ERROR: wolfSSL_CTX_UseSecureRenegotiation %d\n", ret);
	//	wolfSSL_CTX_free(ctx);  /* Free the wolfSSL context object          */
	//	wolfSSL_Cleanup();
	//	ret = -1;
	//	return ret;
	//}

	//// Set the cipher list 
	//const char* cipherlist = "ECDHE-ECDSA-AES128-GCM-SHA256";
	//if ((ret = wolfSSL_CTX_set_cipher_list(ctx, cipherlist)) != WOLFSSL_SUCCESS) {
	//	fprintf(stderr, "ERROR: failed to set cipher list.\n");
	//	ret = -1;
	//	wolfSSL_CTX_free(ctx);  /* Free the wolfSSL context object          */
	//	wolfSSL_Cleanup();
	//	ret = -1;
	//	return ret;
	//}

	/* Create a WOLFSSL object */
    if ((ssl = wolfSSL_new(ctx)) == NULL) {
        fprintf(stderr, "ERROR: failed to create WOLFSSL object\n");
        ret = -1;
        wolfSSL_CTX_free(ctx);  /* Free the wolfSSL context object          */
        wolfSSL_Cleanup();
        ret = -1;
        return ret;
    }
    

    /* Attach wolfSSL to the socket */
    if ((ret = wolfSSL_set_fd(ssl, sockfd)) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "ERROR: Failed to set the file descriptor\n");
        wolfSSL_free(ssl);
        ret = -1;
        return ret;
    }

	//if ((ret = wolfSSL_UseSecureRenegotiation(ssl)) != WOLFSSL_SUCCESS) {
	//	fprintf(stderr, "ERROR: wolfSSL_UseSecureRenegotiation %d\n", ret);
	//	wolfSSL_free(ssl);
	//	ret = -1;
	//	return ret;
	//}

    /* Connect to wolfSSL on the server side */
    if ((ret = wolfSSL_connect(ssl)) != SSL_SUCCESS) {
        fprintf(stderr, "ERROR: failed to connect to wolfSSL errno = %d\n",ret);
        wolfSSL_free(ssl);
        ret = -1;
        return ret;
    }

	// Print the raw request
	printf("\nINeS Request Message: \n%s\n", Handler_https.message);


    /* Send the message to the server */
    if ((ret = wolfSSL_write(ssl, Handler_https.message, strlen(Handler_https.message))) != strlen(Handler_https.message)) {
        fprintf(stderr, "ERROR: failed to write entire message\n");
        fprintf(stderr, "%d bytes of %d bytes were sent", ret, strlen(Handler_https.message));
        wolfSSL_free(ssl);
        ret = -1;
        return ret;
    }

	char response[BUFFER_SIZE] = { 0 };

    /* Read the server data into our buff array */
    memset(response, 0, BUFFER_SIZE);
    if ((ret = wolfSSL_read(ssl, response, BUFFER_SIZE-1)) == -1) {
        fprintf(stderr, "ERROR: failed to read\n");
        //wolfSSL_free(ssl);
        ret = -1;
        return ret; 
    }

	// Print the raw response
	printf("\nINeS Response: \n%s\n", response);

	// If there was no response, then return error status
	int responseSize = strlen(response) + 1;
	if (responseSize < 2)
	{
		ret = -1;
		Handler_https.status = -1;
		return ret;
	}

	// If there was a response, then allocate the Handler_https.response buffer and copy the response
	Handler_https.response=malloc(responseSize);
	sprintf(Handler_https.response,"%s",response);

	// Shut down and return
	wolfSSL_shutdown(ssl);

    Handler_https.status=0;
    ret = 0;
    return ret;
}

char *generateHttpHeader(char *host, int protocol,char *api, char *body, char *accesstoken)
{
    char *headers = "";
    int headers_size = 0;
    char *contentLen = "0";

    if(body){
        contentLen = malloc(11);
        sprintf(contentLen, "%d", strlen(body));
    }
    char *contentType;

    if(protocol==API_EST)
        contentType=PKCS7_CONTENT_TYPE;
    else
        contentType=JSON_CONTENT_TYPE;

    char *accesstokenTemplate = "%s: Bearer %s \r\n";
    char *accesstokenheader = "";

    if (accesstoken)
    {
        accesstokenheader = malloc(strlen(accesstokenTemplate) + strlen(HEADER_AUTHORIZATION) + strlen(accesstoken) +1);
        sprintf(accesstokenheader, accesstokenTemplate, HEADER_AUTHORIZATION, accesstoken);
    }

    // Message Template
    char *normalRequestTemplate = "%s: %s\r\n%s%s: %s\r\n%s: %s\r\n%s: %s\r\n";
    // Message Size
    headers_size += strlen(normalRequestTemplate);
    headers_size += strlen(HEADER_USER_AGENT) + strlen(USER_AGENT);
    headers_size += strlen(HEADER_CONTENT_TYPE) + strlen(HEADER_CONTENT_LENGTH);
    headers_size += strlen(HEADER_ACCEPT) + strlen(ACCEPT_VALUE);
    headers_size += strlen(contentType) + strlen(contentLen) + strlen(accesstokenheader) + 1;
    headers = malloc(headers_size);

    sprintf(headers, normalRequestTemplate, 
            HEADER_USER_AGENT, USER_AGENT,
            accesstokenheader, 
            HEADER_CONTENT_TYPE, contentType, 
            HEADER_ACCEPT, ACCEPT_VALUE,
            HEADER_CONTENT_LENGTH, contentLen);

    if (accesstoken)
    {
        free(accesstokenheader);
    }

    if(body)
    {
        free(contentLen);
    }

    return headers;
}

char *generateCSRBody(char *templateId, char *subjects, char *CSR, int lenCSR, int validityPeriodDays)
{
    char *bodytemplate = "{\"template_id\": %s,\"subject\": %s,\"san\":[{\"name\": \"dns\",\"value\": \"wisekeydemo.com\"}], \"csr\": \"%s\" ,\"passphrase\": \"\",\"include_chain_in_pkcs12\": true, \"valid_from\": \"\", \"validity_period\": %d}";

	// Remove the header/footer for the INeS call
	char* rawCSR = removeCSR_Headers(CSR);

	if (lenCSR > MAXCSR)
	{
		printf("CSR is %u bytes, this exceeds maximum CSR size of %u", strlen(CSR) + 1, MAXCSR);
		return NULL;
	}
	//char csrcpy[MAXCSR] = { 0 };
	//strncpy(csrcpy, CSR, lenCSR);

	//const char *separators = "\r\n";
	//char *CSRtreated = malloc(strlen(CSR) + 10);

	//memset(CSRtreated, 0, strlen(CSR) + 10);
	//char *strseparated = strtok(csrcpy, separators);

	//while (strseparated != NULL)
	//{
	//	strcat(CSRtreated, "\\n");
	//	strcat(CSRtreated, strseparated);
	//	strseparated = strtok(NULL, separators);
	//}

	char *body = malloc(strlen(bodytemplate) + strlen(templateId) + strlen(rawCSR) + strlen(subjects) + 4 /*validityPeriodDays*/ + 1);
	sprintf(body, bodytemplate, templateId, subjects, rawCSR, validityPeriodDays);

	//if (CSRtreated)
	//	free(CSRtreated);

	return body;
}

char *httpsRequest(char*clientCertPath,char*clientKeyPath,char *host,char* method,char *path, char *headers, char *body)
{
    Handler_https.status=1;
    Handler_https.host=host;
    char* httpMessageTemplate = "%s %s HTTP/1.1\r\nHost: %s\r\n";
    char* response=NULL;
    int message_size;
    
    /* How big is the message? */
    message_size = 0;
    message_size += strlen(httpMessageTemplate);
    message_size += strlen(method); /* method         */
    message_size += strlen(host);
    message_size += strlen(path); /* path           */
    message_size += strlen("\r\n");
    message_size += 4;

    if (headers)
    {
        message_size += strlen(headers);
    }

    if (body)
    {
        message_size += strlen(body);
    }

    /* allocate space for the message */
    Handler_https.message = malloc(message_size);

    sprintf(Handler_https.message, httpMessageTemplate, method,path, host); /*path*/

    if (headers)
    {
        strcat(Handler_https.message, headers);
    }
    
    strcat(Handler_https.message, "\r\n");

    if (body)
    {
        strcat(Handler_https.message, body);
    }

    if(httpsRequestWolf(clientCertPath,clientKeyPath)!=0)
    {
      return NULL;
    }    

    while(1)
    {
        if(Handler_https.status==0)
            break;
    }

    if(Handler_https.message)
        free(Handler_https.message);
    
    if(!Handler_https.response || strlen(Handler_https.response)<2)
        return NULL;

    response = malloc(strlen(Handler_https.response)+1);
    strcpy(response,Handler_https.response);
    
    if(Handler_https.response)
        free(Handler_https.response);
    
    return response;
}

char* extractHttpResponseBody(char* response)
{
    char* body=NULL;
    for(size_t i = 0;i<strlen(response);i++)
    {
        if(response[i]=='\r')
            if(response[i+1]=='\n')
                    if(response[i+2]=='\r')
                        if(response[i+3]=='\n')
                        {
                            body = malloc(strlen(response)+1-i-4);
                            sprintf(body,"%s",response+i+4);
                            break;
                        }

    }
    return body;

}


//INES SDK V1
char *inesApi(char* clientCert,char*clientKey,char* host,int protocol,char *pathPrefix, char *inesOrgId,char *accessToken,char* method,char* apiname, char* custom_suffix,char* body)
{
    int api_Str_Size;
    char *response;

    api_Str_Size = strlen("https://")+strlen(host) + strlen(pathPrefix) + strlen(apiname)+ 1;
    
    if(inesOrgId){
        api_Str_Size += strlen(REST_ORGANIZATION_PREFIX);
        api_Str_Size += strlen("/");
        api_Str_Size += strlen(inesOrgId);
    }    
    
    if(custom_suffix){
        api_Str_Size += strlen(custom_suffix);
    }

    char *api = malloc(api_Str_Size);

    sprintf(api,"https://%s%s",host,pathPrefix);

    if(inesOrgId){

        strcat(api,REST_ORGANIZATION_PREFIX);
        strcat(api,"/");
        strcat(api,inesOrgId);
    }

    strcat(api,apiname);

    if(custom_suffix){

        strcat(api,custom_suffix);
    }

    char *headers = generateHttpHeader(host,protocol,api,body, accessToken);

    response = httpsRequest(clientCert,clientKey,host, method, api, headers, body);
    
    if(api)
        free(api);
    if(headers)
        free(headers);
    
    if(!response || (strlen(response)<2))
    {
        wkey_log(LOG_ERROR, "No response from Ines\r\n");
        return NULL;
    }

    if (!strstr(response, "200 OK"))
    {
        printf("INeS Error: See INES response : \r\n%s", response);
            
        if(response)
            free(response);
        return NULL; 
    }


    return response;    
}
