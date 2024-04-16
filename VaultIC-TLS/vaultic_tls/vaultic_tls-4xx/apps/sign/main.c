
#include <stdio.h>
#include <stdlib.h>
#include <vaultic_common.h>
#include <vaultic_tls.h>

#define CHECK_STATUS(label,a) {	VIC_LOGD(label);\
								int ret_status= (a);\
							 	if (ret_status!= 0) {VIC_LOGE("%s error %4.4x",label,ret_status);return 1;}\
                                else VIC_LOGE("Success - %s\n", label);\
							}

int main(int argc, char** argv)
{
    // Define the variables
    int ret = 0;
    unsigned char hash[P256_BYTE_SZ] = {0};
    unsigned char pu8SigR[P256_BYTE_SZ] = {0};
    unsigned char pu8SigS[P256_BYTE_SZ] = {0};
    char *bytesFileName = NULL;
   
    printf("---------------------------------------------\n");
    printf("Sign bytes with VaultIC\n");
    printf("---------------------------------------------\n");

    // Check for proper calling convention
    if (argc != 2)
    {
        printf("usage: %s <bytes_to_sign>  \n", argv[0]);
        printf("\t bytes_to_sign: \t path to file containing bytes to sign\n");
        return -1;
    }
    // Retrieve name of file with bytes to sign
    bytesFileName = argv[1];

    // Read the bytes from the file to sign
    FILE* pFile  = NULL;
    long lSize    = 0;
    char* buffer = NULL;
    size_t result = 0;

    pFile = fopen (bytesFileName , "rb");
    if (pFile != NULL)
    {
        // obtain file size:
        fseek (pFile , 0 , SEEK_END);
        lSize = ftell (pFile);
        rewind (pFile);

        // allocate memory to contain the whole file:
        buffer = (char*)malloc(sizeof(char)*lSize);
        if (buffer != NULL) 
        {
            // Copy the file into the buffer:
            result = fread(buffer, 1, lSize, pFile);
            if (result != lSize)
                printf("Read failed, did not read entire file\n%d bytes read\n", result);
        }
        else
        {printf("Buffer allocation failed\n");} 
    }
    else 
    {printf("File open failed\nFile:%s\n", bytesFileName);}

    // Close file
    if (pFile) fclose (pFile);

    
    // Sign the input bytes
    if (buffer)
    {
        // Open session with VaultIC 
        CHECK_STATUS("vlt_tls_init", vlt_tls_init());
        printf("Init completed\n");

        CHECK_STATUS("Compute Signature", vlt_tls_compute_signature_P256(buffer, lSize, pu8SigR, pu8SigS));
        if (ret ==0)
        {
            printf("\nSignature\nR:");
            VIC_LOGD_PRINT_BUFFER(pu8SigR, P256_BYTE_SZ);
            printf("\nS:");
            VIC_LOGD_PRINT_BUFFER(pu8SigS, P256_BYTE_SZ);
        }
        else 
        {
            VIC_LOGE("(Signature Failed)\n");
        }
        // Close session with VaultIC
        CHECK_STATUS("vlt_tls_close", vlt_tls_close());

        // Free the buffer
        free (buffer);
    }
    return 0;
}
