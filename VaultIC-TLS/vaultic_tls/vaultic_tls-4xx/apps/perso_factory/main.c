#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <vaultic_common.h>
#include <vaultic_api.h>
#include <vaultic_version.h>
#include <vaultic_identity_authentication.h>
#include <vaultic_ecdsa_signer.h>
#include <vaultic_file_system.h>
#include <x509parser.h>

#include <vaultic_tls.h>
#include <vaultic_tls_config.h>

#define CHECK_STATUS(label,a) {	VIC_LOGD(label);\
								int ret_status= (a);\
<<<<<<< HEAD
							 	if (ret_status!= VLT_OK)\
                                {\
                                    VIC_LOGE("%s error %4.4x\n",label,ret_status);\
                                    printf("%s error %4.4x\n",label,ret_status);return 1;\
                                }\
                                else printf("Success - %s\n", label);}\
=======
							 	if (ret_status!= VLT_OK) {VIC_LOGE("%s error %4.4x",label,ret_status);return 1;}\
                                else printf("Success - %s\n", label);\
							}
>>>>>>> a659e4f61ed653f108f5e2ca1f2666cc538dc7ee

void GetManufPwd(unsigned char *buffer, unsigned char *length);
int vlt_copy_file(const char *dest_vic_file, const char *src_file);
int vlt_write_vic_file(const char *vic_file_name, VLT_U8 *u8DataBuffer, VLT_U32 u32DataOffset, VLT_U32 u32DataLength);
int vlt_read_vic_file(const char *vic_file_name, VLT_U8 *u8DataBuffer, VLT_U32 u32DataOffset, VLT_U32 u32DataLength);
int vlt_put_p256_key(char *privkey_file);

extern const VLT_U8 vltApiVersion[];

 #define MANUF_PWD "\x58\x6e\x54\x79\x32\x34\x69\x6e"

/* Input arguments:
 * device_cert_file: path of device certificate file in DER format
 * ca_cert_file: path of CA certificate file in DER format (optional)
 */

int main(int argc, char** argv)
{
    VLT_U8 au8ManufPassword[32];
    VLT_U8 u8ManufPasswordLength;
    VLT_INIT_COMMS_PARAMS comm_params = { 0 };
    VLT_TARGET_INFO chipInfo;

 
#if(VLT_ENABLE_NO_SELF_TESTS_DELAY != VLT_ENABLE)
    VLT_U8 selfTestsMode=0; // Disable FIPS self tests at power on if fast start not supported by the product
#endif    

    char *deviceCertFile=NULL;
    char *caCertFile=NULL;

    /* Check for proper calling convention */
    if( (argc != 2) && (argc != 3))  {
        printf("usage: %s <device_cert_file> <ca_cert_file [O]> \n", argv[0]);
        printf("\t device_cert_file \t path of device certificate file in DER format\n");
        printf("\t ca_cert_file     \t path of CA certificate file in DER format (optional)\n");
        return -1;
    }

    /* Retrieve name of device certificate file */
    deviceCertFile = argv[1];

    if(argc == 3)
    {
        caCertFile = argv[2];
    }

   printf("---------------------------------------------\n");
   printf("Writing %s to the VaultIC\n", deviceCertFile);
   printf("---------------------------------------------\n");

    // Configure communication parameters
    //---------------------------------------------------------------------
    comm_params.VltBlockProtocolParams.u16msSelfTestDelay = 5000; // 5s (max duration of self tests- worst case)
    comm_params.VltBlockProtocolParams.u32msTimeout = 5000; // 5 seconds (max duration of apdu command processing before returning response)

#ifdef USE_TWI
    comm_params.enCommsProtocol = VLT_TWI_COMMS;
    comm_params.VltTwiParams.u16BitRate = I2C_BITRATE;
    comm_params.VltTwiParams.u8Address = I2C_ADDRESS; // I2C address
#endif
#ifdef USE_SPI
    comm_params.enCommsProtocol = VLT_SPI_COMMS;
    comm_params.VltSpiParams.u16BitRate = SPI_BITRATE;
#endif

    // Open Session with VaultIC
    //---------------------------------------------------------------------
    VIC_LOGD("\n%s\n\n", vltApiVersion);
    CHECK_STATUS("VltApiInit" , VltApiInit(&comm_params));

    // Login as the TLS_USER_ID
#ifdef USE_SEC_CHANNEL
	// Authenticate User 1 with SCP03
	unsigned char aucS_MacStaticKey[] = SMAC_KEY;
	unsigned char aucS_EncStaticKey[] = SENC_KEY;

<<<<<<< HEAD
	KEY_BLOB kblMacStatic;
	kblMacStatic.keyType = VLT_KEY_AES_128;
	kblMacStatic.keySize = sizeof(aucS_MacStaticKey);
	kblMacStatic.keyValue = aucS_MacStaticKey;

	KEY_BLOB kblEncStatic;
	kblEncStatic.keyType = VLT_KEY_AES_128;
	kblEncStatic.keySize = sizeof(aucS_EncStaticKey);
	kblEncStatic.keyValue = aucS_EncStaticKey;

	KEY_BLOB_ARRAY theKeyBlobs = { 0 };
	theKeyBlobs.u8ArraySize = 2;
	theKeyBlobs.pKeys[0] = &kblMacStatic;
	theKeyBlobs.pKeys[1] = &kblEncStatic;

	CHECK_STATUS("VltAuthInit", VltAuthInit(VLT_AUTH_SCP03, TLS_USER_ID, VLT_NON_APPROVED_USER, VLT_CMAC_CENC_RMAC_RENC, theKeyBlobs));
#else
	// Authenticate User 0 with password
	VLT_U8 u8UserPassword[20];
	host_memset(u8UserPassword, 0x00, 20);
	host_memcpy(u8UserPassword, (VLT_PU8)TLS_USER_PIN, TLS_USER_PIN_LEN);

	//CHECK_APDU("VltSubmitPassword TLS User", VltSubmitPassword(TLS_USER_ID, VLT_NON_APPROVED_USER, TLS_USER_PIN_LEN, u8UserPassword));
	//if (VLT_OK != (VltSubmitPassword(VLT_USER0, VLT_NON_APPROVED_USER, sizeof(userPin), (VLT_U8*)userPin)))
	CHECK_STATUS("VltSubmitPassword", VltSubmitPassword(TLS_USER_ID, VLT_NON_APPROVED_USER, TLS_USER_PIN_LEN, u8UserPassword));
#endif

    // Call the GetInfo command, print result
    //---------------------------------------------------------------------
    CHECK_STATUS("VltGetInfo" , VltGetInfo(&chipInfo));
    VIC_LOGD("%s\n",chipInfo.au8Firmware);
=======
    // Reset State to CREATION
    //---------------------------------------------------------------------
//    CHECK_STATUS("VltSetStatus ACTIVATED",  VltSetStatus(VLT_STATE_ACTIVATED));
printf("VltSetStatus>>\n");
    // CHECK_STATUS("VltSetStatus CREATION",  VltSetStatus(VLT_STATE_CREATION));
printf("VltSetStatus<<\n");

#if(VLT_ENABLE_NO_SELF_TESTS_DELAY != VLT_ENABLE)
    // Configure power on self tests
    //---------------------------------------------------------------------
    CHECK_STATUS("VltSetConfig VLT_SET_CFG_POWERON_SELFTESTS_MODE", VltSetConfig(VLT_SET_CFG_POWERON_SELFTESTS_MODE, VLT_SET_CFG_POWERON_SELFTESTS_MODE_SZ,&selfTestsMode));
#endif    

//     // Delete user 0,1,2,3,4,5,6
//     //    (user 7 is the manufacturer DO NOT DELETE IT)
//     //---------------------------------------------------------------------
//     VLT_MANAGE_AUTH_DATA structAuthSetup;
//     structAuthSetup.enOperationID = VLT_DELETE_USER;
//     structAuthSetup.enUserID = VLT_USER0;
//     for ( VLT_USER_ID i = VLT_USER0; i <= VLT_USER6; i++) {
//         structAuthSetup.enUserID = i;
//         VltManageAuthenticationData(&structAuthSetup);
//     }

//     // Create TLS user
//     //---------------------------------------------------------------------
//     structAuthSetup.enOperationID = VLT_CREATE_USER;
//     structAuthSetup.u8TryCount = 5;
//     structAuthSetup.enSecurityOption = VLT_NO_DELETE_ON_LOCK;
//     structAuthSetup.enUserID = TLS_USER_ID;
//     structAuthSetup.enRoleID = VLT_NON_APPROVED_USER;

// #ifdef USE_SEC_CHANNEL
//     // SCP03 auth method
//     //---------------------------------------------------------------------
//     VLT_U8 au8S_MacStaticKey[] = SMAC_KEY;
//     VLT_U8 au8S_EncStaticKey[] = SENC_KEY;
//     structAuthSetup.enMethod = VLT_AUTH_SCP03;
//     structAuthSetup.enChannelLevel = VLT_CMAC_CENC;
//     structAuthSetup.data.secret.u8NumberOfKeys = 2;
//     structAuthSetup.data.secret.aKeys[0].enKeyID = VLT_KEY_AES_128;
//     structAuthSetup.data.secret.aKeys[0].u8Mask = 0xBE;
//     structAuthSetup.data.secret.aKeys[0].u16KeyLength = sizeof(au8S_MacStaticKey);
//     structAuthSetup.data.secret.aKeys[0].pu8Key = au8S_MacStaticKey;
//     structAuthSetup.data.secret.aKeys[1].enKeyID = VLT_KEY_AES_128;
//     structAuthSetup.data.secret.aKeys[1].u8Mask = 0xEF;
//     structAuthSetup.data.secret.aKeys[1].u16KeyLength = sizeof(au8S_EncStaticKey);
//     structAuthSetup.data.secret.aKeys[1].pu8Key = au8S_EncStaticKey;
//     VIC_LOGD("Encrypted channel enabled, TLS_USER = USER%d (SCP03)\n",TLS_USER_ID);
// #else
//     // Create user 00 with password auth method
//     //---------------------------------------------------------------------
//     structAuthSetup.enMethod = VLT_AUTH_PASSWORD;
//     structAuthSetup.enChannelLevel = VLT_NO_CHANNEL;
//     structAuthSetup.data.password.u8PasswordLength = TLS_USER_PIN_LEN;
//     memset(structAuthSetup.data.password.u8Password, 0x00, sizeof (structAuthSetup.data.password.u8Password));
//     memcpy(structAuthSetup.data.password.u8Password, (VLT_PU8) TLS_USER_PIN, TLS_USER_PIN_LEN);
//     VIC_LOGD("Encrypted channel disabled, TLS_USER = USER%d (PIN)\n",TLS_USER_ID);
// #endif

    // CHECK_STATUS("VltManageAuthenticationData Create Tls User" , VltManageAuthenticationData(&structAuthSetup));
>>>>>>> a659e4f61ed653f108f5e2ca1f2666cc538dc7ee

    // Create device cert file
    //---------------------------------------------------------------------
    VLT_SELECT respData;
    VLT_U8 u8attribute = 0x00;
    VLT_U16 usStatus = VLT_OK;

    VLT_FILE_PRIVILEGES filePrivileges;
    filePrivileges.u8Read =  0xFF; // All users allowed to read
<<<<<<< HEAD
    filePrivileges.u8Write = 0xFF; // All users can update
    filePrivileges.u8Delete = 0xFF; // All users can delete
    filePrivileges.u8Execute = 0xFF; // All users can use */
=======
    filePrivileges.u8Write = 1<<TLS_USER_ID; // Only TLS user can update
    filePrivileges.u8Delete = 1<<TLS_USER_ID; // Only TLS user can delete
    filePrivileges.u8Execute = 1<<TLS_USER_ID; // Only TLS user can use */
>>>>>>> a659e4f61ed653f108f5e2ca1f2666cc538dc7ee

    if(strcmp(CERTS_DIR_PATH, "/")!=0) {
        // Create Directory to store certificates
        VIC_LOGE("** ERROR not implemented: certificate directory\n");
        return 1;
    }

<<<<<<< HEAD
    // Select the VaultIC root directory
    //---------------------------------------------------------------------
    CHECK_STATUS("Select root directory", VltSelectFileOrDirectory((VLT_PU8) CERTS_DIR_PATH, strlen(CERTS_DIR_PATH), &respData));

    // Create Device certificate file
    //---------------------------------------------------------------------
    usStatus = VltCreateFile(TLS_USER_ID, 0, &filePrivileges, u8attribute, strlen(DEVICE_CERT_NAME)+1, (VLT_PU8)DEVICE_CERT_NAME);
    if (usStatus = 0x6A89)
    {
        // File already exists, not an error
        printf("Device certificate file exists\n");
    }
    else if (usStatus != VLT_OK)
    {
        printf("VltCreateFile Device cert file error %4.4x\n", usStatus);
    }

=======
    CHECK_STATUS("Select root directory", VltSelectFileOrDirectory((VLT_PU8) CERTS_DIR_PATH, strlen(CERTS_DIR_PATH), &respData));
    CHECK_STATUS("VltCreateFile Device cert file ",  VltCreateFile(TLS_USER_ID, 0, &filePrivileges, u8attribute, strlen(DEVICE_CERT_NAME)+1, (VLT_PU8)DEVICE_CERT_NAME));
>>>>>>> a659e4f61ed653f108f5e2ca1f2666cc538dc7ee
    // Create CA cert file
    //---------------------------------------------------------------------
    usStatus = VltCreateFile(TLS_USER_ID, 0, &filePrivileges, u8attribute, strlen(CA_CERT_NAME)+1, (VLT_PU8)CA_CERT_NAME);
    if (usStatus = 0x6A89)
    {
        // File already exists, not an error
        printf("CA certificate file exists\n");
    }
    else if (usStatus != VLT_OK)
    {
        printf("VltCreateFile CA cert file error %4.4x\n", usStatus);
    }

    // Personalize Device certicate
    //---------------------------------------------------------------------
    CHECK_STATUS("vlt_copy_file Device certificate ", vlt_copy_file(DEVICE_CERT_NAME, deviceCertFile ));

    // Personalize CA certicate
    //---------------------------------------------------------------------
    CHECK_STATUS("vlt_copy_file CA certificate ", vlt_copy_file(CA_CERT_NAME, caCertFile ));

    // // Switch state to ACTIVATED
    // //---------------------------------------------------------------------
    // CHECK_STATUS("VltSetStatus ACTIVATED",  VltSetStatus(VLT_STATE_ACTIVATED));

    //---------------------------------------------------------------------
    // Log the TLS_USER_ID out of the VaultIC Secure Object.
    CHECK_STATUS("VltCancelAuthentication", VltCancelAuthentication());

    CHECK_STATUS("VltApiClose", VltApiClose());

    VIC_LOGD("VaultIC TLS Perso done\n\n");
}


#ifndef MANUF_PWD
void GetManufPwd(unsigned char *pu8Pwd, unsigned char *pu8PwdLen)
{
    int nb_chars;

    // disable default 1024 byte buffering
    setvbuf(stdin, NULL, _IONBF, 0);

    char key_entered=FALSE;
    do {
        fflush(stdin); // fflush stdin
        printf("\nPlease enter Manufacturer password (hex bytes) \n");

        char byte_buffer[3];
        char c=0;

        for ( nb_chars = 0 ; nb_chars < (*pu8PwdLen)*2 ; nb_chars++) {

            // wait for character
        	do {
             c= getchar();
        	} while ((nb_chars == 0)&& (c=='\n'));

            // check if ENTER key pressed
            if (c == '\n') {
            	if(nb_chars == 0) c= getchar();
            	else {
            		key_entered = TRUE;
                    break;
            	}
            }

            // check if character is in hexa
            if(!isxdigit(c)) {
                printf("\n *** ERROR: please enter hex digits only \n\n");
                break;
            }

            // append digit in byte_buffer
            byte_buffer[nb_chars % 2] = c;

            // convert 2 digits to byte
            if(nb_chars %2 == 1)
            {
                // convert to byte
                int hex_byte;
                if (sscanf(byte_buffer, "%2x" , &hex_byte) !=1) {
                    printf("\n *** ERROR: please enter hex values only \n\n");
                    break;
                }
                pu8Pwd[nb_chars/2]= (char) hex_byte;
            }
        }

        if ((nb_chars==0)||(nb_chars%2)!=0) key_entered = FALSE;

    } while (key_entered == FALSE) ;

    *pu8PwdLen = nb_chars/2;
}
#else
void GetManufPwd(unsigned char *pu8Pwd, unsigned char *pu8PwdLen)
{
    *pu8PwdLen =sizeof(MANUF_PWD)-1;
    memcpy(pu8Pwd,MANUF_PWD,*pu8PwdLen);
}
#endif

int vlt_copy_file(const char *dest_vic_file, const char *src_file){

    int ret = 0;
    FILE *f1;
    long lSize;

    VLT_PU8 buffer;
    size_t result;

    if( ( f1 = fopen( src_file, "r" ) ) == NULL ) {
        printf("*** ERROR: unable to open file %s\n", src_file);
        return( -1 );
    }

    // obtain file size
    fseek (f1 , 0 , SEEK_END);
    lSize = ftell (f1);
    rewind (f1);

    // read file content
    buffer=malloc(lSize);

    result = fread( buffer, 1, lSize, f1 );
    fclose( f1 );

    if (result != lSize) {
        free(buffer);
        printf("*** ERROR: need to check input file: (length = %d)\n", result);

        return -1;
    }

    // write buffer in vaultic file
    ret = vlt_write_vic_file(dest_vic_file, buffer, VLT_SEEK_FROM_START, lSize);
    if(ret!=0) {
        free(buffer);
        printf("*** ERROR: vlt_write_vic_file");
        return -1;
    }

    // read back
    result = 0;
    memset(buffer, 0, lSize);
    ret = vlt_read_vic_file(dest_vic_file, buffer, VLT_SEEK_FROM_START , lSize);
    if(ret!=lSize) {
        free(buffer);
        printf("*** ERROR: vlt_read_vic_file");
        return -1;
    }

    free(buffer);

    return VLT_OK;
}

int vlt_write_vic_file(const char *vic_file_name, VLT_U8 *u8DataBuffer, VLT_U32 u32DataOffset, VLT_U32 u32DataLength) {

    VLT_FS_ENTRY_PARAMS  structFileEntry = {0};

    if (vic_file_name == NULL || u8DataBuffer == NULL || u32DataLength < 1)
        return -1;

    CHECK_STATUS("VltFsOpenFile" , VltFsOpenFile(strlen(vic_file_name), (VLT_U8 *)vic_file_name, 0,&structFileEntry ) ) ;

    CHECK_STATUS("VltFsWriteFile",VltFsWriteFile(u32DataOffset,u8DataBuffer,u32DataLength,FALSE ));

    CHECK_STATUS("VltFsCloseFile", VltFsCloseFile() ) ;

    return 0;
}


int vlt_read_vic_file(const char *szVicFilePath, VLT_U8 *u8DataBuffer, VLT_U32 u32DataOffset, VLT_U32 u32DataLength){

    VLT_FS_ENTRY_PARAMS  structFileEntry ={0};

    if (szVicFilePath == NULL || u8DataBuffer == NULL )
        return -1;

    CHECK_STATUS("VltFsOpenFile", VltFsOpenFile(strlen(szVicFilePath), (VLT_PU8)szVicFilePath, FALSE ,&structFileEntry ) ) ;

    if(u32DataLength==0) {
        u32DataLength = structFileEntry.u32FileSize; // read whole file
    }

    CHECK_STATUS("VltFsReadFile", VltFsReadFile(u32DataOffset,u8DataBuffer, &u32DataLength));

    CHECK_STATUS("VltFsCloseFile", VltFsCloseFile()) ;

    return u32DataLength;
}

