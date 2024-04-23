#include "vaultic_common.h"
#include "vaultic_api.h"
#include "vaultic_ecdsa_signer.h"
#include "vaultic_HMAC.h"
#include "vaultic_structs.h"
#include "vaultic_identity_authentication.h"
#include <stdio.h>
#include <string.h>

// Definitions for key generation
//P256 parameters
#define P256_BYTE_SZ 	        32
#define ECC_P256_Para_Group 	0xE0
#define ECC_P256_Para_Index 	0x01
// Device public key
#define ECC_EK_Group 			0xEC
#define ECC_EK_Pubk_Index 		0x07
#define ECC_EK_Privk_Index 		0x08

// Defines Used for setting up communication parameters.
#define VLT_TWI_ADDRESS                     0x5F
#define VLT_TWI_BITRATE                     100		// in kbits
#define VLT_SPI_BITRATE                     2000	// in kbits
#define VLT_APDU_TIME_OUT                   5000	// in ms - max time required by vaultic to return a response to an APDU command
#define VLT_SELF_TEST_WAIT_TIME             5000	// in ms - time required for vaultic to complete its self tests

// Definitions for authenticaiton method
//#define USE_SEC_CHANNEL // encryption of communication with VaultIC 
#ifdef USE_SEC_CHANNEL
#define TLS_USER_ID 			VLT_USER1
#define SMAC_KEY { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F}
#define SENC_KEY { 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F}
#else
#define TLS_USER_ID 			VLT_USER0
#define TLS_USER_PIN			"\0\0\0\0"
#define TLS_USER_PIN_LEN		4
#endif

// API function definitions
VLT_STS VltCreateEcdsaDomainParams(VLT_USER_ID userId, VLT_ECC_ID curveId, VLT_U8 domainKeyGroup, VLT_U8 domainKeyIndex, VLT_KEY_OBJECT* pDomainParams);
VLT_STS VltGenKey(VLT_USER_ID userId, VLT_ECC_ID curveId, VLT_U8 genGrp, VLT_U8 genPubIdx, VLT_U8 genPrivIdx, VLT_KEY_OBJ_ECDSA_PUB* pGenPub);


// Macro to exit upon failure
#define CloseAndExit(status,exitMessage)		{ \
	printf("%s\n",exitMessage); \
	if (VLT_OK != status) printf("*** Error status: %04X\n", status);\
    VltApiClose(); \
	return( status ); }	

unsigned char pw[8] = {
    0x58, 0x6e, 0x54, 0x79, 0x32, 0x34, 0x69, 0x6e
};

int main (int argc, char **argv)
{
    VLT_U16 vltStatus = VLT_OK;
    VLT_TARGET_INFO tInfo;
    VLT_INIT_COMMS_PARAMS commsParams;
    VLT_MANAGE_AUTH_DATA structAuthSetup;
    char *szManuf, *szInterface, *c;
    int i;

//    if (argc != 2) {
//        fprintf(stderr, "USAGE: %s <password>\n", argv[0]);
//        exit(1);
//    }

    commsParams.enCommsProtocol = VLT_SPI_COMMS;
    commsParams.VltSpiParams.u16BitRate = VLT_SPI_BITRATE;
    commsParams.VltBlockProtocolParams.u16msSelfTestDelay = VLT_SELF_TEST_WAIT_TIME;
    commsParams.VltBlockProtocolParams.u32msTimeout = VLT_APDU_TIME_OUT;

	//---------------------------------------------------------------------
	// Initialize the API
	//---------------------------------------------------------------------
    if (VltApiInit(&commsParams) != VLT_OK) {
        fprintf(stderr, "%s: can't initialize APIs\n", argv[0]);
        exit(1);
    }

	//---------------------------------------------------------------------
	// Get the device information
	//---------------------------------------------------------------------
    if (VltGetInfo(&tInfo) != VLT_OK) {
        fprintf(stderr, "%s: can't get target info\n", argv[0]);
        exit(1);
    }
    printf("target name is %s\n", tInfo.au8Firmware);

	//---------------------------------------------------------------------
	// Login as the manufacturer.
	//---------------------------------------------------------------------
    if (VltSubmitPassword(VLT_USER7, VLT_MANUFACTURER, sizeof(pw), pw) != VLT_OK) {
        fprintf(stderr, "%s: can't submit user7 password\n", argv[0]);
        exit(1);
    }
    VltSetStatus(VLT_STATE_ACTIVATED);

	//---------------------------------------------------------------------
	// Transition to the creation state.
	//---------------------------------------------------------------------
    if (VltSetStatus(VLT_STATE_CREATION) != VLT_OK) {
        fprintf(stderr, "%s: can't set vlt status\n", argv[0]);
        exit(1);
    }

 	//---------------------------------------------------------------------
	// Delete all users except user 7
	//---------------------------------------------------------------------
    structAuthSetup.enOperationID = VLT_DELETE_USER;
    for (VLT_USER_ID i = VLT_USER0; i < VLT_USER7; i++) {
        printf("deleting user %d...,", i);
        structAuthSetup.enUserID = i;
        VltManageAuthenticationData(&structAuthSetup);
    }
    printf("\ndeleted users0-6\n");

	//---------------------------------------------------------------------
	// Create a user with selected authentication method.
	//---------------------------------------------------------------------
	structAuthSetup.enOperationID = VLT_CREATE_USER;
	structAuthSetup.u8TryCount = 5;
	structAuthSetup.enSecurityOption = VLT_NO_DELETE_ON_LOCK;
	structAuthSetup.enUserID = TLS_USER_ID;
	structAuthSetup.enRoleID = VLT_NON_APPROVED_USER;

#ifdef USE_SEC_CHANNEL
	// Create user 01 with SCP03 auth method
	//---------------------------------------------------------------------
	VLT_U8 au8S_MacStaticKey[] = SMAC_KEY;
	VLT_U8 au8S_EncStaticKey[] = SENC_KEY;
	structAuthSetup.enMethod = VLT_AUTH_SCP03;
	structAuthSetup.enChannelLevel = VLT_CMAC_CENC;
	structAuthSetup.data.secret.u8NumberOfKeys = 2;
	structAuthSetup.data.secret.aKeys[0].enKeyID = VLT_KEY_AES_128;
	structAuthSetup.data.secret.aKeys[0].u8Mask = 0xBE;
	structAuthSetup.data.secret.aKeys[0].u16KeyLength = sizeof(au8S_MacStaticKey);
	structAuthSetup.data.secret.aKeys[0].pu8Key = au8S_MacStaticKey;
	structAuthSetup.data.secret.aKeys[1].enKeyID = VLT_KEY_AES_128;
	structAuthSetup.data.secret.aKeys[1].u8Mask = 0xEF;
	structAuthSetup.data.secret.aKeys[1].u16KeyLength = sizeof(au8S_EncStaticKey);
	structAuthSetup.data.secret.aKeys[1].pu8Key = au8S_EncStaticKey;
	printf("Encrypted channel enabled, TLS_USER = USER%d (SCP03)\n", TLS_USER_ID);
#else
	// Create user 00 with password auth method
	//---------------------------------------------------------------------
	structAuthSetup.enMethod = VLT_AUTH_PASSWORD;
	structAuthSetup.enChannelLevel = VLT_NO_CHANNEL;
	structAuthSetup.data.password.u8PasswordLength = TLS_USER_PIN_LEN;
	memset(structAuthSetup.data.password.u8Password, 0x00, sizeof(structAuthSetup.data.password.u8Password));
	memcpy(structAuthSetup.data.password.u8Password, (VLT_PU8)TLS_USER_PIN, TLS_USER_PIN_LEN);
	printf("Encrypted channel disabled, TLS_USER = USER%d (PIN)\n", TLS_USER_ID);
#endif

	if (VLT_OK != (vltStatus = VltManageAuthenticationData(&structAuthSetup)))
		CloseAndExit(vltStatus, "User creation failed");

    printf("\ncreated user!\n");

	//---------------------------------------------------------------------
	// Transition to the operational active state.
	//---------------------------------------------------------------------
	if (VLT_OK != (vltStatus = VltSetStatus(VLT_STATE_ACTIVATED)))
		CloseAndExit(vltStatus, "Set status failed");

	printf("Set to OPERATIONAL mode successful\n");
	//---------------------------------------------------------------------
	// Log the manufacturer out of the VaultIC Secure Object.
	//---------------------------------------------------------------------
	if (VLT_OK != (vltStatus = VltCancelAuthentication()))
		CloseAndExit(vltStatus, "Cancel authentication failed");

	//---------------------------------------------------------------------
	// Login as TLS user
	//---------------------------------------------------------------------
#ifdef USE_SEC_CHANNEL
	// Authenticate User 1 with SCP03
	unsigned char aucS_MacStaticKey[] = SMAC_KEY;
	unsigned char aucS_EncStaticKey[] = SENC_KEY;

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

	if (VLT_OK != (vltStatus = VltAuthInit(VLT_AUTH_SCP03, TLS_USER_ID, VLT_NON_APPROVED_USER, VLT_CMAC_CENC_RMAC_RENC, theKeyBlobs)))
		CloseAndExit(vltStatus, "VltAuthInit TLS User failed");
#else
	// Authenticate User 0 with password
	VLT_U8 u8UserPassword[20];
	host_memset(u8UserPassword, 0x00, 20);
	host_memcpy(u8UserPassword, (VLT_PU8)TLS_USER_PIN, TLS_USER_PIN_LEN);

	if (VLT_OK != (vltStatus = VltSubmitPassword(TLS_USER_ID, VLT_NON_APPROVED_USER, TLS_USER_PIN_LEN, u8UserPassword)))
		CloseAndExit(vltStatus, "Logging as user 0 failed");
#endif

    //---------------------------------------------------------------------
    // Create ECDSA domain params 
    //---------------------------------------------------------------------
    VLT_KEY_OBJECT domainParams;
    VLT_U8 domainGrp = ECC_P256_Para_Group;
    VLT_U8 domainIdx = ECC_P256_Para_Index;
    if (VLT_OK != (vltStatus = VltCreateEcdsaDomainParams(TLS_USER_ID, VLT_ECC_ID_P256, domainGrp, domainIdx, &domainParams)))
        CloseAndExit(vltStatus, "Set Key Obj Domain Params failed");

    //---------------------------------------------------------------------
    // Generate ECC key pair in VaultIC 
    //---------------------------------------------------------------------
    VLT_KEY_OBJ_ECDSA_PUB genPub;
    VLT_U8 pX[P256_BYTE_SZ] = { 0 };
    VLT_U8 pY[P256_BYTE_SZ] = { 0 };
    VLT_U8 genGrp = ECC_EK_Group;
    VLT_U8 genPubIdx = ECC_EK_Pubk_Index;
    VLT_U8 genPrivIdx = ECC_EK_Privk_Index;
    genPub.pu8Qx = pX;
    genPub.pu8Qy = pY;
    genPub.u8DomainParamsGroup = domainGrp;
    genPub.u8DomainParamsIndex = domainIdx;
    genPub.u16QLen = domainParams.data.EcdsaParamsKey.u16NLen;


    //genPub.u16QLen = P256_BYTE_SZ; //domainParams.data.EcdsaParamsKey.u16NLen;
    genPub.u16QLen = domainParams.data.EcdsaParamsKey.u16NLen;
    if (VLT_OK != (vltStatus = VltGenKey(TLS_USER_ID, VLT_ECC_ID_P256, genGrp, genPubIdx, genPrivIdx, &genPub)))
        CloseAndExit(vltStatus, "Generate ECC keypair failed");

    printf("x:"); PrintHexBuffer(genPub.pu8Qx, P256_BYTE_SZ);
    printf("y:"); PrintHexBuffer(genPub.pu8Qy, P256_BYTE_SZ);

    exit(0);

}

/**
	 * \brief Create the domain parameters to define the key types and domain IDs on the VaultIC
	 * \param[in]		curveId			The ECC curve that the domain is defined for
	 * \param[in]		domainKeyGroup	The group that the domain definition will be added to
	 * \param[in]		domainKeyIndex	The index that the domain definition will be added to
	 * \param[out]		pDomainParams	Needs to be initialized in caller. Holds the parameters for the domain that will be created
	* \return			VLT_OK on success otherwise an error code
	*/
VLT_STS VltCreateEcdsaDomainParams(VLT_USER_ID userId, VLT_ECC_ID curveId, VLT_U8 domainKeyGroup, VLT_U8 domainKeyIndex, VLT_KEY_OBJECT* pDomainParams)
{
	unsigned short usActualSW = 0;

	// Check input parameters
	if (pDomainParams == NULL)
		CloseAndExit(usActualSW, "Bad input parameters for VltCreateEcdsaDomainParams()");

	if (VLT_OK != (usActualSW = EcdsaSetKeyObjDomainParams(curveId, pDomainParams)))
		CloseAndExit(usActualSW, "Set Key Obj Domain Params failed");

	VLT_FILE_PRIVILEGES domainParamsAccess;
	domainParamsAccess.u8Read = 0xFF;
	domainParamsAccess.u8Write = (1 << userId);
	domainParamsAccess.u8Delete = (1 << userId);
	domainParamsAccess.u8Execute = (1 << userId);

	printf("Put ECC domain parameters key \n");
	if (VLT_OK != (usActualSW = VltPutKey(domainKeyGroup, domainKeyIndex, &domainParamsAccess, pDomainParams)))
		CloseAndExit(usActualSW, "PutKey ECC Domain Params Key failed");

	return VLT_OK;
}

/**
 * \brief Generate a public/private key pair base on the inputs
 * \param[in]		userId			VaultIC user that is currently authenticated
 * \param[in]		curveId			The ECC curve that the domain is defined for
 * \param[in]		genGrp			The Group that the key pair will belong to
 * \param[in]		genPubIdx		The Index of the public key
 * \param[in]		genPrivIdx		The Index of the private key
 * \param[out]		pGenPub			Needs to be initialized in caller. Holds the public key pair that is created.
 * \return		VLT_OK on success otherwise an error code
*/
VLT_STS VltGenKey(VLT_USER_ID userId, VLT_ECC_ID curveId, VLT_U8 genGrp, VLT_U8 genPubIdx, VLT_U8 genPrivIdx, VLT_KEY_OBJ_ECDSA_PUB* pGenPub)
{
	unsigned short usActualSW = 0;

	// Check input parameters
	if (pGenPub == NULL)
		CloseAndExit(usActualSW, "Bad input parameters for VltGenKey()");

	VLT_FILE_PRIVILEGES pubAccess;
	pubAccess.u8Read = 0xFF;
	pubAccess.u8Execute = 0xFF;
	pubAccess.u8Write = 0xFF;
	pubAccess.u8Delete = 0xFF;

	VLT_FILE_PRIVILEGES privAccess;
	privAccess.u8Read = 0; // Read not allowed
	privAccess.u8Execute = (1 << userId);
	privAccess.u8Write = (1 << userId);
	privAccess.u8Delete = (1 << userId);

	VLT_KEY_OBJECT genPubKey;
	genPubKey.enKeyID = VLT_KEY_ECC_PUB;

	VLT_BOOL isPrimeCurve;
	if (VLT_OK != (usActualSW = EcdsaIsPcurve(curveId, &isPrimeCurve)))
		CloseAndExit(usActualSW, "isPrimeCurve failed");

	VLT_KEY_GEN_DATA keyGenData;

	if (isPrimeCurve)
		keyGenData.enAlgoID = VLT_ALG_KPG_ECDSA_GFP;
	else
		keyGenData.enAlgoID = VLT_ALG_KPG_ECDSA_GF2M;

	keyGenData.data.EcdsaDsaKeyGenObj.u8DomainParamsGroup = pGenPub->u8DomainParamsGroup;
	keyGenData.data.EcdsaDsaKeyGenObj.u8DomainParamsIndex = pGenPub->u8DomainParamsIndex;

	printf("Generate ECC key pair of device \n");
	if (VLT_OK != (usActualSW = VltGenerateKeyPair(genGrp, genPubIdx, &pubAccess, genGrp, genPrivIdx, &privAccess, &keyGenData)))
		CloseAndExit(usActualSW, "Generate ECC keypair failed");

	printf("Read generated device public key \n");

	genPubKey.data.EcdsaPubKey.u16QLen = MAX_ECC_KEY_BYTES_SIZE;
	genPubKey.data.EcdsaPubKey.pu8Qx = pGenPub->pu8Qx;
	genPubKey.data.EcdsaPubKey.pu8Qy = pGenPub->pu8Qy;

	if (VLT_OK != (usActualSW = VltReadKey(genGrp, genPubIdx, &genPubKey)))
		CloseAndExit(usActualSW, "VltReadKey failed");

	return VLT_OK;
}

