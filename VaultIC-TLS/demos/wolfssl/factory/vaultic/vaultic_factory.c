/**
* @file	   
*
* @note    THIS PRODUCT IS SUPPLIED FOR EVALUATION, TESTING AND/OR DEMONSTRATION PURPOSES ONLY.
*
* @note    <b>DISCLAIMER</b>
*
* @note    Copyright (C) 2017 Wisekey
*
* @note    All products are provided by Wisekey subject to Wisekey Evaluation License Terms and Conditions
* @note    and the provisions of any agreements made between Wisekey and the Customer concerning the same
* @note    subject matter.
* @note    In ordering a product covered by this document the Customer agrees to be bound by those Wisekey's
* @note    Evaluation License Terms and Conditions and agreements and nothing contained in this document
* @note    constitutes or forms part of a contract (with the exception of the contents of this disclaimer notice).
* @note    A copy of Wisekey's Evaluation License Terms and Conditions is available on request. Export of any
* @note    Wisekey product outside of the EU may require an export license.
*
* @note    The information in this document is provided in connection with Wisekey products. No license,
* @note    express or implied, by estoppel or otherwise, to any intellectual property right is granted by this
* @note    document or in connection with the provisions of Wisekey products.
*
* @note    Wisekey makes no representations or warranties with respect to the accuracy or completeness of the
* @note    contents of this document and reserves the right to make changes to specifications and product
* @note    descriptions at any time without notice.
*
* @note    THE PRODUCT AND THE RELATED DOCUMENTATION ARE PROVIDED "AS IS", AND CUSTOMER UNDERSTANDS
* @note    THAT IT ASSUMES ALL RISKS IN RELATION TO ITS USE OF THE PRODUCT AND THE PRODUCT'S
* @note    QUALITY AND PERFORMANCE.
*
* @note    EXCEPT AS SET FORTH IN INSIDE SECURE'S EVALUATION LICENSE TERMS AND CONDITIONS OR IN ANY
* @note    AGREEMENTS MADE BETWEEN WISEKEY AND THE CUSTOMER CONCERNING THE SAME SUBJECT MATTER,
* @note    WISEKEY OR ITS SUPPLIERS OR LICENSORS ASSUME NO LIABILITY WHATSOEVER. CUSTOMER
* @note    AGREES AND ACKNOWLEDGES THAT WISEKEY SHALL HAVE NO RESPONSIBILITIES TO CUSTOMER TO
* @note    CORRECT ANY DEFECTS OR PROBLEMS IN THE PRODUCT OR THE RELATED DOCUMENTATION, OR TO
* @note    ENSURE THAT THE PRODUCT OPERATES PROPERLY.  WISEKEY DISCLAIMS ANY AND ALL WARRANTIES
* @note    WITH RESPECT TO THE PRODUCT AND THE RELATED DOCUMENTATION, WHETHER EXPRESS, STATUTORY
* @note    OR IMPLIED INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTY OF MERCHANTABILITY,
* @note    SATISFACTORY QUALITY, FITNESS FOR A PARTICULAR PURPOSE, OR NON-INFRINGEMENT.
*
* @note    WISEKEY SHALL HAVE NO LIABILITY WHATSOEVER TO CUSTOMER IN CONNECTION WITH THIS
* @note    WISEKEY'S EVALUATION TERMS AND CONDITIONS, INCLUDING WITHOUT LIMITATION, LIABILITY FOR
* @note    ANY PROBLEMS IN OR CAUSED BY THE PRODUCT OR THE RELATED DOCUMENTATION, WHETHER DIRECT,
* @note    INDIRECT, CONSEQUENTIAL, PUNITIVE, EXEMPLARY, SPECIAL OR INCIDENTAL DAMAGES (INCLUDING,
* @note    WITHOUT LIMITATION, DAMAGES FOR LOSS OF PROFITS, LOSS OF REVENUE, BUSINESS INTERRUPTION,
* @note    LOSS OF GOODWILL, OR LOSS OF INFORMATION OR DATA) NOTWITHSTANDING THE THEORY OF
* @note    LIABILITY UNDER WHICH SAID DAMAGES ARE SOUGHT, INCLUDING BUT NOT LIMITED TO CONTRACT,
* @note    TORT (INCLUDING NEGLIGENCE), PRODUCTS LIABILITY, STRICT LIABILITY, STATUTORY LIABILITY OR
* @note    OTHERWISE, EVEN IF WISEKEY HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.
*
* @brief  Demo code that implements an ECC signature
*
*/

#define DEF_VARS
#include "vaultic_common.h"
#include "vaultic_api.h"
#include "vaultic_ecdsa_signer.h"
#include "vaultic_identity_authentication.h"
#include "vaultic_HMAC.h"
#include "common.h"
#include "ini.h"
#include "vaultic_csr.h"

// Demo definitions
//#define DEMO_RESET // This will delete the use after completing the demo

// Definitions for authentication method
#define USE_SEC_CHANNEL // encryption of communication with VaultIC 
#ifdef USE_SEC_CHANNEL
#define TLS_USER_ID 			VLT_USER1
#define SMAC_KEY { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F}
#define SENC_KEY { 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F}
#else
#define TLS_USER_ID 			VLT_USER0
#define TLS_USER_PIN			"\0\0\0\0"
#define TLS_USER_PIN_LEN		4
#endif

// Definitions for key generation
//P256 parameters
#define ECC_P256_Para_Group 	0xE0
#define ECC_P256_Para_Index 	0x01

// Device public key
#define ECC_EK_Group 			0xEC
#define ECC_EK_Pubk_Index 		0x07
#define ECC_EK_Privk_Index 		0x08


int VaultIC_Factory_CSR(TEST_PARAMS_T * test_params, config_values_t config)
{
    VLT_INIT_COMMS_PARAMS *pCommsParams = &test_params->commsParams;
    unsigned short usActualSW = 0;

    printf("\n");
    printf("==========================================================\n");
    printf("                    VaultIC_Factory_CSR                   \n");
    printf("==========================================================\n");

	//---------------------------------------------------------------------
	// Initialize the API
	//---------------------------------------------------------------------
	if (VLT_OK != (usActualSW = VltApiInit(pCommsParams)))
	{
		CloseAndExit(usActualSW, "VltApiInit failed");
	}

	//---------------------------------------------------------------------
	// Login as the manufacturer.
	//---------------------------------------------------------------------
//#ifndef _WIN32
//	strcpy(test_params->au8ManufPassword, pw);
//#endif // !_WIN32

	printf("\nVaultIC reinitialization in progress ...\n");
	if (VLT_OK != (usActualSW = VltSubmitPassword(VLT_USER7,
		VLT_MANUFACTURER,
		test_params->u8ManufPasswordLength,
		test_params->au8ManufPassword)))
	{
		CloseAndExit(usActualSW, "VltSubmitPassword Manuf password");
	}
	printf("Authenticate as Manufacturer successful\n");

	//---------------------------------------------------------------------
	// Get the device information
	//---------------------------------------------------------------------
	VLT_TARGET_INFO targetInfo;

	if (VLT_OK != (usActualSW = VltGetInfo(&targetInfo)))
	{
		CloseAndExit(usActualSW, "VltGetInfo");
	}

	//
	// Report the device name.
	printf("The Target Name: %s\n", targetInfo.au8Firmware);

	//---------------------------------------------------------------------
	// Transition to the creation state.
	//---------------------------------------------------------------------
	VltSetStatus(VLT_STATE_ACTIVATED);

	if (VLT_OK != (usActualSW = VltSetStatus(VLT_STATE_CREATION)))
		CloseAndExit(usActualSW, "Set status failed");

	printf("Set to CREATION mode successful\n");

	//---------------------------------------------------------------------
	// Delete all users except user 7
	//---------------------------------------------------------------------
	VLT_MANAGE_AUTH_DATA structAuthSetup;

	structAuthSetup.enOperationID = VLT_DELETE_USER;

	for (VLT_USER_ID i = VLT_USER0; i < VLT_USER7; i++)
	{
		printf("Delete User %d \n", i);
		structAuthSetup.enUserID = i;
		VltManageAuthenticationData(&structAuthSetup);
	}
	printf("VaultIC reinitialization successful\n\n");



	//---------------------------------------------------------------------
	// Create a user with selected authentication method.
	//---------------------------------------------------------------------
	//     // Create TLS user
	 //---------------------------------------------------------------------
	structAuthSetup.enOperationID = VLT_CREATE_USER;
	structAuthSetup.u8TryCount = 5;
	structAuthSetup.enSecurityOption = VLT_NO_DELETE_ON_LOCK;
	structAuthSetup.enUserID = TLS_USER_ID;
	//structAuthSetup.enRoleID = VLT_APPROVED_USER;
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

	if (VLT_OK != (usActualSW = VltManageAuthenticationData(&structAuthSetup)))
		CloseAndExit(usActualSW, "User creation failed");

	//---------------------------------------------------------------------
	// Transition to the operational active state.
	//---------------------------------------------------------------------
	if (VLT_OK != (usActualSW = VltSetStatus(VLT_STATE_ACTIVATED)))
		CloseAndExit(usActualSW, "Set status failed");

	printf("Set to OPERATIONAL mode successful\n");
	//---------------------------------------------------------------------
	// Log the manufacturer out of the VaultIC Secure Object.
	//---------------------------------------------------------------------
	if (VLT_OK != (usActualSW = VltCancelAuthentication()))
		CloseAndExit(usActualSW, "Cancel authentication failed");

	//---------------------------------------------------------------------
	// Login as user 0.  
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

	if (VLT_OK != (usActualSW = VltAuthInit(VLT_AUTH_SCP03, TLS_USER_ID, VLT_NON_APPROVED_USER, VLT_CMAC_CENC_RMAC_RENC, theKeyBlobs)))
		CloseAndExit(usActualSW, "VltAuthInit TLS User failed");
	//CHECK_APDU("VltAuthInit TLS User", VltAuthInit(VLT_AUTH_SCP03, TLS_USER_ID, VLT_NON_APPROVED_USER, VLT_CMAC_CENC_RMAC_RENC, theKeyBlobs));
#else
	// Authenticate User 0 with password
	VLT_U8 u8UserPassword[20];
	host_memset(u8UserPassword, 0x00, 20);
	host_memcpy(u8UserPassword, (VLT_PU8)TLS_USER_PIN, TLS_USER_PIN_LEN);

	//CHECK_APDU("VltSubmitPassword TLS User", VltSubmitPassword(TLS_USER_ID, VLT_NON_APPROVED_USER, TLS_USER_PIN_LEN, u8UserPassword));
	//if (VLT_OK != (usActualSW = VltSubmitPassword(VLT_USER0, VLT_NON_APPROVED_USER, sizeof(userPin), (VLT_U8*)userPin)))
	if (VLT_OK != (usActualSW = VltSubmitPassword(TLS_USER_ID, VLT_NON_APPROVED_USER, TLS_USER_PIN_LEN, u8UserPassword)))
		CloseAndExit(usActualSW, "Logging as user 0 failed");
#endif


	// Define the curve to be P256
	VLT_ECC_ID curveId = VLT_ECC_ID_P256;
	do
	{
		//---------------------------------------------------------------------
		// Set the P256 parameters
		//---------------------------------------------------------------------
		TEST_DATA* testData = &test_params->testData;
		testData->pu8_Host_D = auc_Host_D_P256;
		testData->pu8_Host_Qx = auc_Host_Qx_P256;
		testData->pu8_Host_Qy = auc_Host_Qy_P256;

		testData->pu8_Device_D = auc_Device_D_P256;
		testData->pu8_Device_Qx = auc_Device_Qx_P256;
		testData->pu8_Device_Qy = auc_Device_Qy_P256;
		testData->pu8_CurveName = auc_CurveName_P256;

		//---------------------------------------------------------------------
		// Select the CSR to use
		//---------------------------------------------------------------------
		//csrdefs csrselection = DeviceIdentity;
		//csrdefs csrselection = DeviceNetworkCredentials;
		csrdefs csrselection = TestCsr;
		if (VLT_OK != (usActualSW = VltSelectCsr(csrselection)))
			CloseAndExit(usActualSW, "Select CSR failed");

		//---------------------------------------------------------------------
		// Create the basic filename
		//---------------------------------------------------------------------
		VLT_U8 sFilename[100] = { 0 };
		if (VLT_OK != (usActualSW = VltGetRootFilename(sFilename, 100, csrselection)))
			CloseAndExit(usActualSW, "Create root filename failed");

		//---------------------------------------------------------------------
		// Base 64 Encode Starting CSR
		//---------------------------------------------------------------------
		VLT_U8 pCsr[MAXLEN_CSR] = { 0 };
		VLT_U16 lenCsr = csrlen_data;
		// Copy the CSR Template into the working buffer
		if (MAXLEN_CSR > csrlen_data) memcpy(pCsr, pCsr_data, lenCsr);
		VLT_U8 pBase64Csr[MAXLEN_CSR_B64 + CSR_LEN_HEADER + CSR_LEN_FOOTER] = { 0 };
		VLT_U16 maxLenBase64 = MAXLEN_CSR_B64 + CSR_LEN_HEADER + CSR_LEN_FOOTER;
		VLT_U16 lenBase64 = maxLenBase64;
		if (VLT_OK != (usActualSW = VltBuildBase64Csr(pCsr, lenCsr, pBase64Csr, &lenBase64)))
			CloseAndExit(usActualSW, "Build Base64 CSR failed");

		printf("[PEM CSR - Starting]\n");
		printf((const char*)pBase64Csr);
		printf("\n\n");

		//---------------------------------------------------------------------
		// Print the base data to CSR, HexText, and ASN.1 files
		//---------------------------------------------------------------------
		// ASN
		//if (VLT_OK != (usActualSW = VltWriteDataBuffer(pCsr, lenCsr, sFilename, "start.asn")))
		//	CloseAndExit(usActualSW, "VltWriteDataBuffer ASN failed");

		// CSR
		if (VLT_OK != (usActualSW = VltWriteText(pBase64Csr, sFilename, (VLT_U8*)"start.csr")))
			CloseAndExit(usActualSW, "VltWriteText CSR failed");

		//---------------------------------------------------------------------
		// Create ECDSA domain params 
		//---------------------------------------------------------------------
		VLT_KEY_OBJECT domainParams;
		VLT_U8 domainGrp = ECC_P256_Para_Group;
		VLT_U8 domainIdx = ECC_P256_Para_Index;
		if (VLT_OK != (usActualSW = VltCreateEcdsaDomainParams(TLS_USER_ID, curveId, domainGrp, domainIdx, &domainParams)))
			CloseAndExit(usActualSW, "Set Key Obj Domain Params failed");

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
		if (VLT_OK != (usActualSW = VltGenKey(TLS_USER_ID, curveId,genGrp, genPubIdx, genPrivIdx, &genPub)))
			CloseAndExit(usActualSW, "Generate ECC keypair failed");

		printf("PubKeyX (VaultIC)");
		PrintHexBuffer(genPub.pu8Qx, P256_BYTE_SZ);

		printf("PubKeyY (VaultIC)");
		PrintHexBuffer(genPub.pu8Qy, P256_BYTE_SZ);

		//---------------------------------------------------------------------
		// Insert Public key into CSR
		//---------------------------------------------------------------------
		VLT_U8 pPubKey[2 * P256_BYTE_SZ] = { 0 };
		VLT_U16 locPubKey = csrloc_pubKey;
		VLT_U16 lenPubKey = csrlen_pubKey;
		// Copy the x&y of the public key into the buffer
		memcpy(pPubKey, pX, P256_BYTE_SZ);
		memcpy(pPubKey + P256_BYTE_SZ, pY, P256_BYTE_SZ);
		// Merge the public key into the CSR
		if (VLT_OK != (usActualSW = VltCsrMergePubKey(pCsr, lenCsr, locPubKey, pPubKey, lenPubKey)))
			CloseAndExit(usActualSW, "Merge public key in CSR failed");

		//---------------------------------------------------------------------
		// Sign the CSR TBS
		//---------------------------------------------------------------------
		VLT_U8 pSig[2 * P256_BYTE_SZ] = { 0 };
		VLT_U16 lenSig = sizeof(pSig);
		VLT_U8* pTbs = pCsr + csrtbs_offset;
		VLT_U16 lenTbs = csrtbs_len;
		if (VLT_OK != (usActualSW = VltSign(curveId, genGrp, genPrivIdx, pTbs, lenTbs, pSig, &lenSig)))
			CloseAndExit(usActualSW, "Generate Signature failed");

		printf("[Signature]");
		PrintHexBuffer(pSig, lenSig);

		//---------------------------------------------------------------------
		// Insert Signature into CSR
		//---------------------------------------------------------------------
		VLT_U16 locSig = csrloc_sig;
		// Reset the lenCsr to the max length. It will be set to the final length once signature is merged.
		lenCsr = MAXLEN_CSR;
		// Merge the signature into the CSR
		if (VLT_OK != (usActualSW = VltCsrMergeSig(pCsr, &lenCsr, locSig, pSig, lenSig)))
			CloseAndExit(usActualSW, "Merge Signaure failed");

		printf("[CSR]");
		PrintHexBuffer(pCsr, lenCsr);

		//---------------------------------------------------------------------
		// Base 64 Encode Merged CSR
		//---------------------------------------------------------------------
		lenBase64 = maxLenBase64;
		if (VLT_OK != (usActualSW = VltBuildBase64Csr(pCsr, lenCsr, pBase64Csr, &lenBase64)))
			CloseAndExit(usActualSW, "Build Base64 CSR failed");

		printf("[Merged PEM CSR]\n");
		printf((const char*)pBase64Csr);
		printf("\n\n");

		//---------------------------------------------------------------------
		// Write the CSR to a file
		//---------------------------------------------------------------------
		VltWriteText(pBase64Csr, config.FACTORY_CSR_PATH, (VLT_U8*)"");

#ifdef _WIN32
		//---------------------------------------------------------------------
		// Verify the CSR signature
		//---------------------------------------------------------------------
		if (VLT_OK != (usActualSW = VltVerify(curveId, &genPub, pTbs, lenTbs, pSig, lenSig)))
			CloseAndExit(usActualSW, "Verify Signature failed");
#endif
	} while (0);

	//---------------------------------------------------------------------
	// Log out 
	//---------------------------------------------------------------------
	if (VLT_OK != (usActualSW = VltCancelAuthentication()))
		CloseAndExit(usActualSW, "De-authentication failed");

#ifdef DEMO_RESET
	printf("End of demo - reinitializing VaultIC \n");
	//---------------------------------------------------------------------
	// Log back in as the manufacturer.  
	//---------------------------------------------------------------------
	if (VLT_OK != (usActualSW = VltSubmitPassword(VLT_USER7,
		VLT_MANUFACTURER,
		test_params->u8ManufPasswordLength,
		test_params->au8ManufPassword)))
		CloseAndExit(usActualSW, "Manufacturer authentication failed");

	//---------------------------------------------------------------------
	// Transition to the creation state, wipes the file system.
	//---------------------------------------------------------------------
	if (VLT_OK != (usActualSW = VltSetStatus(VLT_STATE_CREATION)))
		CloseAndExit(usActualSW, "Set status (CREATION) failed");

	//---------------------------------------------------------------------
	// Delete user 0, which should leave the VaultIC in a virgin state.
	//---------------------------------------------------------------------
	structAuthSetup.enOperationID = VLT_DELETE_USER;
	structAuthSetup.enUserID = VLT_USER0;

	if (VLT_OK != (usActualSW = VltManageAuthenticationData(
		&structAuthSetup)))
		CloseAndExit(usActualSW, "Delete User 0 failed");

	//---------------------------------------------------------------------
	// Log the manufacturer out of the VaultIC Secure Object.
	//---------------------------------------------------------------------
	if (VLT_OK != (usActualSW = VltCancelAuthentication()))
		CloseAndExit(usActualSW, "De-authentication failed");

	printf("VaultIC Reinit complete \n\n");
#endif

	CloseAndExit(usActualSW, "Key CSR demo successful !!!");
}





