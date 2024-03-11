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
* @brief  Demo code that builds a CSR buffer
*
*/

#include "vaultic_common.h"
#include "vaultic_api.h"
#include "vaultic_ecdsa_signer.h"
#include "vaultic_bigdigits.h"
#include "common.h"
#include "vaultic_csr.h"

#ifndef _WIN32
#include <unistd.h>
#include <limits.h>
#endif // !_WIN32


//>>>DeviceIdentity CSR>>>>>>>>>>>>>>>>>>>>>>>
VLT_U16 csrloc_deviceId_pubKey = 106;
VLT_U16 csrlen_deviceId_pubKey = 64;
VLT_U16 csrloc_deviceId_sig = 184;  // the length of the signature is variable
VLT_U16 csrtbs_deviceId_len = 169;
VLT_U16 csrtbs_deviceId_offset = 3;
VLT_U8 csr_deviceId_data[] =
{
	0x30, 0x81, 0xFE, 0x30, 0x81, 0xA6, 0x02, 0x01, 0x00, 0x30, 0x44, 0x31, 0x0D, 0x30, 0x0B, 0x06,
	0x03, 0x55, 0x04, 0x0A, 0x0C, 0x04, 0x4E, 0x49, 0x53, 0x54, 0x31, 0x19, 0x30, 0x17, 0x06, 0x03,
	0x55, 0x04, 0x0B, 0x0C, 0x10, 0x4E, 0x43, 0x43, 0x6F, 0x45, 0x20, 0x4F, 0x6E, 0x62, 0x6F, 0x61,
	0x72, 0x64, 0x69, 0x6E, 0x67, 0x31, 0x18, 0x30, 0x16, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x0F,
	0x44, 0x65, 0x76, 0x69, 0x63, 0x65, 0x20, 0x49, 0x64, 0x65, 0x6E, 0x74, 0x69, 0x74, 0x79, 0x30,
	0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x86,
	0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x78, 0x76, 0x4B, 0xDC, 0xD5, 0xF5,
	0xB1, 0x40, 0x7F, 0xD9, 0x26, 0xC7, 0x4E, 0x5D, 0xC9, 0xAE, 0x2E, 0x31, 0x32, 0xC2, 0xAE, 0x38,
	0x14, 0xAB, 0xE1, 0xA8, 0x0F, 0xDD, 0xD1, 0xCF, 0xE4, 0x0B, 0x69, 0xE6, 0xBD, 0x64, 0x9A, 0x45,
	0x2C, 0x99, 0x7D, 0x9A, 0x68, 0xB8, 0xB2, 0x67, 0x70, 0xCA, 0x75, 0x4A, 0x24, 0x49, 0x89, 0x12,
	0x73, 0xF6, 0x7A, 0xC2, 0xEE, 0x8C, 0x4B, 0xB9, 0x81, 0x0F, 0xA0, 0x00, 0x30, 0x0A, 0x06, 0x08,
	0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02, 0x03, 0x47, 0x00, 0x30, 0x44, 0x02, 0x20, 0x61,
	0xB2, 0x1F, 0xE2, 0xDD, 0xE5, 0x97, 0x9D, 0x71, 0x2A, 0xFB, 0x91, 0x3E, 0xFE, 0xF8, 0x1C, 0x12,
	0xEB, 0x42, 0x3C, 0xBA, 0x8B, 0x4A, 0xC8, 0x4E, 0x28, 0x46, 0x8D, 0x76, 0xC9, 0x0F, 0x50, 0x02,
	0x20, 0x45, 0x36, 0x67, 0x6A, 0xFD, 0xC6, 0x0C, 0x68, 0xE9, 0x30, 0x3A, 0xDC, 0x37, 0x2A, 0x36,
	0xB1, 0x35, 0x38, 0x13, 0x50, 0x6A, 0xE1, 0x78, 0x73, 0x55, 0x81, 0xC8, 0x68, 0xA0, 0xA5, 0x20,
	0xD9
};
VLT_U16 csrlen_deviceId_data = sizeof(csr_deviceId_data);
//<<<DeviceIdentity CSR<<<<<<<<<<<<<<<<<<<<<<<

//>>>DeviceNetworkCredentials CSR>>>>>>>>>>>>>>>>>>>>>>>
VLT_U16 csrloc_deviceNet_pubKey = 146;
VLT_U16 csrlen_deviceNet_pubKey = 64;
VLT_U16 csrloc_deviceNet_sig = 224;  // the length of the signature is variable
VLT_U16 csrtbs_deviceNet_len = 208;
VLT_U16 csrtbs_deviceNet_offset = 4;
VLT_U8 csr_deviceNet_data[] =
{
	0x30, 0x82, 0x01, 0x25, 0x30, 0x81, 0xCD, 0x02, 0x01, 0x00, 0x30, 0x6B, 0x31, 0x0B, 0x30, 0x09,
	0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x0D, 0x30, 0x0B, 0x06, 0x03, 0x55,
	0x04, 0x0A, 0x0C, 0x04, 0x4E, 0x49, 0x53, 0x54, 0x31, 0x28, 0x30, 0x26, 0x06, 0x03, 0x55, 0x04,
	0x0B, 0x0C, 0x1F, 0x4E, 0x43, 0x43, 0x6F, 0x45, 0x20, 0x4E, 0x65, 0x74, 0x77, 0x6F, 0x72, 0x6B,
	0x20, 0x4C, 0x61, 0x79, 0x65, 0x72, 0x20, 0x4F, 0x6E, 0x62, 0x6F, 0x61, 0x72, 0x64, 0x69, 0x6E,
	0x67, 0x20, 0x31, 0x23, 0x30, 0x21, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x1A, 0x44, 0x65, 0x76,
	0x69, 0x63, 0x65, 0x20, 0x4E, 0x65, 0x74, 0x77, 0x6F, 0x72, 0x6B, 0x20, 0x43, 0x72, 0x65, 0x64,
	0x65, 0x6E, 0x74, 0x69, 0x61, 0x6C, 0x73, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48,
	0xCE, 0x3D, 0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42,
	0x00, 0x04, 0x6B, 0x21, 0xC1, 0x92, 0x1B, 0xB0, 0x33, 0xBC, 0xC8, 0x25, 0xB1, 0xA0, 0xC5, 0x7A,
	0x44, 0xDB, 0x26, 0x9C, 0x6A, 0xA8, 0x99, 0xF8, 0x65, 0xAF, 0x15, 0x86, 0xD6, 0x38, 0x58, 0x00,
	0x07, 0xEE, 0x6A, 0x94, 0x3E, 0xDD, 0xA0, 0x7A, 0xBD, 0x27, 0x9B, 0x68, 0xA8, 0x93, 0x4A, 0xD6,
	0xB0, 0x1F, 0xEE, 0x1E, 0x3B, 0x2F, 0x4A, 0xEA, 0x4E, 0xA3, 0x9C, 0x48, 0x5C, 0x78, 0x41, 0xE5,
	0x4A, 0xF1, 0xA0, 0x00, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02,
	0x03, 0x47, 0x00, 0x30, 0x44, 0x02, 0x20, 0x0E, 0xE2, 0x3D, 0x46, 0x74, 0x55, 0x11, 0x35, 0xCE,
	0xBF, 0x48, 0xE9, 0xF3, 0x12, 0x79, 0x97, 0x17, 0xD4, 0xFF, 0x40, 0x00, 0xB0, 0x8B, 0x3C, 0x62,
	0xC5, 0xD2, 0x9B, 0x9F, 0x4C, 0x51, 0x4A, 0x02, 0x20, 0x20, 0xDA, 0xC0, 0x2C, 0xD3, 0x84, 0x6E,
	0xDC, 0xB2, 0x5A, 0xF0, 0xC2, 0x6C, 0x8A, 0xAB, 0x72, 0xD3, 0x87, 0x09, 0x29, 0x44, 0xE5, 0x88,
	0x82, 0x64, 0xC5, 0x7F, 0xDF, 0xA5, 0xFE, 0x2F, 0x96
};
VLT_U16 csrlen_deviceNet_data = sizeof(csr_deviceNet_data);
//<<<DeviceNetworkCredentials CSR<<<<<<<<<<<<<<<<<<<<<<<

// >>>Test CSR>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
VLT_U16 csrloc_testCsr_pubKey = 85;
VLT_U16 csrlen_testCsr_pubKey = 64;
VLT_U16 csrloc_testCsr_sig = 180;  // the length of the signature is variable
VLT_U16 csrtbs_testCsr_len = 165;
VLT_U16 csrtbs_testCsr_offset = 3;
VLT_U8 csr_testCsr_data[] =
{ 
	0x30, 0x81, 0xfb, 0x30, 0x81, 0xa2, 0x02, 0x01, 0x00, 0x30, 0x2f, 0x31, 0x14, 0x30, 0x12, 0x06,
	0x03, 0x55, 0x04, 0x0a, 0x0c, 0x0b, 0x45, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x20, 0x49, 0x6e,
	0x63, 0x31, 0x17, 0x30, 0x15, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0e, 0x45, 0x78, 0x61, 0x6d,
	0x70, 0x6c, 0x65, 0x20, 0x44, 0x65, 0x76, 0x69, 0x63, 0x65, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07,
	0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01,
	0x07, 0x03, 0x42, 0x00, 0x04, 0xd8, 0x70, 0xa4, 0xdf, 0x98, 0xb4, 0x6a, 0x93, 0x2b, 0xf7, 0x40,
	0x39, 0x86, 0x0f, 0xed, 0xd6, 0x69, 0x03, 0x6a, 0xe7, 0xe4, 0x84, 0x9f, 0xfc, 0xfb, 0x61, 0x50,
	0x63, 0x21, 0x95, 0xa8, 0x91, 0x2c, 0x98, 0x04, 0x0e, 0x9c, 0x2f, 0x03, 0xe1, 0xe4, 0x2e, 0xc7,
	0x93, 0x8c, 0x6b, 0xf4, 0xfb, 0x98, 0x4c, 0x50, 0xdb, 0x51, 0xa3, 0xee, 0x04, 0x1b, 0x55, 0xf0,
	0x60, 0x63, 0xeb, 0x46, 0x90, 0xa0, 0x11, 0x30, 0x0f, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
	0x0d, 0x01, 0x09, 0x0e, 0x31, 0x02, 0x30, 0x00, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce,
	0x3d, 0x04, 0x03, 0x02, 0x03, 0x48, 0x00, 0x30, 0x45, 0x02, 0x20, 0x26, 0xab, 0x8a, 0x4f, 0x71,
	0x2c, 0xf9, 0xbb, 0x4f, 0xfa, 0xa4, 0xcd, 0x01, 0x48, 0xf1, 0xdf, 0x9c, 0xdc, 0xff, 0xa0, 0xff,
	0x53, 0x8f, 0x35, 0x8d, 0xd4, 0x3d, 0x49, 0xc0, 0x72, 0xf5, 0x0a, 0x02, 0x21, 0x00, 0xa5, 0x9d,
	0xb4, 0x11, 0x4b, 0xa1, 0x65, 0x7c, 0xbb, 0x48, 0xcf, 0x6d, 0xf6, 0xd0, 0x6a, 0x41, 0x00, 0x96,
	0xe1, 0xe2, 0x79, 0x73, 0xdb, 0xf7, 0x97, 0x80, 0x41, 0x9b, 0x35, 0x01, 0x88, 0x5e
};
VLT_U16 csrlen_testCsr_data = sizeof(csr_testCsr_data);
// <<<Test CSR<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<

// Initialize the extern 
VLT_U16 csrlen_max	= 0;
VLT_U16 csrlen_max_b64	= 0;
VLT_U16 csrloc_pubKey	= 0;
VLT_U16 csrlen_pubKey	= 0;
VLT_U16 csrloc_sig	= 0;
VLT_U16 csrtbs_len	= 0;
VLT_U16 csrtbs_offset	= 0;
VLT_U8* pCsr_data	= 0;
VLT_U16 csrlen_data	= 0;


/**
 * \brief			Initialize the CSR to the selected definition
 * \param[in] id	ID of the selected CSR
 * \return			VLT_OK on success otherwise an error code
*/
VLT_STS VltSelectCsr(csrdefs selection)
{
	unsigned short usActualSW = 0;

	switch (selection)
	{
	case DeviceIdentity:
		csrloc_pubKey = csrloc_deviceId_pubKey;
		csrlen_pubKey = csrlen_deviceId_pubKey;
		csrloc_sig = csrloc_deviceId_sig;
		csrtbs_len = csrtbs_deviceId_len;
		csrtbs_offset = csrtbs_deviceId_offset;
		pCsr_data = csr_deviceId_data;
		csrlen_data = csrlen_deviceId_data;
		csrlen_max = csrlen_deviceId_data;
		break;
	case DeviceNetworkCredentials:
		csrloc_pubKey = csrloc_deviceNet_pubKey;
		csrlen_pubKey = csrlen_deviceNet_pubKey;
		csrloc_sig = csrloc_deviceNet_sig;
		csrtbs_len = csrtbs_deviceNet_len;
		csrtbs_offset = csrtbs_deviceNet_offset;
		pCsr_data = csr_deviceNet_data;
		csrlen_data = csrlen_deviceNet_data;
		csrlen_max = csrlen_deviceNet_data;
		break;
	case TestCsr:
		csrloc_pubKey = csrloc_testCsr_pubKey;
		csrlen_pubKey = csrlen_testCsr_pubKey;
		csrloc_sig = csrloc_testCsr_sig;
		csrtbs_len = csrtbs_testCsr_len;
		csrtbs_offset = csrtbs_testCsr_offset;
		pCsr_data = csr_testCsr_data;
		csrlen_data = csrlen_testCsr_data;
		csrlen_max = csrlen_testCsr_data;
		break;
	default:
		// Selection is not defined
		CloseAndExit(usActualSW, "Selection not defined for VltSelectCsr()");
		break;
	}
	// Define the max length of the resulting CSR to be 2 bytes larger that the template buffer 
	// to account for adding leading 0's for unsigned signature R&S in X.509 
	csrlen_max += 2;
	// When encoding to base64, the result will turn out to be approximately 4/3 of the data buffer size
	csrlen_max_b64 = (4 * (csrlen_max + 2) / 3);

	// Verify the max CSR lengths
	if (csrlen_max > MAXLEN_CSR || csrlen_max_b64 > MAXLEN_CSR_B64)
		CloseAndExit(usActualSW, "Max CSR definition exceeds buffer definigion in VltSelectCsr()\n Increase the size of #define MAXLEN_CSR\n");

#ifndef _WIN32
	// Get the current working directory
	char cwd[PATH_MAX];
	printf("\n\n>>>>>>>>>>>>\n");
	if (getcwd(cwd, sizeof(cwd)) != NULL) {
		printf("Current working dir: %s\n", cwd);
	} else {
		perror("getcwd() error\n");
	}
	printf(">>>>>>>>>>>>\n\n");
#endif

	return VLT_OK;
}

/**
 * \brief Root filename based on the CSR selection.
 * \param[out]		pRootFilename			Pointer to the filename buffer
 * \param[in]		lenRootFilename			Length of the encoded data to write
 * \param[in]		pRootFilename	Root Name the csr file based on the selected CSR definition
 * \return		VLT_OK on success otherwise an error code
*/
VLT_STS VltGetRootFilename(VLT_U8* pRootFilename, VLT_U16 lenRootFilename, csrdefs csrselection)
{
	unsigned short usActualSW = 0;

	// Check input parameters
	if (pRootFilename == NULL && lenRootFilename > 20)
		CloseAndExit(usActualSW, "Bad input parameters for VltGetRootFilename()");

	switch (csrselection)
	{
	case DeviceIdentity:
		memcpy(pRootFilename, "DeviceId", sizeof("DeviceId"));
		break;
	case DeviceNetworkCredentials:
		memcpy(pRootFilename, "DeviceNet", sizeof("DeviceNet"));
		break;
	case TestCsr:
		memcpy(pRootFilename, "TestCsr", sizeof("TestCsr"));
		break;
	default:
		break;
	}
	return VLT_OK;
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

/**
 * \brief Signs a message buffer and returns a signature
 * \param[in]		curveId			The ECC curve that the domain is defined for
 * \param[in]		privGrp			Group ID for the private key
 * \param[in]		privIdx			Key ID for the private key
 * \param[in]		pMsg			Message to be signed
 * \param[in]		lenMsg			Length of pMsg
 * \param[out]		pSig			Needs to be initialized in caller. Holds the signature that is created.
 * \param[in/out]	pLenSig			As input, the max size of the pSig buffer
 *									As output, the final size of the signature
 * \return		VLT_OK on success otherwise an error code
*/
VLT_STS VltSign(VLT_ECC_ID curveId, VLT_U8 privGrp, VLT_U8 privIdx, VLT_U8* pMsg, VLT_U16 lenMsg, VLT_U8* pSig, VLT_U16* pLenSig)
{
	unsigned short usActualSW = 0;

	// Check input parameters
	if (pMsg == NULL || pLenSig == NULL || pSig == NULL)
		CloseAndExit(usActualSW, "Bad input parameters for VltSign()");

	// Set the digest algorithm to SHA256
	VLT_ALG_DIG_ID digest_id = VLT_ALG_DIG_SHA256;

	// Query to determine if this is a prime curve.
	VLT_BOOL isPrimeCurve;
	if (VLT_OK != (usActualSW = EcdsaIsPcurve(curveId, &isPrimeCurve)))
		CloseAndExit(usActualSW, "isPrimeCurve failed");

	// Init the VaultIC Firmware to perform ECDSA signature.
	VLT_ALGO_PARAMS strctAlgoParms;
	strctAlgoParms.data.EcdsaDsa.enDigestId = digest_id;
	if (isPrimeCurve)
		strctAlgoParms.u8AlgoID = VLT_ALG_SIG_ECDSA_GFP;
	else
		strctAlgoParms.u8AlgoID = VLT_ALG_SIG_ECDSA_GF2M;

	if (VLT_OK != (usActualSW = VltInitializeAlgorithm(
		privGrp,
		privIdx,
		VLT_SIGN_MODE,
		&strctAlgoParms)))
		CloseAndExit(usActualSW, "Initialize algo failed");

	// Compute the signature (VaultIC)
	VLT_U16 lenSig = *pLenSig;
	printf("----------------------------------------------------------\n");
	printf("   Sign the whole message with the device's private key   \n");
	printf("   (signature computed by VaultIC)                        \n");
	printf("----------------------------------------------------------\n");

	if (VLT_OK != (usActualSW = VltGenerateSignature(lenMsg, pMsg, pLenSig, lenSig, pSig)))
		CloseAndExit(usActualSW, "Generate Signature failed");

	return VLT_OK;
}

/**
 * \brief Verify the signature given the message that was signed, the public key of signer and the signature
 * \param[in]		curveId			The ECC curve that the domain is defined for
 * \param[in]		pPubObj			Public key object 
 * \param[in]		pMsg			Pointer to the message that was signed
 * \param[in]		lenMsg			Length of the message that was signed
 * \param[in]		pSig			Pointer to the signature buffer
 * \param[in]		lenSig			Length of the signature buffer
 * \return		VLT_OK on success otherwise an error code
*/
VLT_STS VltVerify(VLT_ECC_ID curveId, VLT_KEY_OBJ_ECDSA_PUB* pPubObj, VLT_U8* pMsg, VLT_U16 lenMsg, VLT_U8* pSig, VLT_U16 lenSig)
{
	unsigned short usActualSW = 0;

	// Check input parameters
	if (pPubObj == NULL || pMsg == NULL || pSig == NULL)
		CloseAndExit(usActualSW, "Bad input parameters for VltVerify()");

	//---------------------------------------------------------------------
	// Verify the signature using the vaultic's public key
	// (signature verification done from host side)
	//---------------------------------------------------------------------

	printf("Verify the signature on host (sw verify)\n");

	// Set the digest algorithm to SHA256
	VLT_ALG_DIG_ID digest_id = VLT_ALG_DIG_SHA256;

	VLT_ECDSA_PUBLIC_KEY theEcdsaPublicKey;
	theEcdsaPublicKey.u16QLen = pPubObj->u16QLen;
	theEcdsaPublicKey.pu8Qx = pPubObj->pu8Qx;
	theEcdsaPublicKey.pu8Qy = pPubObj->pu8Qy;

	if (VLT_OK != (usActualSW = EcdsaSignerInit(curveId, digest_id, NULL, &theEcdsaPublicKey, VLT_SIGNER_MODE_VERIFY)))
	{
		CloseAndExit(usActualSW, "EcdsaSignerInit failed");
	}

	if (VLT_OK != (usActualSW = EcdsaSignerDoFinal(pMsg, lenMsg, pSig, &lenSig, 0)))
	{
		CloseAndExit(usActualSW, "EcdsaSignerDoFinal failed");
	}

	/* clear down and free signer resources */
	if (VLT_OK != (usActualSW = EcdsaSignerClose()))
	{
		CloseAndExit(usActualSW, "EcdsaSignerClose failed");
	}

	printf("Signature successfully verified by the host \n");

	return VLT_OK;
}

/**
 * \brief Merge the public key into the CSR
 * \param[in]		pCsr		Pointer to the CSR buffer
 * \param[in]		lenCsr		Length of the CSR buffer
 * \param[in]		locPubKey	Location of the public key in the CSR buffer
 * \param[in]		pPubKey		Pointer to the public key buffer
 * \param[in]		lenPubKey	Length of the public key buffer
 * \return		VLT_OK on success otherwise an error code
*/
VLT_STS VltCsrMergePubKey(VLT_U8* pCsr, VLT_U16 lenCsr, VLT_U16 locPubKey, VLT_U8* pPubKey, VLT_U16 lenPubKey)
{
	unsigned short usActualSW = 0;

	// Check input parameters
	if (pCsr == NULL || pPubKey == NULL)
		CloseAndExit(usActualSW, "Bad input parameters for VltCsrMergePubKey()");

	// Copy the public key into the location
	if (locPubKey+lenPubKey < lenCsr)
		memcpy(pCsr+locPubKey, pPubKey, lenPubKey);

	return VLT_OK;
}

/**
 * \brief Merge the R&S bytes of a P256 signature into a P256 CSR
 * \param[in]		pCsr		The buffer that holds the CSR
 * \param[in,out]	pLenCsr		As input, the max size of the pCsr buffer
 *								As output, the final size of the CSR
 * \param[in]		locSig		The byte location of the signature in pCsr
 * \param[in]		pSig		The buffer that holds the signature
 * \param[in]		lenSig		The length of the signature
 * \return			VLT_OK on success otherwise an error code
*/
VLT_STS VltCsrMergeSig(VLT_U8* pCsr, VLT_U16* pLenCsr, VLT_U16 locSig, VLT_U8* pSig, VLT_U16 lenSig)
{
	unsigned short usActualSW = 0;

	// Check input parameters
	if (pLenCsr == NULL || pCsr == NULL || pSig == NULL)
		CloseAndExit(usActualSW, "Bad input parameters for VltCsrMergeSig()");

	VLT_U16 lenSigMax = *pLenCsr - locSig;
	if (lenSigMax < MAXLEN_P256_X509_SIG)
		CloseAndExit(usActualSW, "Signature buffer too small");

	// Encode the signature for X.509 "in-place" in the CSR buffer
	VLT_U8* pDerSig = pCsr + locSig;

	// Parse the signature into R & S parts adding the leading 0 for unsigned integers
	if (lenSig != 2*P256_BYTE_SZ)
		CloseAndExit(usActualSW, "Signature length incorrect");
	VLT_U8 pR[P256_BYTE_SZ + 1] = { 0 };
	VLT_U8 pS[P256_BYTE_SZ + 1] = { 0 };
	memcpy(pR + 1, pSig, P256_BYTE_SZ);
	memcpy(pS + 1, pSig + P256_BYTE_SZ, P256_BYTE_SZ);

	// Since R & S are x.509 unsigned integers, the first bit must be a 0.
	// If the first bit is a 1, then a preceding 0x00 byte must be added and the size of the OID adjusted
	VLT_U8 bRPad = (pR[1] & 0x80) ? 1 : 0;
	VLT_U8 bSPad = (pS[1] & 0x80) ? 1 : 0;
	VLT_U16 offsetR = bRPad ? 0 : 1;
	VLT_U16 offsetS = bSPad ? 0 : 1;
	VLT_U16 lenR = P256_BYTE_SZ + bRPad;
	VLT_U16 lenS = P256_BYTE_SZ + bSPad;

	// Insert the R&S elements of the signature
	// R signature
	VLT_U16 locOffset = OFFSET_RSIG;
	pDerSig[locOffset] = 0x02;
	pDerSig[++locOffset] = (VLT_U8)lenR;
	memcpy(pDerSig + ++locOffset, pR + offsetR, lenR);
	locOffset += lenR;
	// S signature
	pDerSig[locOffset] = 0x02;
	pDerSig[++locOffset] = (VLT_U8)lenS;
	memcpy(pDerSig + ++locOffset, pS + offsetS, lenS);
	VLT_U16 lenSigDer = locOffset + lenS;
	*pLenCsr = lenSigDer + locSig;

	// Adjust the size bytes of the DER Signature
	pDerSig[1] = (VLT_U8)(lenSigDer - OFFSET_SIG_DER);
	pDerSig[4] = (VLT_U8)(lenSigDer - OFFSET_RSIG);
//	pDerSig[4] = 2 * (P256_BYTE_SZ + 2) + bSPad + bRPad;

	// Adjust the overall size of the CSR including signature (subtract the initial DER header)
	VLT_U16 lenCsrFull = (VLT_U16)(*pLenCsr - csrtbs_offset);
	if (lenCsrFull > 0xFF)
	{
		VLT_U8 multiplier = (lenCsrFull > 0x1FF) ? 0x02 : 0x01;
		pCsr[CSR_SIZE_INDEX] = multiplier;
		pCsr[CSR_SIZE_INDEX + 1] = (VLT_U8)(lenCsrFull - (multiplier * 0x100));
	}
	else
	{
		pCsr[CSR_SIZE_INDEX] = (VLT_U8)lenCsrFull;
	}
	return VLT_OK;
}

/**
 * \brief Build the CSR PEM, a base 64 encoded text buffer
 * \param[in]		pData		Pointer to the CSR data
 * \param[in]		lenData		Length of the CSR data
 * \param[out]		pBase64		Must pass in a valid buffer from calling routine. Buffer is filled with the PEM CSR
 * \param[in]		pLenBase64	Base64 buffer must be at least [4 * ((lenData + 2) / 3) + CSR_LEN_HEADER + CSR_LEN_FOOTER
 * \return		VLT_OK on success otherwise an error code
*/
VLT_STS VltBuildBase64Csr(VLT_U8* pData, VLT_U16 lenData, VLT_U8* pBase64, VLT_U16* pLenBase64)
{
	VLT_U16 retStat = VLT_OK;
	VLT_U8 pCsrHeader[] = "-----BEGIN CERTIFICATE REQUEST-----";
	VLT_U8 pCsrFooter[] = "-----END CERTIFICATE REQUEST-----";
	// Remove the null terminator from the sizes
	VLT_U16 lenHeader = sizeof(pCsrHeader) - 1;
	VLT_U16 lenFooter = sizeof(pCsrFooter) - 1;

	// Check input parameters
	if (pData == NULL || pBase64 == NULL || pLenBase64 == NULL)
	{
		retStat = VLT_FAIL;
		CloseAndExit(retStat, "Bad input parameters for VltBuildBase64Csr()");
	}

	// Check the buffer lengths
	VLT_U16 lenOut = (4 * ((lenData + 2) / 3)) + CSR_NEWLINE;
	if (*pLenBase64 < (lenOut + lenHeader + lenFooter))
	{
		retStat = VLT_FAIL;
		CloseAndExit(retStat, "Base64 buffer too small VltBuildBase64Csr()");
	}

	// Convert binary data to an integer string in base64.
	// Offset the encoded data to accomodate the header
	VLT_U8* pDataB64 = pBase64 + lenHeader;
	VLT_U16 newlineByte = 65;
	VLT_U16 lenDataB64 = *pLenBase64 - lenHeader;
	if (VLT_OK != (retStat = Base64Encode(pData, lenData, pDataB64, &lenDataB64, newlineByte)))
		CloseAndExit(retStat, "Build Base64 CSR failed");

	// Add the header and footer
	memcpy(pBase64, pCsrHeader, lenHeader);
	memcpy(pBase64 + lenHeader + lenDataB64, pCsrFooter, lenFooter);
	*pLenBase64 = lenHeader + lenDataB64 + lenFooter;

	return retStat;
}


static VLT_U8 encTable[] = {	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
								'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
								'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
								'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
								'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
								'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
								'w', 'x', 'y', 'z', '0', '1', '2', '3',
								'4', '5', '6', '7', '8', '9', '+', '/' };

/**
 * \brief Base 64 encode an arbitrary buffer.
 * \param[in]		pData		Pointer to the data to encode
 * \param[in]		lenData		Length of the data to encode
 * \param[out]		pBase64		Must pass in a valid buffer from calling routine. Buffer is filled with the PEM CSR
 * \param[in]		pLenBase64	Base64 buffer must be at least [4 * ((lenData + 2) / 3) + CSR_LEN_HEADER + CSR_LEN_FOOTER
 * \param[in]		newlineByte	Column to insert newline character, ==0 if no newline. Typically 64 for PEM cert/csr.
 * \return		VLT_OK on success otherwise an error code
*/
VLT_STS Base64Encode(VLT_U8* pData, VLT_U16 lenData, VLT_U8* pBase64, VLT_U16* pLenBase64, VLT_U16 newlineByte)
{
	unsigned short usActualSW = 0;

	// Check input parameters
	if (pData == NULL || pLenBase64 == NULL || pBase64 == NULL)
		CloseAndExit(usActualSW, "Bad input parameters for Base64Encode()");

	// Verify output size
	VLT_U16 lenOut = 4 * ((lenData + 2) / 3);
	if (lenOut > *pLenBase64)
		CloseAndExit(usActualSW, "Base64 Buffer too Small");

	VLT_U16 encodeIdx = 0;
	for (int i = 0; i < lenData;)
	{
		VLT_U32 octet_a = i < lenData ? (VLT_U8)pData[i++] : 0;
		VLT_U32 octet_b = i < lenData ? (VLT_U8)pData[i++] : 0;
		VLT_U32 octet_c = i < lenData ? (VLT_U8)pData[i++] : 0;

		VLT_U32 triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

		if (!(encodeIdx % newlineByte) && newlineByte) pBase64[encodeIdx++] = '\n';
		pBase64[encodeIdx++] = encTable[(triple >> 3 * 6) & 0x3F];
		if (!(encodeIdx % newlineByte) && newlineByte) pBase64[encodeIdx++] = '\n';
		pBase64[encodeIdx++] = encTable[(triple >> 2 * 6) & 0x3F];
		if (!(encodeIdx % newlineByte) && newlineByte) pBase64[encodeIdx++] = '\n';
		pBase64[encodeIdx++] = encTable[(triple >> 1 * 6) & 0x3F];
		if (!(encodeIdx % newlineByte) && newlineByte) pBase64[encodeIdx++] = '\n';
		pBase64[encodeIdx++] = encTable[(triple >> 0 * 6) & 0x3F];
	}
	// Add the padding to finish the encoding
	// NOTE: If padding is required, the last couple 'A' characters of pBase64 may need to be '='
	size_t padRemain = lenData % 3;
	size_t padBytes = (padRemain == 0) ? 0 : 3 - padRemain;
	for (size_t i = 0; i < padBytes; i++)
	{
		// Change character from 'A' to '=' >>> If the character is not'A', leave it alone
		pBase64[encodeIdx - 1 - i] = (pBase64[encodeIdx - 1 - i] == 'A') ? '=' : pBase64[encodeIdx - 1 - i];
	}

	// Add a newline at the end (increment index to account for null terminator to string)
	if (newlineByte) pBase64[encodeIdx++] = '\n';

	// Set the final length of the encoded data
	*pLenBase64 = encodeIdx;

	return VLT_OK;
}

/**
 * \brief Write text to a file.
 * \param[in]		pData			Pointer to the text data to write
 * \param[in]		lenData			Length of the encoded data to write
 * \param[in]		pRootFilename	Root Name the file 
 * \param[in]		pExt			Extension of the file 
 * \return		VLT_OK on success otherwise an error code
*/
VLT_STS VltWriteText(VLT_U8* pData, VLT_U8* sRootFilename, VLT_U8* sExt)
{
	unsigned short usActualSW = 0;

	// Check input parameters
	if (pData == NULL || sRootFilename == NULL || sExt == NULL)
		CloseAndExit(usActualSW, "Bad input parameters for VltGetRootFilename()");

	// Set the root filename 
	char sFilename[100] = { 0 };
	size_t lenExt = strlen((const char*)sExt);
	size_t lenRoot = strlen((const char*)sRootFilename);
	memcpy(sFilename, sRootFilename, lenRoot);

	// Define the file pointer
	FILE* pFile = NULL;

#ifdef _WIN32
	if (lenExt > 0)
	{
		strcat_s(sFilename, 100, ".");
		strcat_s(sFilename, 100, (const char*)sExt);
	}
	int csrerr = 0;
	csrerr = fopen_s(&pFile, (const char*)sFilename, "w");

	if (pFile == NULL)
	{
		printf("Error opening file!\n");
		exit(1);
	}
	csrerr = fprintf_s(pFile, "%s", pData);
	fclose(pFile);
#else
	if (lenExt > 0)
	{
		strcat(sFilename, ".");
		strcat(sFilename, sExt);
	}
	pFile = fopen(sFilename, "w");

	// test for files not existing.
	if (pFile == NULL)
	{
		printf("Error opening file!\n");
		exit(1);
	}
	// Write to file
	fprintf(pFile, "%s", pData); // write to file
	fclose(pFile);
	
	char cwd[PATH_MAX];
	if (getcwd(cwd, sizeof(cwd)) != NULL)
	{
		printf("Current working dir: %s\n", cwd);
		printf("Filename: %s\n", sFilename);
	}
	else
		printf("getcwd failed\n");
 
#endif
	printf("Filename: \"%s\"\n", sFilename);
	return VLT_OK;
}

/**
 * \brief Write data buffer to a file
 * \param[in]		pData			Pointer to the data to write
 * \param[in]		lenData			Length of the encoded data to write
 * \param[in]		pRootFilename	Root Name the file
 * \param[in]		pExt			Extension of the file
 * \return		VLT_OK on success otherwise an error code
*/
VLT_STS VltWriteDataBuffer(VLT_U8* pData, VLT_U16 lenData, VLT_U8* sRootFilename, VLT_U8* sExt)
{
	unsigned short usActualSW = 0;

	// Check input parameters
	if (pData == NULL || sRootFilename == NULL || sExt == NULL)
		CloseAndExit(usActualSW, "Bad input parameters for VltWriteDataBuffer()");

	// Build up the filename from the root
	char sFilename[100] = { 0 };
	size_t lenExt = strlen((const char*)sExt);
	size_t lenRoot = strlen((const char*)sRootFilename);
	memcpy(sFilename, sRootFilename, lenRoot);

	FILE* pFile = NULL;
#ifdef _WIN32
	if (lenExt > 0)
	{ 
		strcat_s(sFilename, 100, ".");
		strcat_s(sFilename, 100, (const char*)sExt);
	}
	size_t csrerr = fopen_s(&pFile, (const char*)sFilename, "wb");
	if (pFile == NULL)
	{
		printf("Error opening file!\n");
		exit(1);
	}
	csrerr = fwrite(pData, lenData, 1, pFile);
	fclose(pFile);
#else
	if (lenExt > 0)
	{
		strcat(sFilename, ".");
		strcat(sFilename, sExt);
	}
	pFile = fopen(sFilename, "wb");

	// test for files not existing.
	if (pFile == NULL)
	{
		printf("Error opening file!\n");
		exit(1);
	}
	// Write to file
	fprintf(pFile, "%s", pData); // write to file
#endif

	return VLT_OK;
}


/* Convert a buffer of hex bytes into ascii hex*/
VLT_STS GetHexText(VLT_PU8 pData, VLT_U16 lenData, VLT_U8* pHexText, VLT_U16* pLenHexText)
{
	unsigned short usActualSW = 0;

	// Check input parameters
	if (pData == NULL || pHexText == NULL || pLenHexText == NULL)
		CloseAndExit(usActualSW, "Bad input parameters for GetHexText()");

	const unsigned char ucLineLength = 16;

	unsigned long numLines = (lenData%ucLineLength) ? lenData / ucLineLength + 1 : lenData / ucLineLength;
	unsigned long ctr = 0;
	unsigned long offset = 0;

	// Check the size of the output
	if (((3 * lenData) + numLines + 1) > *pLenHexText)
		CloseAndExit(usActualSW, "HexText buffer too small");

#ifdef _WIN32
	for (unsigned int line = 0; line < numLines; line++)
	{
		for (unsigned int j = 0; j < ucLineLength; j++, ctr++)
		{
			if (ctr >= lenData)
			{
				break;
			}
			// print each character
			sprintf_s((char* const)(pHexText + offset), 4, "%2.2X ", pData[ctr]);
			offset += 3;
		}
		// new line
		sprintf_s((char* const)(pHexText + offset++), 2, "\n");
	}
	sprintf_s((char* const)(pHexText + offset++), 2, "\n");
#else
	for (unsigned int line = 0; line < numLines; line++)
	{
		for (unsigned int j = 0; j < ucLineLength; j++, ctr++)
		{
			if (ctr >= lenData)
			{
				break;
			}
			// print each character
			sprintf(pHexText + offset, "%2.2X ", pData[ctr]);
			offset += 3;
		}
		// new line
		sprintf(pHexText + offset++, "\n");
	}
	sprintf(pHexText + offset++, "\n");
#endif
	*pLenHexText = (VLT_U16)offset;

	return VLT_OK;
}

// >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
// Base64 decode
// >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
static VLT_U8 decTable[256] = { 0 };
static VLT_U8 decodeValid = 0;
 
void BuildDecodeTable()
{
	if (decodeValid) return;

	// Use the encoding table definition to build the decoding table
	for (int i = 0; i < 64; i++)
		decTable[(unsigned char)encTable[i]] = (VLT_U8)i;

	decodeValid = TRUE;
}

VLT_STS Base64Decode(VLT_U8* pBase64, VLT_U16 lenBase64, VLT_U8* pData, VLT_U16* pLenData)
{
	unsigned short usActualSW = 0;

	// Check input parameters
	if (pData == NULL || pLenData == NULL || pBase64 == NULL)
		CloseAndExit(usActualSW, "Bad input parameters for Base64Encode()");

	// Only decode if the length of the encoded data is a multiple of 4
	if (lenBase64 % 4 != 0)
		CloseAndExit(usActualSW, "Bad input buffer size for Base64Encode()");

	// Verify output size
	VLT_U16 lenOut = lenBase64 / 4 * 3;
	if (lenOut > *pLenData)
		CloseAndExit(usActualSW, "Decode Data Buffer too Small");

	// Build the decoding table if necessary
	if (!decodeValid) BuildDecodeTable();

	// Adjust the output length based on the number of pad characters
	if (pBase64[lenBase64 - 1] == '=') lenOut--;
	if (pBase64[lenBase64 - 2] == '=') lenOut--;

	for (int i = 0, j = 0; i < lenBase64;)
	{

		VLT_U32 sextet_a = pBase64[i] == '=' ? 0 & i++ : decTable[pBase64[i++]];
		VLT_U32 sextet_b = pBase64[i] == '=' ? 0 & i++ : decTable[pBase64[i++]];
		VLT_U32 sextet_c = pBase64[i] == '=' ? 0 & i++ : decTable[pBase64[i++]];
		VLT_U32 sextet_d = pBase64[i] == '=' ? 0 & i++ : decTable[pBase64[i++]];

		VLT_U32 triple = (sextet_a << 3 * 6)
			+ (sextet_b << 2 * 6)
			+ (sextet_c << 1 * 6)
			+ (sextet_d << 0 * 6);

		if (j < lenOut) pData[j++] = (triple >> 2 * 8) & 0xFF;
		if (j < lenOut) pData[j++] = (triple >> 1 * 8) & 0xFF;
		if (j < lenOut) pData[j++] = (triple >> 0 * 8) & 0xFF;
	}
	// Set the size of the decoded data
	*pLenData = lenOut;

	return VLT_OK;
}

