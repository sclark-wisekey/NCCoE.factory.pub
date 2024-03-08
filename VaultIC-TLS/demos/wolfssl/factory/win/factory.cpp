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
* @brief  Demo code that generates a P256 key pair and constructs a CSR
*
*/

#include "wisekey_Ines_Agent.h"
#include "wisekey_Crypto_Tools.h"
#include "vaultic_common.h"
#include "vaultic_api.h"
#include "common.h"

// Function prototype to generate CSR based on p256 key pair generated in VaultIC
extern "C" int VaultIC_Factory_CSR(TEST_PARAMS_T * testParams, config_values_t config);

// Manufacturer password for VaultIC
unsigned char pwd[8] = { 0x58, 0x6e, 0x54, 0x79, 0x32, 0x34, 0x69, 0x6e };

#define WIN_CONFIG_DIR "../../VaultIC-TLS/demos/wolfssl/factory/data/inesconfig.win.ini"


#ifdef _WIN32
int main(int argc, char** argv)
#else
int win_main(int argc, char** argv)
#endif
{
	VLT_STS status = VLT_FAIL;
	TEST_PARAMS_T testParams;

	//// We don't need the manufacturer password from the command line since it is defined in code
	//string szManuf = GetCommandLineStringParameter(argc, argv, "-pwd");
	// Set the manufacturer password into the structure
	memcpy(testParams.au8ManufPassword, pwd, sizeof(pwd));
	testParams.u8ManufPasswordLength = sizeof(pwd);

	//string szInterface = GetCommandLineStringParameter(argc, argv, "-it");
	string szInterface = "40";

	DisplayLibraryInformation();

	if (VLT_OK != (status = InitializeReader(strtoul((const char*)szInterface.c_str(), NULL, 10), &testParams.commsParams)))
	{
		CloseAndExit(status, "No reader connected");
	}

	//---------------------------------------------------------------------
	// Call INeS to issue the certificate
	// INeS Issue Certificate Demo
	//---------------------------------------------------------------------
	// Extract the data from the config file
	config_values_t config;
	initConfigFile(&config);
	parseConfigFile(WIN_CONFIG_DIR, &config);


	if (verifyConfigStruc(CONFIG_FILE_INES, &config) < 0)
	{
		wkey_log(LOG_ERROR, "Invalid INES config provided");
		rebootEsp();
	}
	//---------------------------------------------------------------------
	// Execute the example code
	//---------------------------------------------------------------------
	if (VLT_OK != VaultIC_Factory_CSR(&testParams, config))
		wkey_log(LOG_ERROR, "Generate CSR failed");

	int protocol = API_REST;

	int inesStatus = inesDemo_IssueCert(config, protocol);

	if (inesStatus != 0)
		wkey_log(LOG_ERROR, "Ines Agent Malfunction, please see previous error");


	freeConfigStruct(&config);
}

