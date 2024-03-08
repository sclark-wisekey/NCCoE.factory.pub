/**
* @file	   common.h
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
* @brief  Includes for common source code for all demos code
*
*/

#ifndef __VAULTIC_API__DEMOS_COMMON__
#define __VAULTIC_API__DEMOS_COMMON__

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifdef __cplusplus
#include <iostream>
#include <iomanip>
#include <sstream>

using namespace std;
#define SUPPORTED( flags, value )   static_cast<bool>(( flags & value ) == value )
#endif

#if (VLT_ENABLE_ECDSA_B163 == VLT_ENABLE)
#include "test_data/B163.h"
#endif
#if (VLT_ENABLE_ECDSA_B233 == VLT_ENABLE)
#include "test_data/B233.h"
#endif
#if (VLT_ENABLE_ECDSA_B283 == VLT_ENABLE)
#include "test_data/B283.h"
#endif
#if (VLT_ENABLE_ECDSA_B409 == VLT_ENABLE)
#include "test_data/B409.h"
#endif
#if (VLT_ENABLE_ECDSA_B571 == VLT_ENABLE)
#include "test_data/B571.h"
#endif
#if (VLT_ENABLE_ECDSA_K163 == VLT_ENABLE)
#include "test_data/K163.h"
#endif
#if (VLT_ENABLE_ECDSA_K233 == VLT_ENABLE)
#include "test_data/K233.h"
#endif
#if (VLT_ENABLE_ECDSA_K283 == VLT_ENABLE)
#include "test_data/K283.h"
#endif
#if (VLT_ENABLE_ECDSA_K409 == VLT_ENABLE)
#include "test_data/K409.h"
#endif
#if (VLT_ENABLE_ECDSA_K571 == VLT_ENABLE)
#include "test_data/K571.h"
#endif
#if (VLT_ENABLE_ECDSA_P192 == VLT_ENABLE)
#include "test_data/P192.h"
#endif
#if (VLT_ENABLE_ECDSA_P224 == VLT_ENABLE)
#include "test_data/P224.h"
#endif
#if (VLT_ENABLE_ECDSA_P256 == VLT_ENABLE)
#include "test_data/P256.h"
#endif
#if (VLT_ENABLE_ECDSA_P384 == VLT_ENABLE)
#include "test_data/P384.h"
#endif
#if (VLT_ENABLE_ECDSA_P521 == VLT_ENABLE)
#include "test_data/P521.h"
#endif

#if( VLT_PLATFORM == VLT_WINDOWS )
    #include <tchar.h>
    #include "vaultic_lib.h"
#if(VLT_ENABLE_AARDVARK == VLT_ENABLE )
#include "aardvark.h"
#endif
#endif

//
// Defines Used for setting up communication parameters.
#define VLT_TWI_ADDRESS                     0x5F
#define VLT_TWI_BITRATE                     100		/* in kbits */
#define VLT_SPI_BITRATE                     2000	/* in kbits */

#define VLT_APDU_TIME_OUT                   5000	// in ms - max time required by vaultic to return a response to an APDU command
#define VLT_SELF_TEST_WAIT_TIME             5000	// in ms - time required for vaultic to complete its self tests

//
// Defines Used for setting up array lengths and variables.
#define	INITIAL_USER_PIN					(const VLT_U8*)"12345678"
#define INITIAL_USER_PIN_LEN				(VLT_U8)8
#define USER_PIN_ID							VLT_USER0
#define BUF_LEN_MAX							16000


/*******************************************************
 Error Codes:
*******************************************************/
#if( VLT_PLATFORM == VLT_WINDOWS )
#define VLT_FIND_DEVS_MALLOC_FAIL			-10
#define VLT_MALFORMED_XML_PCSC_INTFC		-13 
#define VLT_MALFORMED_XML_PCSC_PERIPH		-14
#define VLT_MALFORMED_XML_WISEBOARD_INTFC	-15
#define VLT_MALFORMED_XML_WISEBOARD_PERIPH	-16 
#define VLT_MALFORMED_XML_AARDVARK_INTFC	-17
#define VLT_MALFORMED_XML_AARDVARK_PERIPH	-18 
#define VLT_NO_AARDVARK_CONNECTED			-19
#define VLT_NO_READER_CONNECTED				-20
#define VLT_INTF_AVAILABILITY_FAILED    	-24
#endif



#define CloseAndExit(status,exitMessage)		{ \
	printf("%s\n",exitMessage); \
	if (VLT_OK != status) printf("*** Error status: %04X\n", status);\
    VltApiClose(); \
	return( status ); }	


// Test values
typedef struct {
    // Host Keypair
    VLT_PU8 pu8_Host_D; // Private key
    VLT_PU8 pu8_Host_Qx; // Public key
    VLT_PU8 pu8_Host_Qy; // Public key

    //Device Keypair
    VLT_PU8 pu8_Device_D; // Private key
    VLT_PU8 pu8_Device_Qx; // Public key
    VLT_PU8 pu8_Device_Qy; // Public key

    //Curve Name
    VLT_PU8 pu8_CurveName;
} TEST_DATA;

typedef struct {
    VLT_U8 au8ManufPassword[32];
    VLT_U8 u8ManufPasswordLength;
    VLT_INIT_COMMS_PARAMS commsParams;
    TEST_DATA testData;
} TEST_PARAMS_T;

#ifdef __cplusplus
extern "C" 
#endif
VLT_STS GetTestDataValues(VLT_ECC_ID curveId, TEST_DATA * pTestData);

#if( VLT_PLATFORM == VLT_WINDOWS )
//Functions
VLT_STS SelectReader(long prefInterface,VLT_INIT_COMMS_PARAMS *commsParams);
VLT_STS DisplayLibraryInformation();

#ifdef __cplusplus
string GetCommandLineStringParameter(int argc, char** argv, const char* paramName);
VLT_STS GetManufPassword(string szPassword, VLT_PU8 pmanufpwd, VLT_PU8 pu8pwdLen);
VLT_STS InitializeReader(long selected,VLT_INIT_COMMS_PARAMS *pcommsParams);
VLT_STS GetI2CAddress(string szI2cAddress);
 void HexStringToByteArray(std::string psz, unsigned char pb[]);
#endif

#endif

#endif //__VAULTIC_API__DEMOS_COMMON__
