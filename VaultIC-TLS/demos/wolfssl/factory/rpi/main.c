/**
* @file	   main.c
*
* @note    THIS PRODUCT IS SUPPLIED FOR EVALUATION, TESTING AND/OR DEMONSTRATION PURPOSES ONLY.
*
* @note    <b>DISCLAIMER</b>
*
* @note    Copyright (C) 2021 Wisekey
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
* @brief  Defines a procedure for demonstrating how to personalise the VaultIC 100 for authentication in NON FIPS mode.
* @par Description:  NON FIPS mode offers the
* host the ability to define a custom ECDSA curve up to 303 bits.
* The NON FIPS mode also offers the ability to transition back to the creation
* state, wiping the keys and file system contents.
*/

#define DEF_VARS

#include "vaultic_common.h"
#include "vaultic_api.h"

#include "common.h"
#include <stdint.h>
#include <ctype.h>


static void GetManufPwd(unsigned char *buffer, unsigned char *length);
static VLT_COMM_MODE GetCommInterface(void);

void CheckStatus(int status);

extern int VaultIC_4XX_Digest(TEST_PARAMS_T * test_params);
extern int VaultIC_4XX_Signature_HMAC(TEST_PARAMS_T * test_params);
extern int VaultIC_4XX_Signature_GMAC(TEST_PARAMS_T * test_params);
extern int VaultIC_4XX_Encrypt_AES_CBC(TEST_PARAMS_T * test_params);
extern int VaultIC_4XX_Encrypt_AES_GCM(TEST_PARAMS_T * test_params);
extern int VaultIC_4XX_Encrypt_RSA(TEST_PARAMS_T * test_params);
extern int VaultIC_4XX_Signature_RSA(TEST_PARAMS_T * test_params);
extern int VaultIC_4XX_Signature_ECC(TEST_PARAMS_T * test_params);
extern int VaultIC_4XX_KeyDerivation_Concatenate(TEST_PARAMS_T * test_params);
extern int VaultIC_4XX_KeyWrapping_AES(TEST_PARAMS_T * test_params);
extern int VaultIC_4XX_KeyWrapping_RSA(TEST_PARAMS_T * test_params);
extern int VaultIC_4XX_Reinitialize(TEST_PARAMS_T * test_params);
extern int VaultIC_4XX_NCCoE_CSR(TEST_PARAMS_T * test_params);
#define RUN_LOOP 1

#if defined(USE_TWI) && defined(TWI_TRACE_ERRORS)
extern uint32_t twi_total_err_cnt_tx;
extern uint32_t twi_total_err_cnt_rx;
#endif

#if defined (USE_SPI) && defined (SPI_TRACE_ERRORS)
extern uint32_t spi_total_err_cnt_tx;
extern uint32_t spi_total_err_cnt_rx;
#endif

//#define MANUF_PWD "\x??\x??\x??\x??\x??\x??\x??\x??"

int main(void)

{
	TEST_PARAMS_T testParams;

	//
	// Choose Communication Interface
	testParams.commsParams.enCommsProtocol = GetCommInterface();

	//
    // Configure Communication parameters
	switch (testParams.commsParams.enCommsProtocol)
	{
#ifdef USE_TWI
		case VLT_TWI_COMMS:
			testParams.commsParams.VltTwiParams.u8Address = VLT_TWI_ADDRESS;
			testParams.commsParams.VltTwiParams.u16BitRate = VLT_TWI_BITRATE;	/* in kbits */;
		break;
#endif

#ifdef USE_SPI
		case VLT_SPI_COMMS:
		    testParams.commsParams.enCommsProtocol = VLT_SPI_COMMS;
		    testParams.commsParams.VltSpiParams.u16BitRate = VLT_SPI_BITRATE;	/* in kbits */
		break;
#endif
	}

    testParams.commsParams.VltBlockProtocolParams.enCheckSumMode = BLK_PTCL_CHECKSUM_SUM8;
    testParams.commsParams.VltBlockProtocolParams.u16msSelfTestDelay = VLT_SELF_TEST_WAIT_TIME; 	// in ms - time required for vaultic to complete its self tests
    testParams.commsParams.VltBlockProtocolParams.u32msTimeout = VLT_APDU_TIME_OUT;        			// in ms - max time required by vaultic to return a response to an APDU command

   //
   // Get manufacturer password
    testParams.u8ManufPasswordLength = sizeof(testParams.au8ManufPassword);
    GetManufPwd(testParams.au8ManufPassword, &testParams.u8ManufPasswordLength);

    //
    // Run Tests
	for (int loop=1;loop<=RUN_LOOP;loop++) {

		printf("\n<<<<<<<<<<<<<<<<<<<<<< RUN %d/%d >>>>>>>>>>>>>>>>>>>>>>\n",loop,RUN_LOOP);

		CheckStatus(VaultIC_4XX_NCCoE_CSR(&testParams));
		//CheckStatus(VaultIC_4XX_Digest(&testParams));
		//CheckStatus(VaultIC_4XX_Signature_HMAC(&testParams));
		//CheckStatus(VaultIC_4XX_Signature_GMAC(&testParams));
		//CheckStatus(VaultIC_4XX_Encrypt_AES_CBC(&testParams));
		//CheckStatus(VaultIC_4XX_Encrypt_AES_GCM(&testParams));
		//CheckStatus(VaultIC_4XX_Encrypt_RSA(&testParams));
		//CheckStatus(VaultIC_4XX_Signature_RSA(&testParams));
		//CheckStatus(VaultIC_4XX_Signature_ECC(&testParams));
		//CheckStatus(VaultIC_4XX_KeyDerivation_Concatenate(&testParams));
		//CheckStatus(VaultIC_4XX_KeyWrapping_AES(&testParams));
		//CheckStatus(VaultIC_4XX_KeyWrapping_RSA(&testParams));
		//CheckStatus(VaultIC_4XX_Reinitialize(&testParams));

#if defined(USE_TWI) && defined (TWI_TRACE_ERRORS)
		if (testParams.commsParams.enCommsProtocol == VLT_TWI_COMMS)
		{
			printf("twi_total_err_cnt_tx: %d\n",twi_total_err_cnt_tx);
			printf("twi_total_err_cnt_rx: %d\n",twi_total_err_cnt_rx);
		}
#endif
#if defined(USE_SPI) && defined (SPI_TRACE_ERRORS)
		if (testParams.commsParams.enCommsProtocol == VLT_SPI_COMMS)
		{
			printf("spi_total_err_cnt_tx: %d\n",spi_total_err_cnt_tx);
			printf("spi_total_err_cnt_rx: %d\n",spi_total_err_cnt_rx);
		}
#endif
    }

	printf("\n*** End of tests ***\n");
	return EXIT_SUCCESS;

}

void CheckStatus(int status)
{
	if(status != VLT_OK)
	{
		printf("[FAIL] Tests aborted\n");
		exit( EXIT_FAILURE);
	}
	else printf("[SUCCESS]\n");
}

#ifndef MANUF_PWD
static void GetManufPwd(unsigned char *pu8Pwd, unsigned char *pu8PwdLen)
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
static void GetManufPwd(unsigned char *pu8Pwd, unsigned char *pu8PwdLen)
{
	*pu8PwdLen =sizeof(MANUF_PWD)-1;
	memcpy(pu8Pwd,MANUF_PWD,*pu8PwdLen);
}
#endif

static VLT_COMM_MODE GetCommInterface(void)
{
	int comm = -1;

#if defined(USE_SPI) && defined (USE_TWI)
	printf("\n\n");
	printf("Please select communication interface \n");
#ifdef USE_SPI
	printf(" [1] : SPI interface \n");
#endif
#ifdef USE_TWI
	printf(" [2] : I2C/TWI interface \n");
#endif

	while (comm == -1)
	{
		// wait for character
		char c = getchar();

	#ifdef USE_SPI
		if (tolower(c) == '1') comm = VLT_SPI_COMMS;
	#endif

	#ifdef USE_TWI
		if (tolower(c) == '2') comm = VLT_TWI_COMMS;
	#endif
	}
#else
	#ifdef USE_SPI
	comm = VLT_SPI_COMMS;
	#endif

	#ifdef USE_TWI
	comm = VLT_TWI_COMMS;
	#endif
#endif

#if defined(USE_SPI)
	if (comm == VLT_SPI_COMMS) printf ("\nUsing SPI interface \n");
#endif

#if defined(USE_TWI)
	if (comm == VLT_TWI_COMMS) printf ("\nUsing I2C/TWI interface \n");
#endif
	return (VLT_COMM_MODE) comm;
}

VLT_STS GetTestDataValues(VLT_ECC_ID curveId, TEST_DATA * testData)
{
    switch (curveId)
    {
#if (VLT_ENABLE_ECDSA_B163 == VLT_ENABLE)
    	case VLT_ECC_ID_B163:
			testData->pu8_Host_D = auc_Host_D_B163;
			testData->pu8_Host_Qx = auc_Host_Qx_B163;
			testData->pu8_Host_Qy = auc_Host_Qy_B163;

			testData->pu8_Device_D = auc_Device_D_B163;
			testData->pu8_Device_Qx = auc_Device_Qx_B163;
			testData->pu8_Device_Qy = auc_Device_Qy_B163;
			testData->pu8_CurveName = auc_CurveName_B163;
        break;
#endif

    	default:
    		return VLT_FAIL;
    }

    return VLT_OK;
}






