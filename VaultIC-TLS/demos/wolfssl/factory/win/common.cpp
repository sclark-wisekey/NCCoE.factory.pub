/**
* @file	   common.cpp
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
* @brief   common source code for all demos code
*
*/

#define DEF_VARS
#include "vaultic_common.h"
#include "vaultic_api.h"
#include "common.h"
#include "vaultic_lib.h"
#include "stdio.h"
#include "conio.h"

VLT_U8 i2cAddress = VLT_TWI_ADDRESS;

#if( VLT_PLATFORM == VLT_WINDOWS )
#pragma warning(disable : 4127)
#pragma warning(disable : 4245)
#endif

#if(VLT_ENABLE_ISO7816 == VLT_ENABLE )
extern "C" VLT_PCSC_PARAMS VltPcscInitParams;
#endif


string GetCommandLineStringParameter(int argc, char** argv, const char* paramName)
{
    for (int pos = 0; pos < argc; pos++)
    {
        string currentParamValue = string(argv[pos]);
        size_t idx = currentParamValue.find_first_of("=");
        string currentParamName = currentParamValue.substr(0, currentParamValue.find_first_of("="));

        if (memcmp(paramName, currentParamName.c_str(), strlen(paramName)) == 0)
        {
            return currentParamValue.substr(idx + 1);
        }
    }
    return "";
}

VLT_STS GetCommandLineParameter(int argc, char** argv, const char* paramName, unsigned char* paramValue)
{
    for (int pos = 0; pos < argc; pos++)
    {
        string currentParamValue = string(argv[pos]);
        size_t idx = currentParamValue.find_first_of("=");
        string currentParamName = currentParamValue.substr(0, currentParamValue.find_first_of("="));

        if (memcmp(paramName, currentParamName.c_str(), strlen(paramName)) == 0)
        {
            string currentParam = currentParamValue.substr(idx + 1);
            HexStringToByteArray(currentParam, paramValue);
            return VLT_OK;
        }
    }
    return VLT_FAIL;
}

VLT_STS GetManufPassword(string szPassword, VLT_PU8 pmanufpwd, VLT_PU8 pu8pwdLen)
{
    unsigned char ucMinPasswordLength = 2*4;
    unsigned char ucMaxPasswordLength = 2*32;
    
    if ((szPassword.length() == 0) || (tolower(szPassword[0])=='x'))
    {
        char key_entered = FALSE;
        do {
            szPassword = "";
            printf("Please enter Manufacturer password (hex bytes) \n");

            int i;
            for (i = 0; i < ucMaxPasswordLength; i++) {
                int c = _getch();
                if (c == '\r')
                {
                    if (szPassword.length() < ucMinPasswordLength) {
                        printf("\n ERROR: please ensure the manufacturer's password is between 4 bytes and 32 bytes\n\n");;

                    }
                    else {
                        key_entered = TRUE;
                    }
                    break;
                }

                if (!(isdigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
                    printf("\nERROR: please enter hex values only \n\n");
                    break;
                }
                printf("%c",c);
                szPassword += (char) c;
            }

            if (i == ucMaxPasswordLength) key_entered = TRUE;
        } while (key_entered == FALSE);
    }

    // Check the supplied password is a valid length.
    //
    if (szPassword.length() < ucMinPasswordLength || szPassword.length() > ucMaxPasswordLength)
    {
        cout << "Please ensure the manufacturer's password is between 4 bytes and 32 bytes" << endl;
        exit(1);
    }

    HexStringToByteArray(szPassword,pmanufpwd);
    printf("\n");
    *pu8pwdLen = (VLT_U8) (szPassword.length() / 2);

    return VLT_OK;
}

VLT_STS GetI2CAddress(string szI2cAddress)
{
    if (szI2cAddress.length() == 0)
    {
        i2cAddress = VLT_TWI_ADDRESS;
    }
    else
    {
        HexStringToByteArray(szI2cAddress, &i2cAddress);
    }
    return VLT_OK;
}

extern "C" VLT_STS GetTestDataValues(VLT_ECC_ID curveId, TEST_DATA * testData)
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

#if (VLT_ENABLE_ECDSA_B233 == VLT_ENABLE)
    case VLT_ECC_ID_B233:
        testData->pu8_Host_D = auc_Host_D_B233;
        testData->pu8_Host_Qx = auc_Host_Qx_B233;
        testData->pu8_Host_Qy = auc_Host_Qy_B233;

        testData->pu8_Device_D = auc_Device_D_B233;
        testData->pu8_Device_Qx = auc_Device_Qx_B233;
        testData->pu8_Device_Qy = auc_Device_Qy_B233;
        testData->pu8_CurveName = auc_CurveName_B233;
        break;
#endif

#if (VLT_ENABLE_ECDSA_B283 == VLT_ENABLE)
    case VLT_ECC_ID_B283:
        testData->pu8_Host_D = auc_Host_D_B283;
        testData->pu8_Host_Qx = auc_Host_Qx_B283;
        testData->pu8_Host_Qy = auc_Host_Qy_B283;

        testData->pu8_Device_D = auc_Device_D_B283;
        testData->pu8_Device_Qx = auc_Device_Qx_B283;
        testData->pu8_Device_Qy = auc_Device_Qy_B283;
        testData->pu8_CurveName = auc_CurveName_B283;
        break;
#endif

#if (VLT_ENABLE_ECDSA_B409 == VLT_ENABLE)
    case VLT_ECC_ID_B409:
        testData->pu8_Host_D = auc_Host_D_B409;
        testData->pu8_Host_Qx = auc_Host_Qx_B409;
        testData->pu8_Host_Qy = auc_Host_Qy_B409;

        testData->pu8_Device_D = auc_Device_D_B409;
        testData->pu8_Device_Qx = auc_Device_Qx_B409;
        testData->pu8_Device_Qy = auc_Device_Qy_B409;
        testData->pu8_CurveName = auc_CurveName_B409;
        break;
#endif

#if (VLT_ENABLE_ECDSA_B571 == VLT_ENABLE)
    case VLT_ECC_ID_B571:
        testData->pu8_Host_D = auc_Host_D_B571;
        testData->pu8_Host_Qx = auc_Host_Qx_B571;
        testData->pu8_Host_Qy = auc_Host_Qy_B571;

        testData->pu8_Device_D = auc_Device_D_B571;
        testData->pu8_Device_Qx = auc_Device_Qx_B571;
        testData->pu8_Device_Qy = auc_Device_Qy_B571;
        testData->pu8_CurveName = auc_CurveName_B571;
        break;
#endif

#if (VLT_ENABLE_ECDSA_K163 == VLT_ENABLE)
    case VLT_ECC_ID_K163:
        testData->pu8_Host_D = auc_Host_D_K163;
        testData->pu8_Host_Qx = auc_Host_Qx_K163;
        testData->pu8_Host_Qy = auc_Host_Qy_K163;

        testData->pu8_Device_D = auc_Device_D_K163;
        testData->pu8_Device_Qx = auc_Device_Qx_K163;
        testData->pu8_Device_Qy = auc_Device_Qy_K163;
        testData->pu8_CurveName = auc_CurveName_K163;
        break;
#endif

#if (VLT_ENABLE_ECDSA_K233 == VLT_ENABLE)
    case VLT_ECC_ID_K233:
        testData->pu8_Host_D = auc_Host_D_K233;
        testData->pu8_Host_Qx = auc_Host_Qx_K233;
        testData->pu8_Host_Qy = auc_Host_Qy_K233;

        testData->pu8_Device_D = auc_Device_D_K233;
        testData->pu8_Device_Qx = auc_Device_Qx_K233;
        testData->pu8_Device_Qy = auc_Device_Qy_K233;
        testData->pu8_CurveName = auc_CurveName_K233;
        break;
#endif

#if (VLT_ENABLE_ECDSA_K283 == VLT_ENABLE)
    case VLT_ECC_ID_K283:
        testData->pu8_Host_D = auc_Host_D_K283;
        testData->pu8_Host_Qx = auc_Host_Qx_K283;
        testData->pu8_Host_Qy = auc_Host_Qy_K283;

        testData->pu8_Device_D = auc_Device_D_K283;
        testData->pu8_Device_Qx = auc_Device_Qx_K283;
        testData->pu8_Device_Qy = auc_Device_Qy_K283;
        testData->pu8_CurveName = auc_CurveName_K283;
        break;
#endif

#if (VLT_ENABLE_ECDSA_K409 == VLT_ENABLE)
    case VLT_ECC_ID_K409:
        testData->pu8_Host_D = auc_Host_D_K409;
        testData->pu8_Host_Qx = auc_Host_Qx_K409;
        testData->pu8_Host_Qy = auc_Host_Qy_K409;

        testData->pu8_Device_D = auc_Device_D_K409;
        testData->pu8_Device_Qx = auc_Device_Qx_K409;
        testData->pu8_Device_Qy = auc_Device_Qy_K409;
        testData->pu8_CurveName = auc_CurveName_K409;
        break;
#endif

#if (VLT_ENABLE_ECDSA_K571 == VLT_ENABLE)
    case VLT_ECC_ID_K571:
        testData->pu8_Host_D = auc_Host_D_K571;
        testData->pu8_Host_Qx = auc_Host_Qx_K571;
        testData->pu8_Host_Qy = auc_Host_Qy_K571;

        testData->pu8_Device_D = auc_Device_D_K571;
        testData->pu8_Device_Qx = auc_Device_Qx_K571;
        testData->pu8_Device_Qy = auc_Device_Qy_K571;
        testData->pu8_CurveName = auc_CurveName_K571;
        break;
#endif

#if (VLT_ENABLE_ECDSA_P192 == VLT_ENABLE)
    case VLT_ECC_ID_P192:
        testData->pu8_Host_D = auc_Host_D_P192;
        testData->pu8_Host_Qx = auc_Host_Qx_P192;
        testData->pu8_Host_Qy = auc_Host_Qy_P192;

        testData->pu8_Device_D = auc_Device_D_P192;
        testData->pu8_Device_Qx = auc_Device_Qx_P192;
        testData->pu8_Device_Qy = auc_Device_Qy_P192;
        testData->pu8_CurveName = auc_CurveName_P192;
        break;
#endif

#if (VLT_ENABLE_ECDSA_P224 == VLT_ENABLE)
    case VLT_ECC_ID_P224:
        testData->pu8_Host_D = auc_Host_D_P224;
        testData->pu8_Host_Qx = auc_Host_Qx_P224;
        testData->pu8_Host_Qy = auc_Host_Qy_P224;

        testData->pu8_Device_D = auc_Device_D_P224;
        testData->pu8_Device_Qx = auc_Device_Qx_P224;
        testData->pu8_Device_Qy = auc_Device_Qy_P224;
        testData->pu8_CurveName = auc_CurveName_P224;
        break;
#endif

#if (VLT_ENABLE_ECDSA_P256 == VLT_ENABLE)
    case VLT_ECC_ID_P256:
        testData->pu8_Host_D = auc_Host_D_P256;
        testData->pu8_Host_Qx = auc_Host_Qx_P256;
        testData->pu8_Host_Qy = auc_Host_Qy_P256;

        testData->pu8_Device_D = auc_Device_D_P256;
        testData->pu8_Device_Qx = auc_Device_Qx_P256;
        testData->pu8_Device_Qy = auc_Device_Qy_P256;
        testData->pu8_CurveName = auc_CurveName_P256;
        break;
#endif

#if (VLT_ENABLE_ECDSA_P384 == VLT_ENABLE)
    case VLT_ECC_ID_P384:
        testData->pu8_Host_D = auc_Host_D_P384;
        testData->pu8_Host_Qx = auc_Host_Qx_P384;
        testData->pu8_Host_Qy = auc_Host_Qy_P384;

        testData->pu8_Device_D = auc_Device_D_P384;
        testData->pu8_Device_Qx = auc_Device_Qx_P384;
        testData->pu8_Device_Qy = auc_Device_Qy_P384;
        testData->pu8_CurveName = auc_CurveName_P384;
        break;
#endif

#if (VLT_ENABLE_ECDSA_P521 == VLT_ENABLE)
    case VLT_ECC_ID_P521:
        testData->pu8_Host_D = auc_Host_D_P521;
        testData->pu8_Host_Qx = auc_Host_Qx_P521;
        testData->pu8_Host_Qy = auc_Host_Qy_P521;

        testData->pu8_Device_D = auc_Device_D_P521;
        testData->pu8_Device_Qx = auc_Device_Qx_P521;
        testData->pu8_Device_Qy = auc_Device_Qy_P521;
        testData->pu8_CurveName = auc_CurveName_P521;
        break;
#endif

    default: 
        return VLT_FAIL;
    }

    return VLT_OK;
}

VLT_STS InitializeReader(long selected,VLT_INIT_COMMS_PARAMS *pcommsParams)
{
    long lPrefferedInterface = 0;

    if (selected != 0xFF)
    {
        lPrefferedInterface = selected;
    }

#ifdef __EMBLINUX__ //These Values are defined for raspberry PI3 and to be used with bcm2835 driver
#ifdef USE_SPI
    pcommsParams->enCommsProtocol = VLT_SPI_COMMS;
    pcommsParams->VltSpiParams.u16BitRate = VLT_SPI_BITRATE;
    pcommsParams->VltBlockProtocolParams.enCheckSumMode = BLK_PTCL_CHECKSUM_SUM8;
    pcommsParams->VltBlockProtocolParams.u16msSelfTestDelay = VLT_SELF_TEST_WAIT_TIME;
#elif defined(USE_TWI) //Config for Raspberry PI3 BCM2835
    pcommsParams->enCommsProtocol = VLT_TWI_COMMS;
    pcommsParams->VltBlockProtocolParams.u32msTimeout = VLT_APDU_TIME_OUT;
    pcommsParams->VltTwiParams.u8Address = i2cAddress;
    pcommsParams->VltTwiParams.u16BitRate = VLT_TWI_BITRATE;
    pcommsParams->VltBlockProtocolParams.enCheckSumMode = BLK_PTCL_CHECKSUM_SUM8;
    pcommsParams->VltBlockProtocolParams.u16msSelfTestDelay = VLT_SELF_TEST_WAIT_TIME;
#elif defined(USE_ISO7816)
    return SelectReader(lPrefferedInterface,pcommsParams);
#else
    CloseAndExit(VLT_INTF_AVAILABILITY_FAILED,"No interface type available"); 
#endif
#else
    return SelectReader(lPrefferedInterface,pcommsParams);
#endif
}
    
 VLT_STS SelectReader(long prefInterface,VLT_INIT_COMMS_PARAMS *commsParams) {
    VLT_STS status = VLT_FAIL;
    string strXMLDevs;
    
    std::string strReaderName;
    //
    // Determine the size of the xml string that will be returned on the second call, 
    // set the stringSize parameter to zero and the string to NULL. On return the 
    // stringSize will be set to the actual number of characters of the XML string 
    // that contains the list of devices.
    //
    VLT_U32 stringSize = 0;
    if (VLT_OK != (status = VltFindDevices(&stringSize, NULL)))
        CloseAndExit( status, "Find device failed");

    //
    // Allocate enough memory to hold the xml string with the list of
    // devices.
    //
    VLT_PU8 pXmlString = (VLT_PU8) NULL;
    if (NULL == (pXmlString = (VLT_PU8)malloc(stringSize))) {
        CloseAndExit(VLT_FIND_DEVS_MALLOC_FAIL, "Memory allocation failed");
    }

    memset(pXmlString,0x00,stringSize);
    //
    // Now call the VltFindDevices again with all the appropriate parameters
    // On return the pXmlString will be filled with the device list.
    //
    if (VLT_OK != (status = VltFindDevices(&stringSize, pXmlString))) {
      FREE(pXmlString);

        CloseAndExit( status, "Find device failed (malformated XML)");
    } else {
        //
        // Assign the XML string to a standard string
        //
        strXMLDevs = string((const char*) pXmlString);
    }

    FREE(pXmlString);


    size_t startPos = 0;
    size_t endPos = 0;

    bool readerFound = false;

    unsigned char item = 0;
    long selection = 0;

    printf("\nList of detected interfaces:");
    printf("\n=====================================\n");
    

#if(VLT_ENABLE_BLE == VLT_ENABLE )
    //
    // Check if the XML string includes an entry for PC/SC readers
    //
    startPos = strXMLDevs.find("<interface type=\"ble\">");
    if (string::npos != startPos) {
        endPos = strXMLDevs.find("</interface>");
        if (string::npos == endPos)
            CloseAndExit(VLT_MALFORMED_XML_PCSC_INTFC, "Find device failed (malformated XML)");

        string strPCSC(strXMLDevs.substr(startPos, (endPos - startPos)));

        // Reset start pointer & item number
        startPos = 0;
        item = 0;

        do {
            //
            // It does so check for entries for a reader
            //
            startPos = strPCSC.find("<peripheral idx=", startPos);
            if (string::npos == startPos) {
                // No more reader in the list = end of loop
                break;
            }
            {
                //
                // Start of the reader name is after the opening tag
                //
                startPos += strlen("<peripheral idx=\"00\">");

                //
                // End position is at beginning of the closing tag
                //
                endPos = strPCSC.find("</peripheral>", startPos);
                if (string::npos == endPos)
                    CloseAndExit(VLT_MALFORMED_XML_PCSC_PERIPH, "Find device failed (malformated XML)");

                //
                // Get the reader name
                //
                strReaderName = strPCSC.substr(startPos, (endPos - startPos));

                // Display the reader name
                printf("    Interface #%d, Name = %s\n", item++ + INTERFACE_BLE, strReaderName.c_str());

                readerFound = true;
            }
        } while (true);
    }
#endif

#if(VLT_ENABLE_ISO7816 == VLT_ENABLE )  
    bool pcsc_readerFound = false;

    //
    // Check if there are any PC/SC readers connected
    ////

    // Check if the XML string includes an entry for PC/SC readers
    //
    startPos = strXMLDevs.find("<interface type=\"pcsc\">");
    if (string::npos != startPos) {
        endPos = strXMLDevs.find("</interface>");
        if (string::npos == endPos)
            CloseAndExit( VLT_MALFORMED_XML_PCSC_INTFC, "Find device failed (malformated XML)");

        string strPCSC(strXMLDevs.substr(startPos, (endPos - startPos)));

        // Reset start pointer & item number
        startPos = 0;
        item = 0;

        do {
            //
            // It does so check for entries for a reader
            //
            startPos = strPCSC.find("<peripheral idx=", startPos);
            if (string::npos == startPos) {
                // No more reader in the list = end of loop
                break;
            }
            {
                //
                // Start of the reader name is after the opening tag
                //
                startPos += strlen("<peripheral idx=\"00\">");

                //
                // End position is at beginning of the closing tag
                //
                endPos = strPCSC.find("</peripheral>", startPos);
                if (string::npos == endPos)
                    CloseAndExit( VLT_MALFORMED_XML_PCSC_PERIPH, "Find device failed (malformated XML)");

                //
                // Get the reader name
                //
                strReaderName = strPCSC.substr(startPos, (endPos - startPos));

                // Display the reader name
                printf("    Interface #%d: Name = %s\n", item++ + INTERFACE_PCSC, strReaderName.c_str());

                readerFound = true;
                pcsc_readerFound = true;
            }
        } while (true);
    }
#endif 

#if(VLT_ENABLE_AARDVARK == VLT_ENABLE )
    bool aardvark_readerFound = false;
    startPos = strXMLDevs.find("<interface type=\"aardvark\">");
    if (string::npos != startPos) {
        endPos = strXMLDevs.find("</interface>", startPos);
        if (string::npos == endPos)
            CloseAndExit(VLT_MALFORMED_XML_AARDVARK_INTFC, "Find device failed (malformated XML)");

        string strAardvark(strXMLDevs.substr(startPos, (endPos - startPos)));

        // Reset start pointer & item number
        startPos = 0;
        item = 0;

        do {
            //
            // It does so check for entries for a reader
            //
            startPos = strAardvark.find("<peripheral idx=", startPos);
            if (string::npos == startPos) {
                // No more reader in the list = end of loop
                break;
            }
            else {
                //
                // Start of the reader name is after the opening tag
                //
                startPos += strlen("<peripheral idx=\"00\">");

                //
                // End position is at beginning of the closing tag
                //
                endPos = strAardvark.find("</peripheral>", startPos);
                if (string::npos == endPos)
                    CloseAndExit(VLT_MALFORMED_XML_AARDVARK_PERIPH, "Find device failed (malformated XML)");

                //
                // Get the Aardwark serial number
                //
                strReaderName = strAardvark.substr(startPos, (endPos - startPos));

                // Display the reader name
#if (VLT_ENABLE_SPI == VLT_ENABLE)
                printf("    Interface #%d: Aardvark SPI Serial Number = %s\n", INTERFACE_AARDVARK_SPI + item, strReaderName.c_str());
#endif
#if (VLT_ENABLE_TWI== VLT_ENABLE)
                printf("    Interface #%d: Aardvark TWI Serial Number = %s\n", INTERFACE_AARDVARK_TWI + item++, strReaderName.c_str());
#endif

                readerFound = true;
                aardvark_readerFound = true;
            }
        } while (true);
    }
#endif

#if(VLT_ENABLE_WISEBOARD == VLT_ENABLE )
    bool wiseboard_readerFound = false;
    startPos = strXMLDevs.find("<interface type=\"wiseboard\">");
    if (string::npos != startPos) {
        endPos = strXMLDevs.find("</interface>", startPos);
        if (string::npos == endPos)
            CloseAndExit( VLT_MALFORMED_XML_WISEBOARD_INTFC, "Find device failed (malformated XML)");

        string strWiseboard(strXMLDevs.substr(startPos, (endPos - startPos)));

        // Reset start pointer & item number
        startPos = 0;
        item = 0;

        do {
            //
            // It does so check for entries for a reader
            //
            startPos = strWiseboard.find("<peripheral idx=", startPos);
            if (string::npos == startPos) {
                // No more reader in the list = end of loop
                break;
            }
            else {
                //
                // Start of the reader name is after the opening tag
                //
                startPos += strlen("<peripheral idx=\"00\">");

                //
                // End position is at beginning of the closing tag
                //
                endPos = strWiseboard.find("</peripheral>", startPos);
                if (string::npos == endPos)
                    CloseAndExit( VLT_MALFORMED_XML_WISEBOARD_PERIPH, "Find device failed (malformated XML)");

                strReaderName = strWiseboard.substr(startPos, (endPos - startPos));

                // Display the reader name
#ifdef USE_SPI
                printf("    Interface #%d; %s SPI\n", INTERFACE_WISEBOARD_SPI + item, strReaderName.c_str());
#endif
#ifdef USE_TWI
                printf("    Interface #%d; %s I2C\n", INTERFACE_WISEBOARD_I2C + item, strReaderName.c_str());
#endif
                readerFound = true;
                wiseboard_readerFound = true;

            }
        } while (true);
    }



#endif

    if (!readerFound) {
        CloseAndExit( VLT_NO_READER_CONNECTED, "No reader connected");
    }

    if (prefInterface ==0)
    {
    // If no preferred interface is provided
        // -> Prompt the user to select the communication interface
        printf("\nPlease enter the interface number to use, followed by ENTER: ");
#if (VLT_PLATFORM == VLT_WINDOWS)
        scanf_s("%02d", &selection);
#else
        scanf("%02d", &selection);
#endif
        getchar();
        printf("\n");
    }
    else
    {
        selection = prefInterface;
    }

    char pXmlData[30];

    unsigned char protocol = (unsigned char)((selection / 10) * 10);
    
    unsigned char idx = selection % 10;
#if (VLT_PLATFORM == VLT_WINDOWS)
    sprintf_s((char*) pXmlData,30, (const char*) "<peripheral idx=\"%02d\">", idx);
#else
    sprintf((char*) pXmlData, (const char*) "<peripheral idx=\"%02d\">", idx);
#endif

#if(VLT_ENABLE_ISO7816 == VLT_ENABLE )  
    VltPcscInitParams.pu8ReaderString = NULL;
#endif

    commsParams->VltInterface = (COMM_INTERFACE_T) protocol;

    switch (protocol) {

#if(VLT_ENABLE_BLE == VLT_ENABLE )
    case INTERFACE_BLE:
    {
        string strDeviceId;
        startPos = strXMLDevs.find("<interface type=\"ble\">");
        startPos = strXMLDevs.find(pXmlData, startPos);
        startPos += strlen(pXmlData);
        endPos = strXMLDevs.find("</peripheral>", startPos);

        //Extract BLE device ID

        // Get the reader name
        strReaderName = strXMLDevs.substr(startPos, (endPos - startPos));
        startPos = strReaderName.find("[") + 1;
        endPos = strReaderName.find("]", startPos);
        strDeviceId = strReaderName.substr(startPos, (endPos - startPos));
        
        if (strDeviceId.length() <= 12)
        {
            memset(commsParams->Params.VltBleInitParams.pu8DeviceID, 0x00, sizeof(commsParams->Params.VltBleInitParams.pu8DeviceID));
            memcpy(commsParams->Params.VltBleInitParams.pu8DeviceID, strDeviceId.c_str(), strDeviceId.length());
        }
        else
        {
            CloseAndExit(VLT_READER_NAME_TOO_LONG_CONNECTED, "Reader name is too long");
        }
        commsParams->enCommsProtocol = VLT_BLE_COMMS;
    }
        break;
#endif

#if(VLT_ENABLE_ISO7816 == VLT_ENABLE )  
        case INTERFACE_PCSC:
            if (pcsc_readerFound == false) CloseAndExit(VLT_NO_READER_CONNECTED, "No pcsc reader connected");
            startPos = strXMLDevs.find("<interface type=\"pcsc\">");
            startPos = strXMLDevs.find(pXmlData, startPos);
            startPos += strlen(pXmlData);
            endPos = strXMLDevs.find("</peripheral>", startPos);

            // Get the reader name
            strReaderName = strXMLDevs.substr(startPos, (endPos - startPos));
            VltPcscInitParams.hCard = 0;
            VltPcscInitParams.hContext = 0;
            VltPcscInitParams.u32Protocol = VLT_ISO_T0_OR_T1_COMMS;
            VltPcscInitParams.pu8ReaderString = (VLT_PU8)malloc(strReaderName.length()+1);
            memset(VltPcscInitParams.pu8ReaderString,0x00,strReaderName.length()+1);
            memcpy(VltPcscInitParams.pu8ReaderString,strReaderName.c_str(),strReaderName.length());
            commsParams->enCommsProtocol = VLT_ISO_T0_OR_T1_COMMS;
            break;
#endif
#if(VLT_ENABLE_WISEBOARD == VLT_ENABLE ) 
            
#if (VLT_ENABLE_TWI == VLT_ENABLE)
        case INTERFACE_WISEBOARD_I2C:
            if (wiseboard_readerFound == false) CloseAndExit(VLT_NO_READER_CONNECTED, "No wiseboard connected");
            startPos = strXMLDevs.find("<interface type=\"wiseboard\">");
            startPos = strXMLDevs.find(pXmlData, startPos);
            startPos += strlen(pXmlData);
            endPos = strXMLDevs.find("</peripheral>", startPos);

            // Get the reader name
            strReaderName = strXMLDevs.substr(startPos, (endPos - startPos));

            // Setup communications using TWI
            commsParams->enCommsProtocol = VLT_TWI_COMMS;
            commsParams->VltTwiParams.pu8WiseboardName = (VLT_PU8)malloc(strReaderName.length() + 1);
            memset(commsParams->VltTwiParams.pu8WiseboardName, 0x00, strReaderName.length() + 1);
            memcpy(commsParams->VltTwiParams.pu8WiseboardName, strReaderName.c_str(), strReaderName.length());

            commsParams->VltTwiParams.u8Address = i2cAddress;
            commsParams->VltTwiParams.u16BitRate = VLT_TWI_BITRATE;
            commsParams->VltBlockProtocolParams.enCheckSumMode = BLK_PTCL_CHECKSUM_SUM8;
            commsParams->VltBlockProtocolParams.u16msSelfTestDelay = VLT_SELF_TEST_WAIT_TIME;
            commsParams->VltBlockProtocolParams.u32msTimeout = VLT_APDU_TIME_OUT;

            printf("\nI2C configuration : %dKhz at address 0x%.2X \n\n", commsParams->VltTwiParams.u16BitRate, commsParams->VltTwiParams.u8Address);
            break;
#endif

#if (VLT_ENABLE_SPI == VLT_ENABLE)
        case INTERFACE_WISEBOARD_SPI:
            if (wiseboard_readerFound == false) CloseAndExit(VLT_NO_READER_CONNECTED, "No wiseboard connected");
            startPos = strXMLDevs.find("<interface type=\"wiseboard\">");
            startPos = strXMLDevs.find(pXmlData, startPos);
            startPos += strlen(pXmlData);
            endPos = strXMLDevs.find("</peripheral>", startPos);

            // Get the reader name
            strReaderName = strXMLDevs.substr(startPos, (endPos - startPos));

            // Setup communications using SPI
            commsParams->enCommsProtocol = VLT_SPI_COMMS;
            commsParams->VltSpiParams.pu8WiseboardName = (VLT_PU8)malloc(strReaderName.length() + 1);
            memset(commsParams->VltSpiParams.pu8WiseboardName, 0x00, strReaderName.length() + 1);
            memcpy(commsParams->VltSpiParams.pu8WiseboardName, strReaderName.c_str(), strReaderName.length());

            commsParams->VltSpiParams.u16BitRate = VLT_SPI_BITRATE;
            //commsParams->VltSpiParams.u32SerialNo = strtoul(strReaderName.c_str(), NULL, 10);
            //commsParams->VltBlockProtocolParams.enCheckSumMode = BLK_PTCL_CHECKSUM_SUM8;
            commsParams->VltBlockProtocolParams.u16msSelfTestDelay = VLT_SELF_TEST_WAIT_TIME;
            commsParams->VltBlockProtocolParams.u32msTimeout = VLT_APDU_TIME_OUT;

            printf("\nSPI configuration : %dKhz \n\n", commsParams->VltSpiParams.u16BitRate);            
            break;
#endif

#endif

#if(VLT_ENABLE_AARDVARK == VLT_ENABLE )  
#if ( VLT_ENABLE_TWI == VLT_ENABLE)
        case INTERFACE_AARDVARK_TWI:
            if (aardvark_readerFound == false) CloseAndExit(VLT_NO_READER_CONNECTED, "No aardvark connected");
            startPos = strXMLDevs.find("<interface type=\"aardvark\">");
            startPos = strXMLDevs.find(pXmlData, startPos);
            startPos += strlen(pXmlData);
            endPos = strXMLDevs.find("</peripheral>", startPos);

            // Get the reader name
            strReaderName = strXMLDevs.substr(startPos, (endPos - startPos));
            commsParams->VltTwiParams.u32SerialNo = strtoul(strReaderName.c_str(), NULL, 10);

            // Setup communications using TWI over Aarvark
            commsParams->enCommsProtocol = VLT_TWI_COMMS;

            commsParams->VltTwiParams.u8Address = i2cAddress;
            commsParams->VltTwiParams.u16BitRate = VLT_TWI_BITRATE;

            commsParams->VltBlockProtocolParams.enCheckSumMode = BLK_PTCL_CHECKSUM_SUM8;
            commsParams->VltBlockProtocolParams.u16msSelfTestDelay = VLT_SELF_TEST_WAIT_TIME;
            commsParams->VltBlockProtocolParams.u32msTimeout = VLT_APDU_TIME_OUT;

            printf("\nI2C configuration : %dKhz at address 0x%.2X \n\n", commsParams->VltTwiParams.u16BitRate, commsParams->VltTwiParams.u8Address);
            strReaderName = "Aardvark I2C " + strReaderName;
            break;
#endif
#if (VLT_ENABLE_SPI == VLT_ENABLE)
        case INTERFACE_AARDVARK_SPI:
            if (aardvark_readerFound == false) CloseAndExit(VLT_NO_READER_CONNECTED, "No aardvark connected");
            startPos = strXMLDevs.find("<interface type=\"aardvark\">");
            startPos = strXMLDevs.find(pXmlData, startPos);
            startPos += strlen(pXmlData);
            endPos = strXMLDevs.find("</peripheral>", startPos);

            // Get the reader name
            strReaderName = strXMLDevs.substr(startPos, (endPos - startPos));

            // Setup communications using SPI over Aarvark
            commsParams->enCommsProtocol = VLT_SPI_COMMS;
            commsParams->VltSpiParams.u8AdapterType = VLT_SPI_AARDVARK_ADAPTER;
            commsParams->VltSpiParams.u16BitRate = VLT_SPI_BITRATE;
            commsParams->VltSpiParams.u32SerialNo = strtoul(strReaderName.c_str(), NULL, 10);
            commsParams->VltBlockProtocolParams.enCheckSumMode = BLK_PTCL_CHECKSUM_SUM8;
            commsParams->VltBlockProtocolParams.u32msTimeout = VLT_APDU_TIME_OUT;

            //
            // Add a delay to allow self tests to run before establishing comms.
            //
            commsParams->VltBlockProtocolParams.u16msSelfTestDelay = VLT_SELF_TEST_WAIT_TIME;

            printf("\nSPI configuration : %dKhz \n\n", commsParams->VltSpiParams.u16BitRate);            
            strReaderName = "Aardvark SPI " + strReaderName;
            break;
#endif

#endif
        default:
            CloseAndExit( VLT_NO_READER_CONNECTED, "Invalid selection\n");
            }
    cout << "Using reader : " << strReaderName.c_str() << endl;
    return VLT_OK;
}
VLT_STS DisplayLibraryInformation()
{
    VLT_LIBRARY_INFO libInfo;
    VLT_STS status = VLT_FAIL;

    //
    // Determine the library capabilities and print those out in the 
    // standard output. 
    //
    if( VLT_OK != ( status = VltGetLibraryInfo( &libInfo ) ) )
    {
        return( status );
    }
    else
    {
        string chipname;
        switch (libInfo.fwCompatibilityVersionId)
        {
        case VAULTIC_405_1_X_X:
            chipname = "VaultIC 405";
            break;
        case VAULTIC_407_1_0_X:
            chipname = "VaultIC 407";
            break;
        case VAULTIC_420_1_2_X:
            chipname = "VaultIC 420";
            break;
        }


        cout << endl;
        cout << libInfo.pVersion <<endl;
        cout << "====================================" << endl;

        if (SUPPORTED(libInfo.capabilities, VLT_CPB_ENABLE_KEY_SECRET))
            cout << "    Put/Read Secret Key Support   " << endl;

        if (SUPPORTED(libInfo.capabilities, VLT_CPB_ENABLE_KEY_HOTP))
            cout << "    Put/Read HOTP Key Support  " << endl;

        if (SUPPORTED(libInfo.capabilities, VLT_CPB_ENABLE_KEY_TOTP))
            cout << "    Put/Read TOTP Key Support  " << endl;

        if (SUPPORTED(libInfo.capabilities, VLT_CPB_ENABLE_KEY_RSA))
            cout << "    Put/Read RSA Key Support  " << endl;
        
        if (SUPPORTED(libInfo.capabilities, VLT_CPB_ENABLE_KEY_DSA))
            cout << "    Put/Read DSA Key Support  " << endl;
            
        if (SUPPORTED(libInfo.capabilities, VLT_CPB_ENABLE_KEY_ECDSA))
            cout << "    Put/Read ECDSA Key Support  " << endl;
            
        if (SUPPORTED(libInfo.capabilities, VLT_CPB_ENABLE_CIPHER_TESTS))
            cout << "    Cipher Self Tests Support  " << endl;
            
        if (SUPPORTED(libInfo.capabilities, VLT_CPB_ENABLE_IDENTITY_AUTH))
            cout << "    Identity Authentication Service Support  " << endl;
        
        if (SUPPORTED(libInfo.capabilities, VLT_CPB_ENABLE_SCP02))
            cout << "    SCP02 Secure Channel Support  " << endl;
            
        if (SUPPORTED(libInfo.capabilities, VLT_CPB_ENABLE_SCP03))
            cout << "    SCP03 Secure Channel Support  " << endl;
        
        if (SUPPORTED(libInfo.capabilities, VLT_CPB_ENABLE_MS_AUTH))
            cout << "    Microsoft Minicard Driver Support  " << endl;
            
        if (SUPPORTED(libInfo.capabilities, VLT_CPB_ENABLE_TWI))
            cout << "    TWI Interface Support  " << endl;
            
        if (SUPPORTED(libInfo.capabilities, VLT_CPB_ENABLE_SPI))
            cout << "    SPI Interface Support  " << endl;
            
        if (SUPPORTED(libInfo.capabilities, VLT_CPB_ENABLE_ISO7816))
            cout << "    ISO7816 Protocol Support  " << endl;
            
        if (SUPPORTED(libInfo.capabilities, VLT_CPB_ENABLE_BLE))
            cout << "    BLE Interface Support  " << endl;
            
        if (SUPPORTED(libInfo.capabilities, VLT_CPB_ENABLE_CIPHER_AES))
            cout << "    AES(128, 192, 256) Support  " << endl;
            
        if (SUPPORTED(libInfo.capabilities, VLT_CPB_ENABLE_CIPHER_TDES))
            cout << "    TDES(EEE& EDE modes) Support  " << endl;
            
        if (SUPPORTED(libInfo.capabilities, VLT_CPB_ENABLE_CIPHER_DES))
            cout << "    DES Support  " << endl;
        
        if (SUPPORTED(libInfo.capabilities, VLT_CPB_ENABLE_FAST_CRC16CCIT))
            cout << "    Fast CRC16 CCIT Support  " << endl;
            
        if (SUPPORTED(libInfo.capabilities, VLT_CPB_ENABLE_KEY_WRAPPING))
            cout << "    Key Wrapping Service Support  " << endl;
            
        if (SUPPORTED(libInfo.capabilities, VLT_ENABLE_KEY_IDENTIFIER))
            cout << "    Put/Read Host/Device ID Key Support  " << endl;
            
        if (SUPPORTED(libInfo.capabilities, VLT_ENABLE_FILE_SYSTEM))
            cout << "    File System Service Support  " << endl;
            
        cout << "\nThis Library is compiled for " << chipname.c_str() << endl;

    }
    return VLT_OK;
}


void HexStringToByteArray(std::string psz, unsigned char pb[])
{
    char buf[4];
    buf[2] = 0;
    int idx =0;
    for(unsigned int i=0;i< psz.length();i=i+2)
    {
        buf[0] = (char)psz[i];
        buf[1] = (char)psz[i+1];
        pb[idx++] = (unsigned char)strtoul(buf, NULL, 16);
    }
}
