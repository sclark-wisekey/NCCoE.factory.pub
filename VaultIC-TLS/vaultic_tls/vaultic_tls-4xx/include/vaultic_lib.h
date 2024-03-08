/**
* @file	   vaultic_lib.h
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
* @defgroup VaultIcLib Vault IC Library
* 
* @brief VaultIC API as DLL.
* 
* @par Description:
*
* This file provides an interface to the VaultIC API in DLL form.
*/

/**@{*/

#ifndef VAULTIC_LIB_H
#define VAULTIC_LIB_H

#include "VaultIC_config.h"

#ifdef __cplusplus 
extern "C" 
{
#endif 

    /**
     * \struct _VltLibraryInfo
     *
     * \brief The VaultIC library information
     *
     * \par Description
     * The _VltLibraryInfo structure is used to return the properties of the VaultIC API Library.
     * Its members are:
     *
     * \li pVersion A pointer to a null terminated string of characters that denotes the version of the library.
     * \li capabilities A bitfield of the capabilities supported by the library build. Possible values are:

 *  - #VLT_CPB_ENABLE_KEY_SECRET    
 *  - #VLT_CPB_ENABLE_KEY_HOTP      
 *  - #VLT_CPB_ENABLE_KEY_TOTP      
 *  - #VLT_CPB_ENABLE_KEY_RSA       
 *  - #VLT_CPB_ENABLE_KEY_DSA       
 *  - #VLT_CPB_ENABLE_KEY_ECDSA     
 *  - #VLT_CPB_ENABLE_CIPHER_TESTS  
 *  - #VLT_CPB_ENABLE_SCP02         
 *  - #VLT_CPB_ENABLE_SCP03         
 *  - #VLT_CPB_ENABLE_BLOCK_PROTOCOL
 *  - #VLT_CPB_ENABLE_ISO7816       
 *  - #VLT_CPB_ENABLE_TWI           
 *  - #VLT_CPB_ENABLE_SPI           
 *  - #VLT_CPB_ENABLE_CIPHER_AES    
 *  - #VLT_CPB_ENABLE_CIPHER_TDES   
 *  - #VLT_CPB_ENABLE_CIPHER_DES    
 *  - #VLT_CPB_ENABLE_FAST_CRC16CCIT
 *  - #VLT_CPB_ENABLE_KEY_WRAPPING  
 *  - #VLT_CPB_ENABLE_MS_AUTH       
 *  - #VLT_CPB_ENABLE_IDENTITY_AUTH 

     * \li reserved A bitfiled reserved for future use, set to 0.
     * \li fwCompatibilityVersion A value that signifies the version compatibility of the library with the VaultIC.
     *  - 1 = Library is compatible with version 1.0.X of the VaultIC
     *  - 2 = Library is compatible with version 1.2.0 of the VaultIC
     */
    struct _VltLibraryInfo
    {
        VLT_PU8 pVersion;
        VLT_U32 capabilities;
        VLT_U32 reserved;
        VLT_U8 fwCompatibilityVersionId;
    };

    /**
     * \typedef VLT_LIBRARY_INFO
     *
     * \brief The type definition of the structure _VltLibraryInfo
     */
    typedef struct _VltLibraryInfo VLT_LIBRARY_INFO;
    
    /**
     * \fn VltInitLibrary( VLT_INIT_COMMS_PARAMS* pInitCommsParams )
     *
     * \brief Initialises the Vault IC API library.
     *
     * \par Description
     *
     * The VltInitLibrary() method is responsible for initialising the Vault IC
     * API library
     *
     * \param pInitCommsParams [IN] Parameters passed to communications layer.
     *  
     * \return Upon successful completion a VLT_OK status will be returned otherwise
     * the appropriate error code will be returned.
     *
     * \par Example:
     * \code
     *  VLT_INIT_COMMS_PARAMS* commsParams;

     *  VLT_STS status = VLT_FAIL 
     *  VLT_INIT_COMMS_PARAMS params;
     *
     *  params.enCommsProtocol = VLT_TWI_COMMS;
     *  params.Params.VltBlockProtocolParams.u16BitRate = 100;
     *  params.Params.VltBlockProtocolParams.enCheckSumMode = BLK_PTCL_CHECKSUM_SUM8;
     *
     *  params.Params.VltBlockProtocolParams.VltPeripheralParams.PeriphParams.VltTwiParams.u16BusTimeout = 450;
     *  params.Params.VltBlockProtocolParams.VltPeripheralParams.PeriphParams.VltTwiParams.u8Address = 0x5F;
     *
     *  params.Params.VltBlockProtocolParams.VltPeripheralParams.u32SerialNo = 1234567890;
     * 
     *  status = VltInitLibrary( &params );
     *
     * \endcode
     */
    VLT_STS VltInitLibrary( VLT_INIT_COMMS_PARAMS* pInitCommsParams );

    /**
     * \fn VltCloseLibrary( void )
     *
     * \brief Closes the Vault IC API library.
     *
     * \par Description
     *
     * The VltCloseLibrary() method is responsible for closing the Vault IC
     * API library
     *  
     * \return Upon successful completion a VLT_OK status will be returned otherwise
     * the appropriate error code will be returned.
     *
     * \par Example:
     * \code 
     *  VLT_STS status = VLT_FAIL; 
     * 
     *  status = VltCloseLibrary();   
     * 
     * \endcode
     */
    VLT_STS VltCloseLibrary( void );


    /**
     * \fn VltGetLibraryInfo( VLT_LIBRARY_INFO* pLibraryInfo )
     *
     * \brief Populates a provided #VLT_LIBRARY_INFO structure with information
     * about the library
     *
     * \par Description
     *
     * The VltGetLibraryInfo() method provides the caller with the capabilities of
     * the current version of the library.  The information is provided in the
     * #VLT_LIBRARY_INFO structure
     *
     * * \return Upon successful completion a VLT_OK status will be returned otherwise
     * the appropriate error code will be returned.
     *
     * \par Note:
     * Please note this method is not supported in the embedded environments.
     *
     * \par Example:
     * \code 
     *  VLT_STS status = VLT_FAIL; 
     *  VLT_LIBRARY_INFO libInfo;
     * 
     *  status = VltGetLibraryInfo( &libInfo );   
     * 
     * \endcode
     */
    VLT_STS VltGetLibraryInfo( VLT_LIBRARY_INFO* pLibraryInfo );

    /**
     * \fn VltFindDevices( VLT_PU32 pSize, VLT_PU8 pXmlReaderString )
     *
     * \brief Provides an XML based list of all supported type of devices currently connected to the system.
     *
     * \par Description
     *
     * The VltFindDevices() method provides the caller an XML based list of all 
     * supported type of devices currently connected to the system. The caller 
     * can then parse the data in order to use them in calling the VltInit() method.
     * 
     * Due to the dymanic nature of the number of supported types of devices connected, 
     * the VltFindDevices() method has to be called twice to determine the amount of 
     * data that will be eventually returned. The caller needs to call the VltFindDevices()  
     * the first time with the value of pSize set to 0 and the pXmlReaderString set to NULL, 
     * upon successful completion the VltFindDevices(), will populate the pSize with the 
     * actual number of bytes required to return the xml based data.
     * The caller then needs to allocate enough memory to hold the number of bytes returned
     * by the previous call to the VltFindDevices() in pSize.
     * Once enough memory has been allocated then the caller has to make a second call to the
     * VltFindDevices() method with pSize set to the value from the previous call and 
     * pXmlReaderString set to the pointer of the recently allocated buffer.
     * The second call will update the pSize variable to indicate the amount of data written
     * to the pXmlReaderString, while the pXmlReaderString will be populated with a null 
     * terminated XML string, an example of this is shown below:
     * 
     * \code
     * <?xml version="1.0" encoding="ISO-8859-1"?>
     * <devices>
     *      <interface type="pcsc">
     *          <peripheral idx="00">Gemplus USB Smart Card Reader 0</peripheral>
     *      </interface>
     *      <interface type="aardvark">
     *          <peripheral idx="00">2237366715</peripheral>
     *          <peripheral idx="01">2237367164</peripheral>
     *      </interface>
     *  </devices>
     * \endcode
     *
     * The VltFindDevices() method has a fundamentaly different dependency model from 
     * all other VaultIC API library methods. The VltFindDevices() method may be 
     * called before a call to the VltInitLibrary() method has been made.
     *
     * \par Note:
     * Please note this method is not supported in the embedded environments. Also
     * this method depends on having the Total Phase aardvark.dll/so
     * binaries located in the same path as your executable, or in the standard 
     * operating system library search path.
     * 
     * \return Upon successful completion a VLT_OK status will be returned otherwise
     * the appropriate error code will be returned.
     *
     * \par Example:
     * \code 
     *  VLT_STS status = VLT_FAIL ;
     *  VLT_U32 size = 0;
     *  VLT_PU8 pXmlString;
     * 
     *  \size must be set to zero for the first call.
     *  size = 0;
     *  VltFindDevices( &size , NULL );   
     *  pXmlString = (VLT_PU8)malloc( size );
     *
     *  VltFindDevices( &size , pXmlString );
     *  free( (void*)pXmlString );
     * 
     * \endcode
     */
    VLT_STS VltFindDevices( VLT_PU32 pSize, VLT_PU8 pXmlReaderString );




    /*******************************************************
    Library capabilities options
    *******************************************************/

/*
* \def VLT_CPB_ENABLE_KEY_SECRET
* \brief Library supports the use of the ::VLT_KEY_OBJ_SECRET type in all relevant API methods. 
*/
#define VLT_CPB_ENABLE_KEY_SECRET               (VLT_U32)0x00000001u
/*
* \def VLT_CPB_ENABLE_KEY_SECRET
* \brief Library supports the use of the ::VLT_KEY_OBJ_HOTP type in all relevant API methods. 
*/
#define VLT_CPB_ENABLE_KEY_HOTP                 (VLT_U32)0x00000002u
/*
* \def VLT_CPB_ENABLE_KEY_TOTP
* \brief Library supports the use of the ::VLT_KEY_OBJ_TOTP type in all relevant API methods. 
*/
#define VLT_CPB_ENABLE_KEY_TOTP                 (VLT_U32)0x00000004u
/*
* \def VLT_CPB_ENABLE_KEY_RSA
* \brief Library supports the use of the ::VLT_KEY_OBJ_RSA_PUB, ::VLT_KEY_OBJ_RSA_PRIV and VLT_KEY_OBJ_RSA_PRIV_CRT types in all relevant API methods. 
*/
#define VLT_CPB_ENABLE_KEY_RSA                  (VLT_U32)0x00000008u  
/*
* \def VLT_CPB_ENABLE_KEY_DSA
* \brief Library supports the use of the ::VLT_KEY_OBJ_DSA_PUB and ::VLT_KEY_OBJ_DSA_PRIV types in all relevant API methods. 
*/
#define VLT_CPB_ENABLE_KEY_DSA                  (VLT_U32)0x00000010u
/*
* \def VLT_CPB_ENABLE_KEY_ECDSA
* \brief Library supports the use of the ::VLT_KEY_OBJ_ECDSA_PUB and ::VLT_KEY_OBJ_ECDSA_PRIV types in all relevant API methods. 
*/
#define VLT_CPB_ENABLE_KEY_ECDSA                (VLT_U32)0x00000020u
/*
* \def VLT_CPB_ENABLE_CIPHER_TESTS
* \brief Library supports running the Cipher Self Tests after initialisation.
*/
#define VLT_CPB_ENABLE_CIPHER_TESTS             (VLT_U32)0x00000040u
/*
* \def VLT_CPB_ENABLE_IDENTITY_AUTH
* \brief Library supports the identity authentication service.
* 
* The specific authentication method supported can be found by 
* interrogating the state of the capabilities for VLT_CPB_ENABLE_SCP02,
* VLT_CPB_ENABLE_SCP03 and VLT_CPB_ENABLE_MS_AUTH.
*/
#define VLT_CPB_ENABLE_IDENTITY_AUTH            (VLT_U32)0x00000080u
/*
* \def VLT_CPB_ENABLE_SCP02
* \brief Library supports SCP02 as an authentication method.
*/
#define VLT_CPB_ENABLE_SCP02                    (VLT_U32)0x00000100u
/*
* \def VLT_CPB_ENABLE_SCP03
* \brief Library supports SCP03 as an authentication method.
*/
#define VLT_CPB_ENABLE_SCP03                    (VLT_U32)0x00000200u
/*
* \def VLT_CPB_ENABLE_MS_AUTH
* \brief Library supports Microsoft's Smart Card Minidriver as an authentication method.
*/
#define VLT_CPB_ENABLE_MS_AUTH                  (VLT_U32)0x00000400u
/*
* \def VLT_CPB_ENABLE_BLOCK_PROTOCOL
* \brief Library supports the proprietary Block Protocol for peripherals such as TWI and SPI.
*/
#define VLT_CPB_ENABLE_BLOCK_PROTOCOL           (VLT_U32)0x00000800u
/*
* \def VLT_CPB_ENABLE_ISO7816
* \brief Library supports the ISO 7816 communication protocol.
*/
#define VLT_CPB_ENABLE_ISO7816                  (VLT_U32)0x00001000u
/*
* \def VLT_CPB_ENABLE_TWI
* \brief Library supports communcation with the Vault IC via TWI.
*/
#define VLT_CPB_ENABLE_TWI                      (VLT_U32)0x00002000u
/*
* \def VLT_CPB_ENABLE_SPI
* \brief Library supports communcation with the Vault IC via SPI.
*/
#define VLT_CPB_ENABLE_SPI                      (VLT_U32)0x00004000u
/*
* \def VLT_CPB_ENABLE_SPI
* \brief Library supports the AES Cipher (128, 192 and 256 bit variant).
*/
#define VLT_CPB_ENABLE_CIPHER_AES               (VLT_U32)0x00008000u
/*
* \def VLT_CPB_ENABLE_SPI
* \brief Library supports the Triple DES Cipher (EEE and EDE modes).
*/
#define VLT_CPB_ENABLE_CIPHER_TDES              (VLT_U32)0x00010000u
/*
* \def VLT_CPB_ENABLE_SPI
* \brief Library supports the DES Cipher.
*/
#define VLT_CPB_ENABLE_CIPHER_DES               (VLT_U32)0x00020000u
/*
* \def VLT_CPB_ENABLE_SPI
* \brief Library supports the table driven CRC16 CCIT calculations.
*/
#define VLT_CPB_ENABLE_FAST_CRC16CCIT           (VLT_U32)0x00040000u
/*
* \def VLT_CPB_ENABLE_SPI
* \brief Library supports the key Wrapping Service.
*/
#define VLT_CPB_ENABLE_KEY_WRAPPING             (VLT_U32)0x00080000u
/*
* \def VLT_CPB_ENABLE_KEY_HOST_DEVICE_ID
* \brief Library supports the use of the ::VLT_KEY_OBJ_ID type in all relevant API methods. 
*/
#define VLT_CPB_ENABLE_KEY_HOST_DEVICE_ID       (VLT_U32)0x00100000u
/*
* \def VLT_CPB_ENABLE_FILE_SYSTEM
* \brief Library supports the File System Service. 
*/
#define VLT_CPB_ENABLE_FILE_SYSTEM              (VLT_U32)0x00200000u
/*
* \def VLT_CPB_ENABLE_AARDVRKSUPP_ERR
* \brief Library supports the File System Service. 
*/
#define VLT_CPB_ENABLE_AARDVRKSUPP_ERR          (VLT_U32)0x00400000u

/*
* \def VLT_CPB_ENABLE_BLE
* \brief Library supports communcation with the Vault IC via BLE.
*/
#define VLT_CPB_ENABLE_BLE                      (VLT_U32)0x00800000u

/*
* \def VLT_CPB_ENABLE_WISEBOARD
* \breif Library supports the wiseboard.
*
* The define is used to add or remove support for B-283 curve.  The curve is
* used within the identity authentication service.
*/
#define VLT_CPB_ENABLE_WISEBOARD                  (VLT_U32)0x40000000u

#ifdef __cplusplus 
}
#endif 
/**@}*/
#endif /*VAULTIC_LIB_H*/
