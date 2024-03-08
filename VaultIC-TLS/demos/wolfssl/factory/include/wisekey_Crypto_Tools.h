/*=======================================
SEAL SQ 2023
Zero-touch Provisioning
IoT / Tools / Provisioning / Firmware Team
=======================================*/

#ifndef OPENSSL_TOOLS_H
#define OPENSSL_TOOLS_H

#include "wolfssl/wolfcrypt/asn.h"
#include <wolfssl/wolfcrypt/aes.h>

#ifdef __cplusplus
extern "C"
{
#endif

// Define OIDs for X.509 certificates
#define OID_COUNTRY "2.5.4.6"
#define OID_ORGANIZATION_NAME "2.5.4.10"
#define OID_ORGANIZATIONAL_UNIT_NAME "2.5.4.11" 
#define OID_COMMON_NAME "2.5.4.3"
#define OID_LOCALITY_NAME "2.5.4.7"
#define OID_STATE_OR_PROVINCE_NAME "2.5.4.8"
#define OID_POSTAL_CODE "2.5.4.17"
#define OID_TITLE "2.5.4.12"
#define OID_GIVEN_NAME "2.5.4.42"
#define OID_INITIALS "2.5.4.43"
#define OID_SUR_NAME "2.5.4.4"
#define OID_STREET_ADDRESS "2.5.4.9"
#define OID_DEVICE_SERIAL_NUMBER "2.5.4.5"

// Define constant allocations 
#define MAXCSR  4097

// General defines
#define READ_CSR

    /**
     * @brief Generate and save an ECC Keys With an ECC_SECP256R1 Curve.
     *
     * @param[in] ecKey Key type
     * @param[in] outFilePath Path of the file to save the .pem key file
     */
    int generateAndSavePrivateEccKey(ecc_key *ecKey, char *outFilePath);

    /**
     * @brief this function will count the size of the string of the subject you want to add
     * @param[in] oid is the OID of the subject (please choose on of OID_)
     * @param[in] value is the value of the subject
     * @param[in] first to mark it is the first iteration of concatenateSubject
     * @return size of the subject str
     */
    int countStrSubjectSize(char *oid, char *value, int *first);

    /**
     * @brief Call this function to create the subjects part of the Ines call API
     *
     * @param[in] strsubjects is the string to concatenate with the new subject
     * @param[in] oid is the OID of the subject
     * @param[in] value is the value of the subject
     * @param[in] first to mark it is the first iteration of concatenateSubject 
     */
    void concatenateSubject(char *strsubjects, char *oid, char *value, int *first);

    /**
     * @brief This function will generate the subjects part 
     * @param[in] certDefaultName WolfSLL certName Struct
     * @return string of subject for Ines call API
     */
    char *generateSubjects(CertName *certDefaultName);

    /**
     * @brief Generate a private key signed CSR to send to INES PKI
     *
     * @param[in] ecKey Key type previously generated (generateAndSavePrivateEccKey)
     * @param[in] deviceName Name of the device that will be save in common
     * @param[in] country country part of the certificate
     */
    char *generateCSR(ecc_key *ecKey, CertName* certDefaultName, int* lenCSR);

    /**
     * @brief Check validity date of certificate.
     *
     * @param[in] Path_file Path file.
     * @return 0 if certificate is valid, -1 if is expired
     */
    int checkCertificateValidity(const char *path_file);

    /**
     * @brief this function remove the certificate without BEGIN CERT and END CERT part
     * @param[in] cert certificate string
     * @return certifictate without headers and footer
     */
    char* removeCertificateHeaders(char *cert);

    /**
     * @brief this function remove the certificate without BEGIN CERT and END CERT part
     * @param[in] cert certificate string
     * @return certifictate without headers and footer
     */
    char* removeCSR_Headers(char *CSR);

#ifdef __cplusplus
}
#endif

#endif /*OPENSSL_TOOLS_H_*/
