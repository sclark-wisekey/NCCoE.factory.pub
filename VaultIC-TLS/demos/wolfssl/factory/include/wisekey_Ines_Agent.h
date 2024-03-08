/*=======================================
SEAL SQ 2023
Zero-touch Provisioning
IoT / Tools / Provisioning / Firmware Team
=======================================*/

/*! \file wisekey_Ines_Agent.h
    \brief INES SDK.
    
    Details.
*/
#ifndef INES_AGENT_H_
#define INES_AGENT_H_

#include "wisekey_Tools.h"

#ifdef __cplusplus
extern "C"
{
#endif

	/*! @brief Launch the Ines Zero Touch Provisioning Demo
	 * It will verify the certificate, if the certificate isn't valid, it will lauch createDeviceCertificateFromInesFromInes to ask another certificate
	 *
	 *  @param config Config File to choose
	 *  @param protocol protocol to use (API_EST or API_REST)
	 */
	int inesDemo_ZeroTouchProv(config_values_t config, int protocol);

	/*! @brief Launch the Ines Issue Cert Demo
	 * It will create the certificate using the CSR created on a VaultIC
	 *
	 *  @param config Config File to choose
	 *  @param protocol protocol to use (API_EST or API_REST)
	 */
	int inesDemo_IssueCert(config_values_t config, int protocol);

    /** @brief This will lauch the procedure to ask for a certificate to Ines, please verify you have an internet connexion and the correct config files
     *
     *  @param config Config File to choose
     *  @param deviceName to choose the name display by Ines
     *  @param country country string display by the certificate
     *  @param protocol protocol to use (API_EST or API_REST)

     */
    int createDeviceCertificateFromInes(config_values_t config, int protocol);

    /** @brief This will send a REST request to Ines
     *  @param config Config File to choose
     *  @param method
     *  @param apiname
     *  @param custom_suffix
     *  @param body
     *  @return response from Ines
     */
    char* apiREST_process(config_values_t config, char* method, char* apiname, char* custom_suffix,char* body);

    /** @brief This will send a EST request to Ines
     *  @param method
     *  @param apiname
     *  @param custom_suffix
     *  @param body
     *  @return response from Ines
     */
    char* apiEST_process(config_values_t config,char* clientCert,char*clientKey,char* method, char* apiname, char* custom_suffix,char* body);


    /// @brief Struct to store certificate details when askeb from Ines
    typedef struct authentication_t
    {
        char *access_token;
    } authentication_t;


    /// @brief Struct to store certificate details when askeb from Ines
    typedef struct CA_details_t
    {
        char *id;
        char *caAlias;
        char *thumbprint;
        char *serverName;
        char *caName;
        char *description;
        char *certificate;
    } CA_details_t;

    /// @brief Struct to store certificate chain when askeb from Ines
    typedef struct CA_certificat_chain_detail_t
    {
        char *subject;
        char *issuer;
        char *certificate;
    } CA_certificat_chain_detail_t;

    /// @brief Struct to store certificate chain when askeb from Ines
    typedef struct CA_certificat_chain_t
    {
        CA_certificat_chain_detail_t root;
        CA_certificat_chain_detail_t issuing;
    } CA_certificat_chain_t;

    /// @brief Struct to store certificate when askeb from Ines
    typedef struct certificate_t
    {
        char *certificate_id;
        char *organization_id;
        char *common_name;
        char *issued_dn;
        char *certificate;
        char *certificate_pkcs12;
        char *passphrase;
        char *status;
        char *issuer;
        char *serial_number;
        char *valid_from;
        char *valid_until;
        char *revocation_reason;
        char *revocation_date;
        char *thumbprint;
        char *san;
    } certificate_t;

    /// @brief Struct to store the status of a certificate when asked from Ines
    typedef struct certificate_status_t
    {
        char *status;
        char *detail;
        char *reason;
        char *revocation_date;
    } certificate_status_t;

    /// @brief Struct to store the status of a certificate template when asked from Ines
    typedef struct certificate_template_t
    {
        char *template_id;
        char *organization_id;
        char *name;
        char *description;
        char *status;
    } certificate_template_t;

    /** @brief Enum to specify the type of struct to fill
     *
     *  @param config Config File to choose
     */
    enum INES_STRUCT_TYPE
    {
        INES_RESPONSE_TYPE_CA_DETAILS = 0,
        INES_RESPONSE_TYPE_CA_LIST = 1,
        INES_RESPONSE_TYPE_CA_CERTIFICATE_CHAIN = 2,
        INES_RESPONSE_TYPE_CERTIFICATE = 3,
        INES_RESPONSE_TYPE_CERTIFICATE_STATUS = 4,
        INES_RESPONSE_TYPE_AUTHENTICATION = 5,
        INES_RESPONSE_TYPE_CERTIFICATE_TEMPLATE = 6,
    };

    /** @brief fill the Array with the response from Ines
     *
     *  @param type type of structure to fill, choose on of INES_STRUCT_TYPE, must correspond to the input_struct type
     *  @param input_Struct structure to fill
     *  @param value Json Value
     */
    void fillArrayList(int type, void*OutputArray, json_value *value);


    /** @brief fill the structure with the response from Ines
     *
     *  @param type type of structure to fill, choose on of INES_STRUCT_TYPE, must correspond to the input_struct type
     *  @param input_Struct structure to fill
     *  @param value Json Value
     */
    void fillResultStruct(int type, void *input_Struct, json_value *value);

    /** @brief Display the result stored into the choosen structure
     *
     *  @param type type of structure to diplay, choose on of INES_STRUCT_TYPE, must correspond to the input_struct type
     *  @param input_Struct structure to diplay
     */
    void displayResults(int type, void *input_Struct);

    /** @brief Free the struct
     *
     *  @param type type of structure to free, choose on of INES_STRUCT_TYPE, must correspond to the input_struct type
     *  @param input_Struct structure to free
     */
    void freeResultStruct(int type, void *input_Struct);

    /** @brief Ask Ines to get the list of CA available
     *
     *  @param config .ini config struct
     *  @param CA_List CA_details_t[x] array struct to store results
     *  @return Number of CA returned
     */
    int apiREST_getCAList(config_values_t config,CA_details_t*CA_List, int CA_listSize);

    /** @brief Will ask INES to get the CA details with the provided ID
     *
     *  @param config .ini config struct
     *  @param CA_id id of CA you wnat details
     *  @return CA_details_t structure filled on success, filled of "NULL" in case of failure
     */
    CA_details_t apiREST_getCAdetails(config_values_t config, int CA_id);

    /** @brief Will ask INES to get the CA chain with the provided ID
     *
     *  @param config .ini config struct
     *  @param CA_id id of CA you wnat details
     *  @return CA_certificat_chain_t structure filled on success, filled of "NULL" in case of failure
     */
    CA_certificat_chain_t apiREST_getCACertificateChain(config_values_t config, int CA_id);

    /** @brief Will ask INES to get the CA details with the provided ID
     *
     *  @param config .ini config struct
     *  @param templateId template provided by your Wisekey FAE
     *  @param subjects subjects generated by generateSubjects(...)
     *  @param CSR string
     *  @return certificate_t structure filled on success, filled of "NULL" in case of failure
     */
    certificate_t apiREST_issueCertificate(config_values_t config, char *templateId, char *subjects, char *CSR, int lenCSR);

    /** @brief Will ask Ines a list of certificate at the current pageNum
     *
     *  @param config .ini config struct
     *  @param certificate_List certificate_t[x] array struct to store results
     *  @param commonName if You want to filter the list by commonName
     *  @param certificate_ListSize Size allocated in certificate_List
     *  @param pageNum choose the PageNumber of Ines
     *  @return Number of certificate returned
     */
    int apiREST_getCertificateList(config_values_t config,certificate_t* certificate_List,char* commonName,int certificate_ListSize, int pageNum);

    /** @brief Will ask INES to get the CA details with the provided ID
     *
     *  @param config .ini config struct
     *  @param certificate_id Id of the certificate you want to renew
     *  @param revokeOriginal set a TRUE if you want to revoke the original certificate (with the id provided before)
     *  @param CSR string
     *  @return certificate_t structure filled on success, filled of "NULL" in case of failure
     */
    certificate_t apiREST_renewCertificate(config_values_t config, int certificate_id, int revokeOriginal, char *CSR);

    /** @brief Will ask INES to verify if a certificate is valid (not revoked and not expired) and also ask the revokation status
     *
     *  @param config .ini config struct
     *  @param certificate certificate you want to validate, must be a certificate generated by INES
     *  @return 0 if certificate validated by INES, 1 if revoke, 2 if expired, <0 if error
     */
    int checkCertificate(config_values_t config, char *certificate);

    /** @brief Will ask INES to validate a certificate 
     *
     *  @param config .ini config struct
     *  @param certificate certificate you want to validate, must be a certificate generated by INES
     *  @return certificate_status_t structure filled on success, filled of "NULL" in case of failure
     */
    certificate_status_t apiREST_validateCertificate(config_values_t config, char *certificate);

    /** @brief Will ask INES revokation informations of the certificate 
     *
     *  @param config .ini config struct
     *  @param certificate certificate you want to get revokation informations, must be a certificate generated by INES
     *  @return certificate_status_t structure filled on success, filled of "NULL" in case of failure
     */
    certificate_status_t apiREST_getRevocationInformation(config_values_t config, char *certificate);

    /** @brief Will ask INES details of certificate by Id or thumbprint (only fill one of this two parametters) 
     *
     *  @param config .ini config struct
     *  @param thumbprint fill it if you want to get informations by the thumbprint of the certificate
     *  @param certID fill it if you want to get informations by id of the certificate
     *  @return certificate_status_t structure filled on success, filled of "NULL" in case of failure
     */
    certificate_t apiREST_getCertificateDetails(config_values_t config, char *thumbprint, int certID);

    /**  @brief Enum to choose a revokation reason when asked to Ines*/
    enum REVOCATION_REASONS
    {
        REVOKE_UNSPECIFIED = 0,
        REVOKE_KEY_COMPROMISE = 1,
        REVOKE_CA_COMPROMISE = 2,
        REVOKE_AFFILIATION_CHANGED = 3,
        REVOKE_SUPERSEDED = 4,
        REVOKE_CESSATION_OF_OPERATION = 5,
        REVOKE_CERTIFICATE_HOLD = 6,
        REVOKE_REMOVE_FROM_CRL = 7,
        REVOKE_PRIVILEGE_WITHDRAW = 8,
        REVOKE_AA_COMPROMISE = 9,
    };

    /** @brief Will ask Ines to revoke the given certificate
     *
     *  @param config .ini config struct
     *  @param certId id of the certificate you want to revoke
     *  @param revokationReason choose one of REVOCATION_REASONS enum
     *  @param revocationComment fill if you want to add a comment on the revokation
     *  @return 0 if success, -1 in case of faillure
     */
    int apiREST_revokeCertificate(config_values_t config, int certId, int revokationReason, char *revocationComment);

    /** @brief Will ask Ines a list of certificate Template
     *
     *  @param config .ini config struct
     *  @param certificate_List certificate_t[x] array struct to store results
     *  @param certificate_ListSize Size allocated in certificate_List
     *  @return Number of certificate returned
     */
    int apiREST_getCertificateTemplateList(config_values_t config,certificate_template_t* certificateTemplate_List, int certificateTemplate_ListSize);

    /** @brief enum of possible API EST*/
    enum API_EST
    {
        GET_CA_CERTIFICATE = 0,
        GET_CA_CERTIFICATE_ARBITRARY_LABEL = 1,
        ENROLL_CERTIFICATE = 2,
        ENROLL_CERTIFICATE_ARBITRARY_LABEL = 3,
        RE_ENROLL_CERTIFICATE = 4,
        RE_ENROLL_CERTIFICATE_ARBITRARY_LABEL = 5,
        ENROLL_CERTIFICATE_SERVER_KEY_GEN = 6,
        ENROLL_CERTIFICATE_SERVER_KEY_GEN_ARBITRARY_LABEL = 7,
    };

    /** @brief will send the choosen EST request to INES
     *
     *  @param config .ini config struct
     *  @param mode choose one of API_EST enum
     *  @param body if body needed, see INES documentation
     *  @param arbitraryLabel see INES documentation
     *  @return 0 if success, -1 in case of faillure
     */
    char *apiEST(config_values_t config,char* clientCert,char*clientKey,int mode, char *body, char *arbitraryLabel);

#ifdef __cplusplus
}
#endif

#endif // INES_AGENT_H_
