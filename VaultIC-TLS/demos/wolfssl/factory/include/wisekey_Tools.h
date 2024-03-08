/*=======================================
SEAL SQ 2023
Zero-touch Provisioning
IoT / Tools / Provisioning / Firmware Team
=======================================*/
#ifndef TOOLS_H
#define TOOLS_H

#include "../lib/ini/ini.h"
#include "../lib/json/json.h"


#ifdef __cplusplus
extern "C"
{
#endif

    /** @brief Ines Protocol to choose
     * 
    */
    enum INES_PROTOCOL
    {
        API_REST = 0,
        API_EST = 1,
    };


    /** @brief Create a device name for registration to IoT Hub.
     *
     * @param config .ini structure
     * @return Device name
     */
    char *createDeviceName(config_values_t config);

    /**
     * @brief Restart ESP32
     */
    void rebootEsp();

    /** @brief Open file and place it in a buffer.
     *
     *  @param path path of file to open.
     *  @return text file in buffer.
     */
    char *openFile(const char *path);

    /** @brief Save the input char* to a file
     *
     *  @param name path/to/file of file to save
     *  @param content Content of the string
     *  @param size size of the string to save
     *  @return status 0 on success
     */
    int writeAndSaveFile(char *name, char *content, int size);

    /** @brief Verify presence of certificate, certificate chain and key
     *
     *  @param config 
     *  @return status 0 on success
     */
    int checkCertificateAndKeyDisponibility(config_values_t config);

    /** @brief Format the raw certificate sended by REST API Ines into a .pem format char*
     *
     *  @param path path of file to open.
     *  @return text file in buffer.
     */
    char *inesRawCartificatetoFormatedcert(char *rawCert);

    /** @brief Format the raw certificate sended by EST API Ines into a .pem format char*
     *
     *  @param path path of file to open.
     *  @return text file in buffer.
     */
    char *estRawCartificatetoFormatedcert(char *rawCert);
    
    /** @brief Format a string into a JSON_Value type
     *
     *  @param string to convert
     *  @return json_value type
     */
    json_value* convertStringIntoJsontype(char* string);

    /** @brief This will extract the json value choosen
     * exemple :  
     * "ca": {
        "id": 1,
        "caAlias": "DEVIOTSUBCA1 for CMS",
        "thumbprint": "F3B64C042C73F66B179B4082C773AC3BCDF761A7",
        "serverName": "_name_",
        "caName": "DEVIOTSUBCA1",
        "description": null,
        "certificate": "MIICvzCCAkagAwIBAg...+vSEIw5IfWBds24k="
        },
     * @param value is the json string
     * @param object is the first level object (ca for example)
     * @param object2 is the second level object (id, caAlias, thumbprint ...)
     * @return char* value corresponding, NULL if no value  
     */
    char *extractJsonValue(json_value *value, char *object, char *object2);

    /** @brief This will copy the value corresponding into the struct oject choosen
     * @param structValue struct fiels where to store the value
     * @param value is the json string
     * @param object is the first level object (ca for example)
     * @param object2 is the second level object (id, caAlias, thumbprint ...)
     * @return 0 if success, -1 is case of problem  
     */
    int storeJsonValueIntoStructValue(char **structValue, json_value *value, char *object, char *object2);

    /** @brief Acepted values of wkey_log(...) function
    */
    enum LOG_TYPE
    {
        LOG_INFO = 0,
        LOG_WARNING = 1,
        LOG_ERROR = 2,
        LOG_STEP_INDICATOR = 3,
        LOG_DEBUGING = 4,
        LOG_SUCCESS =5,
    };

    /** @brief Wisekey Log function
     *
     *  @param type LOG_INFO, LOG_WARNING, LOG_ERROR, LOG_STEP_INDICATOR, LOG_SUCCESS and LOG_DEBUGING
     *  @param format String to display
     *  @param ... some further arguments
     */
    void wkey_log(int type, char *format, ...);

#ifdef __cplusplus
}
#endif

#endif /*TOOLS_H*/
