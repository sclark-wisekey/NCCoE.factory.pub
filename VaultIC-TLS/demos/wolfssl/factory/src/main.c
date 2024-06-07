/*=======================================
SEAL SQ 2023
Zero-touch Provisioning
IoT / Tools / Provisioning / Firmware Team
=======================================*/

// System libs
#include <time.h>

// SEAL SQ Libs
#include "wisekey_Ines_Agent.h"
#include "wisekey_Ines_settings.h"
#include "wisekey_Crypto_Tools.h"
#include "vaultic_common.h"
#include "vaultic_api.h"
#include "common.h"
#include <math.h>

#ifdef _WIN32
#define CONFIG_DIR "../../VaultIC-TLS/demos/wolfssl/factory/data/inesConfig.win.ini"
#else
#define CONFIG_DIR "../data/inesConfig.rpi.ini"
#include "limits.h"
#endif

// Defines
#define SNTP_SERVER_FQDN "pool.ntp.org"
#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT BIT1


// Function prototypes
int VaultIC_Factory_CSR(TEST_PARAMS_T * test_params, config_values_t config);
//VLT_STS DisplayLibraryInformation();
static VLT_COMM_MODE GetCommInterface(void);


#ifdef _WIN32
void rpi_main(int argc, char *argv[])
#else
void main(int argc, char *argv[])
#endif
{

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

    
    printf("SEAL SQ\n\n------------------------------------\nFactory Provisioning using INES\n------------------------------------\n\n");
    wkey_log(LOG_INFO,"VERSION : %s",DEMO_VERSION);
    wkey_log(LOG_STEP_INDICATOR,"INES DEMOS INITIALIZING");

    time_t seconds;
     
    seconds = time(NULL);
    printf("Seconds since January 1, 1970 = %ld\n", (long)seconds);

    // Extract the data from the config file
    config_values_t config;
    initConfigFile(&config);
    parseConfigFile(CONFIG_DIR, &config);


    if(verifyConfigStruc(CONFIG_FILE_INES,&config)<0)
    {
        wkey_log(LOG_ERROR, "Invalid INES config provided");
        rebootEsp() ;
    }

    wkey_log(LOG_STEP_INDICATOR,"INES DEMOS INITIALIZED");

	//// Display the eLib version and information
	//DisplayLibraryInformation();

	// Prepare reader to start VaultIC functionality
	VLT_STS status = VLT_FAIL;
	TEST_PARAMS_T testParams;

#ifndef _WIN32
	// Set Communication Interface to use SPI
	testParams.commsParams.enCommsProtocol = GetCommInterface();

	// Configure Communication parameters
	testParams.commsParams.enCommsProtocol = VLT_SPI_COMMS;
	testParams.commsParams.VltSpiParams.u16BitRate = VLT_SPI_BITRATE;	// in kbits

	//testParams.commsParams.VltBlockProtocolParams.enCheckSumMode = BLK_PTCL_CHECKSUM_SUM8;
	testParams.commsParams.VltBlockProtocolParams.u16msSelfTestDelay = VLT_SELF_TEST_WAIT_TIME; 	// in ms - time required for vaultic to complete its self tests
	testParams.commsParams.VltBlockProtocolParams.u32msTimeout = VLT_APDU_TIME_OUT;        		// in ms - max time required by vaultic to return a response to an APDU command
#endif
	// Set the manufacturer password into the structure
	// VaultIC4xx
	unsigned char pwd[8] = { 0x58, 0x6e, 0x54, 0x79, 0x32, 0x34, 0x69, 0x6e };

	// VaultIC408 v1.2
	//unsigned char pwd[8] = { 0x33, 0x49, 0x70, 0x6D, 0x59, 0x54, 0x35, 0x58 };
	
	memcpy(testParams.au8ManufPassword, pwd, sizeof(pwd));
	testParams.u8ManufPasswordLength = sizeof(pwd);

	// INeS Issue Certificate Demo
	int protocol = API_REST;

	// Create a CSR using a VaultIC key pair
	if (VLT_OK != VaultIC_Factory_CSR(&testParams, config))
		return;

	int inesStatus = inesDemo_IssueCert(config, protocol);

	if (inesStatus != 0)
		wkey_log(LOG_ERROR, "Ines Agent Malfunction, please see previous error");


	freeConfigStruct(&config);
}

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
