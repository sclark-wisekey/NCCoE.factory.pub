#include "vaultic_common.h"
#include "vaultic_api.h"
#include "vaultic_ecdsa_signer.h"
#include "vaultic_HMAC.h"
// #include "common.h"
// #include "vaultic_csr.h"

unsigned char pw[8] = {
    0x58, 0x6e, 0x54, 0x79, 0x32, 0x34, 0x69, 0x6e
};

int
main (int argc, char **argv)
{
    TEST_PARAMS_T testParams;
    VLT_TARGET_INFO tInfo;
    VLT_INIT_COMMS_PARAMS *commsParams;
    VLT_MANAGE_AUTH_DATA structAuthSetup;
    VLT_U8 userPin[] = {0x30, 0x31, 0x30, 0x31, 0x30, 0x31};
    VLT_KEY_OBJ_ECDSA_PUB genPub;
    VLT_U8 pX[P256_BYTE_SZ] = { 0 };
    VLT_U8 pY[P256_BYTE_SZ] = { 0 };
    VLT_U8 genGrp = 0x51;
    VLT_U8 genPubIdx = 0xDE;
    VLT_U8 genPrivIdx = 0xCA;
    char *szManuf, *szInterface, *c;
    int i;

//    if (argc != 2) {
//        fprintf(stderr, "USAGE: %s <password>\n", argv[0]);
//        exit(1);
//    }

    testParams.commsParams.enCommsProtocol = VLT_SPI_COMMS;
    testParams.commsParams.VltSpiParams.u16BitRate = VLT_SPI_BITRATE;
    testParams.commsParams.VltBlockProtocolParams.enCheckSumMode = BLK_PTCL_CHECKSUM_SUM8;
    testParams.commsParams.VltBlockProtocolParams.u16msSelfTestDelay = VLT_SELF_TEST_WAIT_TIME;
    testParams.commsParams.VltBlockProtocolParams.u32msTimeout = VLT_APDU_TIME_OUT;

    strcpy(testParams.au8ManufPassword, pw);
    testParams.u8ManufPasswordLength = 8;

    commsParams = &testParams.commsParams;

//    DisplayLibraryInformation();
//    if (InitializeReader(strtoul((const char *)szInterface.c_str(), NULL, 10), &testParams.commsParams) != VLT_OK) {
//        fprintf(stderr, "%s: can't initialize reader\n", argv[0]);
//        exit(1);
//    }
    
    if (VltApiInit(commsParams) != VLT_OK) {
        fprintf(stderr, "%s: can't initialize APIs\n", argv[0]);
        exit(1);
    }
    if (VltGetInfo(&tInfo) != VLT_OK) {
        fprintf(stderr, "%s: can't get target info\n", argv[0]);
        exit(1);
    }
    printf("target name is %s\n", tInfo.au8Firmware);

    if (VltSubmitPassword(VLT_USER7, VLT_MANUFACTURER,
                          testParams.u8ManufPasswordLength, testParams.au8ManufPassword) != VLT_OK) {
        fprintf(stderr, "%s: can't submit user7 password\n", argv[0]);
        exit(1);
    }
    VltSetStatus(VLT_STATE_ACTIVATED);

    if (VltSetStatus(VLT_STATE_CREATION) != VLT_OK) {
        fprintf(stderr, "%s: can't set vlt status\n", argv[0]);
        exit(1);
    }

    structAuthSetup.enOperationID = VLT_DELETE_USER;
    for (VLT_USER_ID i = VLT_USER0; i < VLT_USER7; i++) {
        printf("deleting user %d...,", i);
        structAuthSetup.enUserID = i;
        VltManageAuthenticationData(&structAuthSetup);
    }
    printf("\ndeleted users0-6\n");

    structAuthSetup.enOperationID = VLT_CREATE_USER;
    structAuthSetup.enUserID = USER_PIN_ID;
    structAuthSetup.enMethod = VLT_AUTH_PASSWORD;
    structAuthSetup.enRoleID = VLT_NON_APPROVED_USER;
    structAuthSetup.enChannelLevel = VLT_NO_CHANNEL;
    structAuthSetup.enSecurityOption = VLT_NO_DELETE_ON_LOCK;
    structAuthSetup.u8TryCount = 5;

    memcpy(&structAuthSetup.data.password.u8Password, userPin, sizeof(userPin));
    structAuthSetup.data.password.u8PasswordLength = (VLT_U8)sizeof(userPin);

    if (VltManageAuthenticationData(&structAuthSetup) != VLT_OK) {
        fprintf(stderr, "%s: can't create user!\n", argv[0]);
        exit(1);
    }
    printf("\ncreated user!\n");

    if (VltSetStatus(VLT_STATE_ACTIVATED) != VLT_OK) {
	fprintf(stderr, "%s: can't set operational mode\n");
	exit(1);
    }
    printf("set to operational mode successfull!\n");
    VltCancelAuthentication();
    if (VltSubmitPassword(VLT_USER0, VLT_NON_APPROVED_USER, sizeof(userPin), (VLT_U8 *)userPin) != VLT_OK) {
        fprintf(stderr, "%s: can't log in as user 0\n", argv[0]);
        exit(1);
    }

    genPub.pu8Qx = pX;
    genPub.pu8Qy = pY;
    genPub.u8DomainParamsGroup = 0x24;
    genPub.u8DomainParamsIndex = 0x0D;
    genPub.u16QLen = P256_BYTE_SZ; //domainParams.data.EcdsaParamsKey.u16NLen;
    if (VltGenKey(USER_PIN_ID, VLT_ECC_ID_P256, genGrp, genPubIdx, genPrivIdx, &genPub) != VLT_OK) {
        fprintf(stderr, "%s: can't generate keypair!\n", argv[0]);
        exit(1);
    }

    printf("x:"); PrintHexBuffer(genPub.pu8Qx, P256_BYTE_SZ);
    printf("y:"); PrintHexBuffer(genPub.pu8Qy, P256_BYTE_SZ);

    exit(0);

}
