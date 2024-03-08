#ifndef VLT_CSR_H
#define VLT_CSR_H

#ifdef __cplusplus
extern "C" {
#endif

// Definition of public constants
#define P256_BYTE_SZ 			32

typedef enum {
	SSL_IDEVID_CERT,
	SSL_LDEVID_CERT
} cert_type;

//>>>>>>>>>> CSR variables
// When CSR definitions are added, update this enumeration
typedef enum
{
	DeviceIdentity,
	DeviceNetworkCredentials,
	TestCsr,
} csrdefs;

// Individually defined CSR variables
extern VLT_U16 csrlen_max;
extern VLT_U16 csrlen_max_b64;
extern VLT_U16 csrloc_pubKey;
extern VLT_U16 csrlen_pubKey;
extern VLT_U16 csrloc_sig;
extern VLT_U16 csrtbs_len;
extern VLT_U16 csrtbs_offset;
extern VLT_U8* pCsr_data;
extern VLT_U16 csrlen_data;

//<<<<<<<<<<<<<<<<<<<<<<<

// Crypto / X.509 Constants
#define CSR_SIZE_INDEX		2
#define CSR_LEN_HEADER		36
#define CSR_LEN_FOOTER		34
#define OFFSET_RSIG			5
#define OFFSET_SIG_DER		2
// Define these variables and check validity in VltSelectCsr()
#define MAXLEN_CSR			550
#define CSR_NEWLINE			20
#define MAXLEN_CSR_B64		((4*(MAXLEN_CSR + 2) / 3) + CSR_NEWLINE)

// The X.509 signatures includes encoding bytes and potentially 0x00 uint bytes
#define MAXLEN_P256_X509_SIG	73

// Definition of public functions 
VLT_STS VltSelectCsr(csrdefs selection);
VLT_STS VltCreateEcdsaDomainParams(VLT_USER_ID userId, VLT_ECC_ID curveId, VLT_U8 domainKeyGrp, VLT_U8 domainKeyIdx, VLT_KEY_OBJECT* pDomainParams);
VLT_STS VltGenKey(VLT_USER_ID userId, VLT_ECC_ID curveId, VLT_U8 genGrp, VLT_U8 genPubIdx, VLT_U8 genPrivIdx, VLT_KEY_OBJ_ECDSA_PUB* pGenPub);
VLT_STS VltSign(VLT_ECC_ID curveId, VLT_U8 privGrp, VLT_U8 privIdx, VLT_U8* pMsg, VLT_U16 lenMsg, VLT_U8* pSig, VLT_U16* pLenSig);
VLT_STS VltVerify(VLT_ECC_ID curveId, VLT_KEY_OBJ_ECDSA_PUB* pPubObj, VLT_U8* pMsg, VLT_U16 lenMsg, VLT_U8* pSig, VLT_U16 lenSig);
VLT_STS VltCsrMergePubKey(VLT_U8* pCsr, VLT_U16 lenCsr, VLT_U16 locPubKey, VLT_U8* pPubKey, VLT_U16 lenPubKey);
VLT_STS VltCsrMergeSig(VLT_U8* pCsr, VLT_U16* pLenCsr, VLT_U16 locSig, VLT_U8* pSig, VLT_U16 lenSig);
VLT_STS VltBuildBase64Csr(VLT_U8* pData, VLT_U16 lenData, VLT_U8* pBase64Csr, VLT_U16* pLenBase64Csr);
VLT_STS VltBuildBase64Csr(VLT_U8* pData, VLT_U16 lenData, VLT_U8* pBase64Csr, VLT_U16* pLenBase64Csr);
VLT_STS Base64Encode(VLT_U8* pData, VLT_U16 lenData, VLT_U8* pBase64, VLT_U16* pLenBase64, VLT_U16 newlineByte);
VLT_STS Base64Decode(VLT_U8* pBase64, VLT_U16 lenBase64, VLT_U8* pData, VLT_U16* pLenData);
VLT_STS GetHexText(VLT_PU8 pData, VLT_U16 lenData, VLT_U8* pHexText, VLT_U16* pLenHexText);
VLT_STS VltGetRootFilename(VLT_U8* pRootFilename, VLT_U16 lenRootFilename, csrdefs csrselection);
VLT_STS VltWriteText(VLT_U8* pData, VLT_U8* sRootFilename, VLT_U8* sExt);
VLT_STS VltWriteDataBuffer(VLT_U8* pData, VLT_U16 lenData, VLT_U8* sRootFilename, VLT_U8* sExt);

#endif // VLT_CSR_H 
