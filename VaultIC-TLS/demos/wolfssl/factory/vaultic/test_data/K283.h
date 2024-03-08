/**
* @file
*
* @note    THIS PRODUCT IS SUPPLIED FOR EVALUATION, TESTING AND/OR DEMONSTRATION PURPOSES ONLY.
*
* @note    <b>DISCLAIMER</b>
*
* @note    Copyright (C) 2020 Wisekey
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
*/

//K283 Test Key Values
#ifdef DEF_VARS

//Host Keypair
unsigned char auc_Host_Qx_K283[]=
{
	0x06, 0x58, 0x31, 0x21, 0xB8, 0x69, 0x48, 0x54, 0x56, 0x91, 0x9D, 0xAE, 0xC3, 0x3C, 0x87, 0xDA, 0x69, 0xA5, 0xC3, 0x43, 0x14, 0x01, 0xE8, 0xFA, 0xD2, 0x60, 0x28, 0xD3, 0xA6, 0x53, 0x05, 0x7C, 0xFF, 0xFC, 0x87, 0x02, 
};

unsigned char auc_Host_Qy_K283[]=
{
	0x01, 0x45, 0xBF, 0x0B, 0xDB, 0xB8, 0x8B, 0xFC, 0xA6, 0x19, 0xE0, 0xE4, 0x55, 0xCA, 0xEE, 0x11, 0x39, 0x77, 0x59, 0x32, 0xB4, 0x53, 0x01, 0x53, 0x8F, 0xB3, 0x91, 0x11, 0x29, 0x25, 0xE9, 0x2C, 0xEB, 0x06, 0x9F, 0x27, 
};

unsigned char auc_Host_D_K283[]=
{
	0x01, 0xD9, 0x58, 0xFD, 0x8D, 0x5C, 0x41, 0xCD, 0xF5, 0x32, 0x19, 0x19, 0xDF, 0x8C, 0xD8, 0xFF, 0x5B, 0xAA, 0x86, 0x0E, 0xB6, 0xCD, 0x7D, 0x78, 0xD5, 0xC3, 0x58, 0x98, 0x4C, 0xFA, 0x4F, 0xC6, 0x3C, 0xA9, 0x17, 0x08, 
};

//Device Keypair
unsigned char auc_Device_Qx_K283[]=
{
	0x01, 0x83, 0x68, 0x08, 0xB9, 0xE5, 0x8F, 0x47, 0x60, 0xEC, 0x54, 0xC4, 0x85, 0x5A, 0xAB, 0xCF, 0xBE, 0x3C, 0xF4, 0xE4, 0x9A, 0xBC, 0xDF, 0x3E, 0xDA, 0x83, 0x14, 0x88, 0x90, 0xAD, 0x72, 0x57, 0xC0, 0x56, 0x5E, 0xB6, 
};

unsigned char auc_Device_Qy_K283[]=
{
	0x07, 0xE8, 0xFB, 0x64, 0xCC, 0x75, 0x52, 0xB9, 0x26, 0x26, 0x15, 0x46, 0x36, 0x3A, 0xB1, 0x79, 0xF3, 0xAE, 0x63, 0x5C, 0xC3, 0xB6, 0x02, 0xE3, 0x17, 0xE8, 0x6D, 0x98, 0x4F, 0x58, 0x18, 0x3D, 0x16, 0xA9, 0x1E, 0x2C, 
};

unsigned char auc_Device_D_K283[]=
{
	0x01, 0x4C, 0x9A, 0xAD, 0xEE, 0xC9, 0xBC, 0xCF, 0xD6, 0x96, 0x22, 0xCC, 0xAE, 0x68, 0x89, 0x6C, 0x63, 0xA9, 0x68, 0xB5, 0x48, 0xCF, 0x47, 0x4D, 0x4F, 0x0F, 0x9E, 0xEC, 0x62, 0x8B, 0x7E, 0x81, 0x90, 0x27, 0x2E, 0x44, 
};

unsigned char auc_CurveName_K283[] = "NIST_K283";

#else
extern unsigned char auc_Host_Qx_K283[];
extern unsigned char auc_Host_Qy_K283[];
extern unsigned char auc_Host_D_K283[];
extern unsigned char auc_Device_Qx_K283[];
extern unsigned char auc_Device_Qy_K283[];
extern unsigned char auc_Device_D_K283[];
extern unsigned char auc_CurveName_K283[];
#endif
