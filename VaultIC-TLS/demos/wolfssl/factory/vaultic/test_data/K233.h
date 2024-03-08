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

//K233 Test Key Values
#ifdef DEF_VARS

//Host Keypair
unsigned char auc_Host_Qx_K233[]=
{
	0x00, 0x00, 0x01, 0x42, 0x62, 0x64, 0x59, 0x42, 0x9E, 0x22, 0x4D, 0xB5, 0x7A, 0x97, 0x17, 0x1E, 0x6D, 0xE5, 0x0E, 0x58, 0x2F, 0xBC, 0xBA, 0x2C, 0x3C, 0x33, 0xC7, 0x53, 0xCE, 0xE4, 0xAA, 0x36, 
};

unsigned char auc_Host_Qy_K233[]=
{
	0x00, 0x00, 0x01, 0x1A, 0x71, 0x9B, 0x7D, 0x68, 0xC8, 0x6A, 0x4D, 0xA7, 0xA2, 0x3E, 0xA5, 0xAD, 0x45, 0x6C, 0x34, 0xD1, 0x38, 0x26, 0x45, 0x9E, 0x89, 0x1F, 0x43, 0x42, 0x42, 0x70, 0x50, 0x81, 
};

unsigned char auc_Host_D_K233[]=
{
	0x00, 0x00, 0x00, 0x5E, 0x2D, 0xBA, 0xF8, 0x8F, 0x0E, 0xC4, 0x8B, 0xAE, 0x43, 0x70, 0xD5, 0xC9, 0x00, 0x61, 0x46, 0x05, 0x85, 0xC4, 0xD0, 0x8B, 0x1B, 0x41, 0xDC, 0x0C, 0xAE, 0xB2, 0x19, 0x75, 
};

//Device Keypair
unsigned char auc_Device_Qx_K233[]=
{
	0x00, 0x00, 0x00, 0xCA, 0x20, 0x23, 0xAC, 0x47, 0xD4, 0x11, 0x47, 0x39, 0x22, 0x9E, 0x2E, 0x60, 0xFB, 0x08, 0x61, 0x3C, 0x82, 0xD1, 0xB9, 0xDA, 0xD7, 0x37, 0x4D, 0xCB, 0x35, 0x98, 0xC6, 0x74, 
};

unsigned char auc_Device_Qy_K233[]=
{
	0x00, 0x00, 0x01, 0xB7, 0xBA, 0xEA, 0x45, 0x20, 0x3E, 0x51, 0x13, 0x01, 0xFE, 0x43, 0x96, 0x8A, 0x4D, 0x8C, 0xEB, 0x1A, 0x29, 0x03, 0x77, 0x8D, 0x38, 0x44, 0x76, 0x3C, 0x1F, 0x66, 0x29, 0x85, 
};

unsigned char auc_Device_D_K233[]=
{
	0x00, 0x00, 0x00, 0x60, 0xAE, 0x3A, 0xCA, 0x3D, 0x99, 0x22, 0x72, 0x3E, 0xC3, 0x8B, 0x58, 0xBC, 0x66, 0x7C, 0x1F, 0xDC, 0x8F, 0xE0, 0xC1, 0x6A, 0xD3, 0xD7, 0x0F, 0x02, 0x30, 0x07, 0x68, 0x3A, 
};

unsigned char auc_CurveName_K233[] = "NIST_K233";

#else
extern unsigned char auc_Host_Qx_K233[];
extern unsigned char auc_Host_Qy_K233[];
extern unsigned char auc_Host_D_K233[];
extern unsigned char auc_Device_Qx_K233[];
extern unsigned char auc_Device_Qy_K233[];
extern unsigned char auc_Device_D_K233[];
extern unsigned char auc_CurveName_K233[];
#endif
