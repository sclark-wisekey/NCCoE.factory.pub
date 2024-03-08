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

//K163 Test Key Values
#ifdef DEF_VARS

//Host Keypair
unsigned char auc_Host_Qx_K163[]=
{
	0x00, 0x00, 0x00, 0x05, 0x3A, 0x54, 0xEE, 0x84, 0xB1, 0x8E, 0x63, 0x0E, 0x34, 0x79, 0xBC, 0xC7, 0xC9, 0xB3, 0xB4, 0xEB, 0xDA, 0x64, 0xE3, 0xE2, 
};

unsigned char auc_Host_Qy_K163[]=
{
	0x00, 0x00, 0x00, 0x07, 0x8D, 0x60, 0x0E, 0x78, 0xB7, 0xCA, 0x0D, 0x5F, 0x33, 0x28, 0x13, 0xC1, 0x0B, 0xCC, 0x05, 0x2B, 0xB9, 0xE7, 0x9E, 0x93, 
};

unsigned char auc_Host_D_K163[]=
{
	0x00, 0x00, 0x00, 0x00, 0x9C, 0x81, 0x6E, 0x8D, 0x0B, 0xD6, 0x6B, 0x9D, 0x1B, 0x6D, 0x7D, 0x37, 0x3A, 0x37, 0x8C, 0x24, 0x19, 0xA8, 0xB1, 0xF0, 
};

//Device Keypair
unsigned char auc_Device_Qx_K163[]=
{
	0x00, 0x00, 0x00, 0x02, 0x0D, 0x17, 0x72, 0x81, 0x40, 0x1F, 0x5D, 0x6F, 0x55, 0xC9, 0xDA, 0xAD, 0xD7, 0x7C, 0x9C, 0x1F, 0xDD, 0xBF, 0x4E, 0x1F, 
};

unsigned char auc_Device_Qy_K163[]=
{
	0x00, 0x00, 0x00, 0x00, 0x4A, 0xC3, 0xF9, 0x25, 0x61, 0xE8, 0xB9, 0xCD, 0x74, 0xE7, 0x08, 0xB9, 0xD9, 0xB9, 0xEB, 0x18, 0x2B, 0x79, 0xD9, 0x98, 
};

unsigned char auc_Device_D_K163[]=
{
	0x00, 0x00, 0x00, 0x03, 0xB5, 0x5C, 0x5E, 0xB2, 0x9E, 0x44, 0x9D, 0x15, 0x6F, 0x5D, 0x0A, 0x78, 0x1C, 0xAD, 0xF0, 0x70, 0x89, 0x72, 0x58, 0x1C, 
};

unsigned char auc_CurveName_K163[] = "NIST_K163";

#else
extern unsigned char auc_Host_Qx_K163[];
extern unsigned char auc_Host_Qy_K163[];
extern unsigned char auc_Host_D_K163[];
extern unsigned char auc_Device_Qx_K163[];
extern unsigned char auc_Device_Qy_K163[];
extern unsigned char auc_Device_D_K163[];
extern unsigned char auc_CurveName_K163[];
#endif
