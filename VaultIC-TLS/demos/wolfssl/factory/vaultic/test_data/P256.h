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

//P256 Test Keys Value
#ifdef DEF_VARS

//Host Keypair
unsigned char auc_Host_Qx_P256[]=
{
    0x25, 0x64, 0xA6, 0x95, 0xFD, 0xCB, 0xEE, 0xAC, 0x8D, 0x73, 0x34, 0x6D, 0x26, 0xF6, 0xB7, 0x23, 0xE5, 0xFD, 0x47, 0xF9, 0x40, 0x7B, 0xDF, 0x3E, 0x0C, 0xFE, 0x25, 0x4A, 0xCE, 0xEE, 0xA5, 0xE0
};

unsigned char auc_Host_Qy_P256[]=
{
    0x1C, 0x5F, 0x1C, 0x77, 0x2B, 0xFD, 0x79, 0xA2, 0x6F, 0x80, 0x2A, 0xC4, 0x20, 0x0E, 0xC0, 0x72, 0x51, 0x3E, 0xF9, 0x36, 0xE1, 0x9E, 0x3B, 0x3A, 0xBA, 0x12, 0x1D, 0x5E, 0x9D, 0x55, 0xC8, 0xA9
};

unsigned char auc_Host_D_P256[]=
{
    0xD3, 0x61, 0xEF, 0xD9, 0x76, 0xE9, 0xBB, 0x11, 0x06, 0xBF, 0x56, 0xA9, 0x77, 0xCC, 0x06, 0x9E, 0x5D, 0x46, 0x02, 0xFC, 0x93, 0xA4, 0x91, 0x19, 0xE1, 0x4B, 0xFD, 0x2A, 0x87, 0xC8, 0x05, 0x10
};

//Device Keypair
unsigned char auc_Device_Qx_P256[]=
{
    0xC9, 0x99, 0xCE, 0x5A, 0x7B, 0x5D, 0x33, 0xC6, 0x53, 0x16, 0x30, 0xC6, 0xD0, 0xEF, 0x74, 0x25, 0x4F, 0xA4, 0xA6, 0x72, 0x44, 0xAA, 0x57, 0xFD, 0x4F, 0x75, 0xC8, 0xF6, 0x0A, 0xAC, 0xBF, 0x27
};

unsigned char auc_Device_Qy_P256[]=
{
    0xE4, 0xFC, 0xBF, 0xF9, 0x7B, 0x56, 0x21, 0x1C, 0x87, 0x45, 0x7E, 0xC2, 0x65, 0xB8, 0x4D, 0x37, 0x23, 0x5E, 0x23, 0x18, 0x56, 0x20, 0x99, 0xCF, 0x94, 0x22, 0xE5, 0x3D, 0xD0, 0x5E, 0xC3, 0x43
};

unsigned char auc_Device_D_P256[]=
{
    0xA2, 0x9C, 0xD8, 0x80, 0x73, 0x1F, 0x03, 0x85, 0x93, 0xCF, 0x57, 0x12, 0x25, 0x87, 0x94, 0xD3, 0x0D, 0x19, 0xE1, 0xE7, 0x04, 0xF8, 0x09, 0xBD, 0xE4, 0x87, 0x09, 0xC9, 0xE9, 0xFF, 0xAA, 0xC1
};

unsigned char auc_CurveName_P256[] = "NIST_P256";

#else
extern unsigned char auc_Host_Qx_P256[];
extern unsigned char auc_Host_Qy_P256[];
extern unsigned char auc_Host_D_P256[];
extern unsigned char auc_Device_Qx_P256[];
extern unsigned char auc_Device_Qy_P256[];
extern unsigned char auc_Device_D_P256[];
extern unsigned char auc_CurveName_P256[];
#endif
