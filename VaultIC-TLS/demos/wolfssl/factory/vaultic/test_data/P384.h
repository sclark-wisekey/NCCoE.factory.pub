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

//P384 Test Keys Value
#ifdef DEF_VARS

//Host Keypair
unsigned char auc_Host_Qx_P384[]=
{
    0x46, 0x5E, 0x59, 0x05, 0x9E, 0xCB, 0xA7, 0xE6, 0x0C, 0x82, 0xAF, 0x19, 0x68, 0xCF, 0x0C, 0x3F, 0x65, 0x7C, 0x60, 0xAC, 0xA5, 0xF1, 0x54, 0x12, 0xE3, 0xA8, 0xF7, 0x28, 0x83, 0x81, 0x51, 0x36, 0xCC, 0xF9, 0x2F, 0xD8, 0xED, 0x99, 0x08, 0x6A, 0x40, 0x71, 0x58, 0x9F, 0x9F, 0x2A, 0xAB, 0xBF
};

unsigned char auc_Host_Qy_P384[]=
{
    0xF4, 0x97, 0x6B, 0x4C, 0xF2, 0x26, 0x4F, 0xD7, 0x67, 0x6B, 0x82, 0xC5, 0x0D, 0xDA, 0x28, 0x4D, 0x69, 0xA4, 0x71, 0x3F, 0x86, 0x83, 0x14, 0x5F, 0x66, 0x56, 0x87, 0xCF, 0x12, 0xE9, 0x25, 0x44, 0xF2, 0x79, 0xB7, 0xAB, 0x9D, 0xC0, 0xD1, 0x10, 0x0B, 0x1A, 0x62, 0x7C, 0x29, 0xFE, 0xF1, 0xEE
};

unsigned char auc_Host_D_P384[]=
{
    0x9A, 0xE1, 0xA4, 0x53, 0x78, 0x65, 0x57, 0x0F, 0xED, 0x38, 0x1A, 0xD1, 0xF4, 0xAD, 0x4E, 0xE2, 0x7D, 0x41, 0x3F, 0xA3, 0x7F, 0x97, 0xE6, 0x54, 0x2C, 0x10, 0xE0, 0xB2, 0x23, 0x0A, 0xD6, 0x81, 0xA4, 0x6E, 0xCC, 0x0B, 0xD1, 0x5C, 0x09, 0xF3, 0x73, 0x37, 0xDF, 0x3E, 0x65, 0x30, 0x07, 0x2D
};

//Device Keypair
unsigned char auc_Device_Qx_P384[]=
{
    0x18, 0x29, 0x9F, 0xBF, 0xD8, 0x88, 0xEA, 0x05, 0x0B, 0x59, 0x97, 0x67, 0xE0, 0x19, 0xC0, 0xA6, 0x7C, 0x4F, 0xCA, 0xE0, 0xF0, 0x36, 0x76, 0xA1, 0x97, 0x4A, 0xB3, 0x92, 0xCE, 0xAB, 0xB6, 0x2C, 0xE0, 0xA7, 0xAC, 0x06, 0xE5, 0x56, 0x9D, 0xBC, 0x86, 0xB7, 0x56, 0xD3, 0xF7, 0x1E, 0x70, 0xA3
};

unsigned char auc_Device_Qy_P384[]=
{
    0x53, 0x65, 0xC4, 0x9D, 0x24, 0xD9, 0x6E, 0xF8, 0x2E, 0x05, 0x49, 0x73, 0x2F, 0xD8, 0x11, 0x7D, 0x93, 0x37, 0x1A, 0x69, 0x0B, 0x94, 0xD6, 0x62, 0x30, 0x47, 0xB6, 0x33, 0x47, 0xEE, 0xE8, 0xE9, 0xFD, 0x77, 0x83, 0xA3, 0xD7, 0xC5, 0x40, 0x6A, 0x85, 0x1F, 0x5F, 0x14, 0x11, 0xB0, 0x83, 0x28
};

unsigned char auc_Device_D_P384[]=
{
    0xAB, 0x3D, 0xBA, 0x0F, 0x88, 0x90, 0x8A, 0x22, 0x06, 0xCA, 0x5B, 0x6D, 0xC8, 0x74, 0xF6, 0x93, 0x4B, 0x3C, 0xA9, 0x87, 0x84, 0x1A, 0xA0, 0xA1, 0x1F, 0x0D, 0xFE, 0x6E, 0xC9, 0x3B, 0x27, 0xF4, 0x30, 0xDD, 0x17, 0xE8, 0x5D, 0xD1, 0xBF, 0xE5, 0x90, 0x98, 0x02, 0x40, 0x0F, 0xAD, 0x55, 0xE4
};

unsigned char auc_CurveName_P384[] = "NIST_P384";

#else
extern unsigned char auc_Host_Qx_P384[];
extern unsigned char auc_Host_Qy_P384[];
extern unsigned char auc_Host_D_P384[];
extern unsigned char auc_Device_Qx_P384[];
extern unsigned char auc_Device_Qy_P384[];
extern unsigned char auc_Device_D_P384[];
extern unsigned char auc_CurveName_P384[];
#endif
