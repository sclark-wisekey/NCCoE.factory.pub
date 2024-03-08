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

//P224 Test Keys Value
#ifdef DEF_VARS

//Host Keypair
unsigned char auc_Host_Qx_P224[]=
{
    0xA8, 0x6E, 0x5B, 0xDA, 0x80, 0x7F, 0xF9, 0x34, 0xF4, 0x66, 0x97, 0x1C, 0xCD, 0x9D, 0xDC, 0xD7, 0xBF, 0x61, 0x11, 0xD1, 0x19, 0x40, 0x37, 0x7A, 0x22, 0x71, 0xA1, 0xAE
};

unsigned char auc_Host_Qy_P224[]=
{
    0x90, 0x8C, 0x5D, 0x8C, 0xBF, 0xE1, 0x29, 0x07, 0xB8, 0xA5, 0xDE, 0xB5, 0x89, 0x8F, 0x41, 0x62, 0x92, 0x42, 0x9C, 0x87, 0x2E, 0xCD, 0x61, 0x9D, 0xEA, 0xF0, 0x17, 0xBF
};

unsigned char auc_Host_D_P224[]=
{
    0x77, 0x55, 0x21, 0x65, 0xA5, 0x24, 0xA1, 0x57, 0x3F, 0xB8, 0x9E, 0xA2, 0x1F, 0xD4, 0xD8, 0xE6, 0xA8, 0x98, 0xB0, 0x4C, 0x86, 0x46, 0x1B, 0x71, 0x54, 0x4C, 0x38, 0x6D
};

//Device Keypair
unsigned char auc_Device_Qx_P224[]=
{
    0xE7, 0xB4, 0x3F, 0x86, 0xE2, 0x56, 0x2E, 0x23, 0x05, 0x02, 0x86, 0x3A, 0x4B, 0x59, 0xBB, 0xCC, 0x28, 0x0C, 0x1A, 0x53, 0x04, 0x8C, 0x3A, 0x5C, 0xC9, 0x3A, 0x5F, 0x05
};

unsigned char auc_Device_Qy_P224[]=
{
    0x40, 0x29, 0x62, 0xD0, 0xCC, 0xBB, 0xF7, 0xC9, 0xBD, 0x6B, 0x62, 0xE5, 0xE5, 0x26, 0xA9, 0x32, 0xAB, 0x98, 0xD5, 0x90, 0x54, 0x03, 0x4B, 0x14, 0xFC, 0x70, 0xB4, 0x5B
};

unsigned char auc_Device_D_P224[]=
{
    0xCF, 0xB8, 0x06, 0x8A, 0xF1, 0x2C, 0xB0, 0x30, 0x64, 0xD3, 0x16, 0x3F, 0xEA, 0x3E, 0xE0, 0x4F, 0x0D, 0xA7, 0xE0, 0x1B, 0xC9, 0x56, 0x34, 0x5C, 0x4F, 0x86, 0x06, 0x17
};

unsigned char auc_CurveName_P224[] = "NIST_P224";

#else
extern unsigned char auc_Host_Qx_P224[];
extern unsigned char auc_Host_Qy_P224[];
extern unsigned char auc_Host_D_P224[];
extern unsigned char auc_Device_Qx_P224[];
extern unsigned char auc_Device_Qy_P224[];
extern unsigned char auc_Device_D_P224[];
extern unsigned char auc_CurveName_P224[];
#endif
