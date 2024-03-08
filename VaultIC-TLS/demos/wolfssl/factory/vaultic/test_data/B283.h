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

//B283 Test Key Values
#ifdef DEF_VARS

//Host Keypair
unsigned char auc_Host_Qx_B283[]=
{
    0x03, 0xA3, 0x75, 0x17, 0x3D, 0xE1, 0xE0, 0x55, 0x35, 0xC4, 0xBB, 0xAF, 0x5A, 0xE3, 0x31, 0x63, 0x8E, 0x6A, 0xB2, 0x3B, 0x84, 0xB7, 0x3E, 0x9F, 0x4A, 0xF6, 0x62, 0xAC, 0x2E, 0xBD, 0x4F, 0xDB, 0xC7, 0xC0, 0x7A, 0xA5, 
};

unsigned char auc_Host_Qy_B283[]=
{
    0x06, 0x59, 0xA3, 0xF8, 0xDB, 0x58, 0xE7, 0x44, 0x76, 0xC5, 0x93, 0xD4, 0x89, 0x5A, 0x50, 0x80, 0x58, 0xC1, 0x58, 0xA4, 0x08, 0xBC, 0x39, 0x21, 0x04, 0x7D, 0x14, 0xD6, 0x75, 0xEF, 0xCF, 0xB1, 0xEB, 0x57, 0x8A, 0xD5, 
};

unsigned char auc_Host_D_B283[]=
{
    0x01, 0x95, 0x96, 0x67, 0x1A, 0xED, 0x84, 0x04, 0xC8, 0x0E, 0x53, 0x88, 0x15, 0x78, 0xEF, 0x2A, 0x24, 0xAA, 0x41, 0x1E, 0x20, 0xD4, 0x85, 0xAE, 0x4E, 0x78, 0xD9, 0x7A, 0x14, 0xB1, 0xB6, 0x24, 0x1D, 0x79, 0x7C, 0x76, 
};

//Device Keypair
unsigned char auc_Device_Qx_B283[]=
{
    0x04, 0xC8, 0x05, 0x77, 0xD2, 0x98, 0x75, 0x4C, 0x3C, 0x12, 0x30, 0x0E, 0x2B, 0xBF, 0xA0, 0x64, 0x27, 0xDE, 0x6A, 0x08, 0x17, 0x74, 0xF1, 0xBB, 0x1F, 0x59, 0xEB, 0x3D, 0x4B, 0x77, 0x18, 0x97, 0xBE, 0x19, 0x49, 0x53, 
};

unsigned char auc_Device_Qy_B283[]=
{
    0x00, 0x12, 0x39, 0x9F, 0xC0, 0x0B, 0x0B, 0xA1, 0xA9, 0x08, 0x30, 0x07, 0x93, 0x1D, 0x66, 0xCB, 0xF4, 0xD7, 0x38, 0x4C, 0xDF, 0xBE, 0x78, 0xA1, 0x03, 0x56, 0xA4, 0x04, 0xAB, 0xA0, 0x76, 0xD8, 0x9F, 0xC6, 0x83, 0xB1, 
};

unsigned char auc_Device_D_B283[]=
{
    0x00, 0x7D, 0xBD, 0x00, 0x67, 0x14, 0x90, 0x2E, 0xC1, 0x78, 0x24, 0x4E, 0x27, 0x1B, 0x53, 0xBE, 0x4F, 0x43, 0x7C, 0x5A, 0xCC, 0xD7, 0x2F, 0xC9, 0x82, 0xA7, 0xAD, 0x7F, 0xA1, 0x2A, 0x12, 0xF2, 0xF0, 0xD5, 0xDF, 0xD7, 
};

unsigned char auc_CurveName_B283[] = "NIST_B283";

#else
extern unsigned char auc_Host_Qx_B283[];
extern unsigned char auc_Host_Qy_B283[];
extern unsigned char auc_Host_D_B283[];
extern unsigned char auc_Device_Qx_B283[];
extern unsigned char auc_Device_Qy_B283[];
extern unsigned char auc_Device_D_B283[];
extern unsigned char auc_CurveName_B283[];
#endif
