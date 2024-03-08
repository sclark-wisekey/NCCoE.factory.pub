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

//B233 Test Key Values
#ifdef DEF_VARS

//Host Keypair
unsigned char auc_Host_Qx_B233[]=
{
    0x00, 0x00, 0x00, 0x9B, 0x18, 0x3A, 0xB6, 0x2F, 0x9B, 0x01, 0x0C, 0x4D, 0x27, 0xC9, 0x75, 0xFC, 0x92, 0xDE, 0x63, 0x10, 0x45, 0x33, 0x3E, 0x48, 0x87, 0x10, 0xAD, 0x21, 0x22, 0x82, 0xA3, 0x7D, 
};

unsigned char auc_Host_Qy_B233[]=
{
    0x00, 0x00, 0x00, 0xF0, 0x85, 0x9E, 0x8F, 0x10, 0x61, 0xE1, 0xD5, 0x3B, 0x89, 0xCF, 0x93, 0x22, 0xFD, 0xBC, 0x99, 0xA1, 0x4A, 0x5E, 0x3C, 0x11, 0xD0, 0xAA, 0x6E, 0xEB, 0x41, 0xCC, 0xF6, 0xCB, 
};

unsigned char auc_Host_D_B233[]=
{
    0x00, 0x00, 0x00, 0xA0, 0xB6, 0x7A, 0x3A, 0x0B, 0x62, 0x17, 0x40, 0xA6, 0x7C, 0xC6, 0x77, 0x60, 0x19, 0xA6, 0xC4, 0x93, 0x22, 0xBF, 0x7D, 0x5B, 0x3A, 0x4A, 0xB8, 0xA6, 0xCB, 0xD2, 0x99, 0x06, 
};

//Device Keypair
unsigned char auc_Device_Qx_B233[]=
{
    0x00, 0x00, 0x01, 0x2E, 0xE2, 0xD7, 0x5B, 0xB9, 0x47, 0xB0, 0xE1, 0x6C, 0xFE, 0x25, 0x18, 0xF4, 0xF5, 0xEF, 0xE6, 0x00, 0xE8, 0xBD, 0x51, 0xFC, 0xA6, 0xA6, 0x57, 0xEA, 0xB3, 0x4B, 0x88, 0xC0, 
};

unsigned char auc_Device_Qy_B233[]=
{
    0x00, 0x00, 0x00, 0x0A, 0xAC, 0x92, 0x16, 0x1A, 0x25, 0x6A, 0x75, 0xAF, 0x1E, 0x0C, 0x8D, 0xD2, 0x1F, 0xCE, 0x1D, 0x06, 0xB1, 0x1E, 0xE5, 0x04, 0x53, 0x2E, 0xBE, 0xFE, 0xE7, 0xC2, 0xB6, 0xB1, 
};

unsigned char auc_Device_D_B233[]=
{
    0x00, 0x00, 0x00, 0x98, 0x63, 0x5E, 0x82, 0x24, 0xB0, 0x68, 0x90, 0x72, 0x33, 0x1D, 0xCE, 0xFF, 0x6E, 0xC8, 0x4B, 0xE2, 0xD3, 0xCE, 0x68, 0x58, 0xD5, 0xAF, 0xDC, 0x28, 0x14, 0x37, 0x3A, 0x9A, 
};

unsigned char auc_CurveName_B233[] = "NIST_B233";

#else
extern unsigned char auc_Host_Qx_B233[];
extern unsigned char auc_Host_Qy_B233[];
extern unsigned char auc_Host_D_B233[];
extern unsigned char auc_Device_Qx_B233[];
extern unsigned char auc_Device_Qy_B233[];
extern unsigned char auc_Device_D_B233[];
extern unsigned char auc_CurveName_B233[];
#endif
