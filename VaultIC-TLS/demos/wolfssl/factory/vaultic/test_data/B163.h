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

//B163 Test Key Values
#ifdef DEF_VARS

//Host Keypair
unsigned char auc_Host_Qx_B163[]=
{
    0x00, 0x00, 0x00, 0x01, 0x26, 0x5A, 0xB6, 0x3C, 0xCD, 0x6F, 0x5B, 0x80, 0xB6, 0x52, 0xA4, 0xF4, 0x2C, 0x7B, 0x51, 0x63, 0xE1, 0x26, 0x10, 0x64, 
};

unsigned char auc_Host_Qy_B163[]=
{
    0x00, 0x00, 0x00, 0x02, 0xB3, 0x72, 0xB4, 0xF6, 0x98, 0x32, 0x7A, 0xEE, 0xF6, 0xA7, 0x68, 0xCF, 0x66, 0xD3, 0x19, 0x10, 0x82, 0x2A, 0xD7, 0x99, 
};

unsigned char auc_Host_D_B163[]=
{
    0x00, 0x00, 0x00, 0x00, 0x55, 0x19, 0x3F, 0x45, 0xF5, 0x12, 0x7F, 0xEA, 0xFC, 0xC7, 0x6C, 0x6B, 0x0B, 0x76, 0xB6, 0x41, 0xE0, 0x61, 0x8D, 0x75, 
};

//Device Keypair
unsigned char auc_Device_Qx_B163[]=
{
    0x00, 0x00, 0x00, 0x06, 0xA2, 0x72, 0x56, 0x76, 0x83, 0x16, 0x56, 0x42, 0x04, 0xA1, 0xEC, 0x6E, 0xC2, 0xEA, 0x41, 0xAE, 0x70, 0x18, 0x44, 0x4E, 
};

unsigned char auc_Device_Qy_B163[]=
{
    0x00, 0x00, 0x00, 0x03, 0x20, 0x48, 0x0C, 0x88, 0x3F, 0xE1, 0xC3, 0xC6, 0x71, 0x4F, 0xB2, 0x0A, 0xC6, 0x63, 0xBA, 0xCA, 0x91, 0xF2, 0x67, 0x62, 
};

unsigned char auc_Device_D_B163[]=
{
    0x00, 0x00, 0x00, 0x00, 0x0A, 0x84, 0xA0, 0x74, 0xE6, 0xD7, 0x1E, 0xCC, 0x11, 0x75, 0x42, 0xC5, 0xF8, 0x6D, 0x96, 0xA7, 0x68, 0xD8, 0x90, 0xD1, 
};

unsigned char auc_CurveName_B163[] = "NIST_B163";

#else
extern unsigned char auc_Host_Qx_B163[];
extern unsigned char auc_Host_Qy_B163[];
extern unsigned char auc_Host_D_B163[];
extern unsigned char auc_Device_Qx_B163[];
extern unsigned char auc_Device_Qy_B163[];
extern unsigned char auc_Device_D_B163[];
extern unsigned char auc_CurveName_B163[];
#endif
