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

//P192 Test Keys Value
#ifdef DEF_VARS

//Host Keypair
unsigned char auc_Host_Qx_P192[]=
{
    0x72, 0x8E, 0x36, 0x01, 0xDE, 0x1A, 0x63, 0xD6, 0xBB, 0x5F, 0x1B, 0xB5, 0xF3, 0xB5, 0x2C, 0x79, 0xED, 0x1D, 0x63, 0x82, 0xC6, 0x8B, 0x37, 0xBF
};

unsigned char auc_Host_Qy_P192[]=
{
    0x58, 0xE8, 0x37, 0x4F, 0xC9, 0xF5, 0x0C, 0x88, 0x50, 0xC7, 0x57, 0x17, 0xD9, 0x81, 0xED, 0x4D, 0xB5, 0x8E, 0x6D, 0xC0, 0x50, 0xBD, 0xDA, 0xA6
};

unsigned char auc_Host_D_P192[]=
{
    0xF8, 0x82, 0x38, 0x38, 0x90, 0x29, 0x00, 0x59, 0x5F, 0x79, 0xA0, 0x66, 0xFC, 0x7E, 0xF0, 0x7C, 0x93, 0xA1, 0x7F, 0x16, 0x73, 0xD0, 0x0C, 0x96
};

//Device Keypair
unsigned char auc_Device_Qx_P192[]=
{
    0x5A, 0xCD, 0xBF, 0x07, 0xA5, 0xD1, 0x19, 0x25, 0xD2, 0xCE, 0x40, 0x20, 0xF7, 0xBC, 0x39, 0x8C, 0x2D, 0x01, 0x0A, 0x74, 0xA9, 0x31, 0x3B, 0xC9
};

unsigned char auc_Device_Qy_P192[]=
{
    0xCF, 0xC4, 0x5E, 0xF2, 0xF1, 0x37, 0xB3, 0x15, 0x0A, 0x28, 0x53, 0xC5, 0xDF, 0x7F, 0x25, 0xF4, 0x40, 0x7E, 0x8B, 0xFF, 0xFA, 0x44, 0x89, 0x20
};

unsigned char auc_Device_D_P192[]=
{
    0xFB, 0x83, 0x46, 0x9F, 0x21, 0xDB, 0x05, 0x3C, 0xF1, 0x8B, 0x2F, 0x18, 0xD6, 0x5C, 0x4C, 0xE1, 0xEE, 0x29, 0xA0, 0x82, 0x51, 0xE4, 0x65, 0x75
};

unsigned char auc_CurveName_P192[] = "NIST_P192";

#else

extern unsigned char auc_Host_Qx_P192[];
extern unsigned char auc_Host_Qy_P192[];
extern unsigned char auc_Host_D_P192[];
extern unsigned char auc_Device_Qx_P192[];
extern unsigned char auc_Device_Qy_P192[];
extern unsigned char auc_Device_D_P192[];
extern unsigned char auc_CurveName_P192[];
#endif
