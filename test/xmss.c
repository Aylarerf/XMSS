#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>


#include "../xmss.h"
#include "../params.h"
#include "../randombytes.h"

#define XMSS_MLEN 32

#ifndef XMSS_SIGNATURES
    #define XMSS_SIGNATURES 16
#endif

#ifdef XMSSMT
    #define XMSS_PARSE_OID xmssmt_parse_oid
    #define XMSS_STR_TO_OID xmssmt_str_to_oid
    #define XMSS_KEYPAIR xmssmt_keypair
    #define XMSS_SIGN xmssmt_sign
    #define XMSS_SIGN_OPEN xmssmt_sign_open
    #define XMSS_VARIANT "XMSSMT-SHA2_20/2_256"
#else
    #define XMSS_PARSE_OID xmss_parse_oid
    #define XMSS_STR_TO_OID xmss_str_to_oid
    #define XMSS_KEYPAIR xmss_keypair
    #define XMSS_SIGN xmss_sign
    #define XMSS_SIGN_OPEN xmss_sign_open
    #define XMSS_VARIANT "XMSS-SHA2_10_256"
#endif

int main()
{
    xmss_params params;
    uint32_t oid;
    int ret = 0;
    int i,j;
	clock_t t1,t2;

    // TODO test more different variants
    XMSS_STR_TO_OID(&oid, XMSS_VARIANT);
    XMSS_PARSE_OID(&params, oid);

    unsigned char pk[XMSS_OID_LEN + params.pk_bytes];
    unsigned char sk[XMSS_OID_LEN + params.sk_bytes];
    unsigned char *m = malloc(XMSS_MLEN);
    unsigned char *sm = malloc(params.sig_bytes + XMSS_MLEN);
    unsigned char *mout = malloc(params.sig_bytes + XMSS_MLEN);
    unsigned long long smlen;
    unsigned long long mlen;

    randombytes(m, XMSS_MLEN);

    t1 = clock();
    xmss_keypair(pk, sk, oid);
    t2 = clock() - t1;
    printf("Key Generation Time for 1 iteration :: %lfs\n",(double)t2/CLOCKS_PER_SEC);

   

   t1 = clock();
   xmss_sign(sk, sm, &smlen, m, XMSS_MLEN);
    t2 = clock() - t1;
    printf("signing Time for 1 iteration :: %lfs\n",(double)t2/CLOCKS_PER_SEC);

    
 t1 = clock();
 xmss_sign_open(mout, &mlen, sm, smlen, pk)
 t2 = clock() - t1;
 printf("signing Time for 1 iteration :: %lfs\n",(double)t2/CLOCKS_PER_SEC);
     
     
     

        
        

        



   
