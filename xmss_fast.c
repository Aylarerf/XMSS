/*
xmss.c version 20150811
Andreas Hülsing
Public domain.
*/

#include "xmss_fast.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>

#include "randombytes.h"
#include "wots.h"
#include "hash.h"
#include "prg.h"
#include "xmss_commons.h"

// For testing
#include "stdio.h"

/**
 * Macros used to manipulate the respective fields
 * in the 16byte hash address
 */
#define SET_LAYER_ADDRESS(a, v) {\
  a[6] = (a[6] & 3) | ((v << 2) & 255);\
  a[5] = (a[5] & 252) | ((v >> 6) & 255);}  

#define SET_TREE_ADDRESS(a, v) {\
  a[9] = (a[9] & 3) | ((v << 2) & 255);\
  a[8] = (v >> 6) & 255;\
  a[7] = (v >> 14) & 255;\
  a[6] = (a[6] & 252) | ((v >> 22) & 255);}  
  
#define SET_OTS_BIT(a, b) {\
  a[9] = (a[9] & 253) | (b << 1);}

#define SET_OTS_ADDRESS(a, v) {\
  a[12] = (a[12] & 1) | ((v << 1) & 255);\
  a[11] = (v >> 7) & 255;\
  a[10] = (v >> 15) & 255;\
  a[9] = (a[9] & 254) | ((v >> 23) & 1);}  
  
#define ZEROISE_OTS_ADDR(a) {\
  a[12] = (a[12] & 254);\
  a[13] = 0;\
  a[14] = 0;\
  a[15] = 0;}
  
#define SET_LTREE_BIT(a, b) {\
  a[9] = (a[9] & 254) | b;}

#define SET_LTREE_ADDRESS(a, v) {\
  a[12] = v & 255;\
  a[11] = (v >> 8) & 255;\
  a[10] = (v >> 16) & 255;}

#define SET_LTREE_TREE_HEIGHT(a, v) {\
  a[13] = (a[13] & 3) | ((v << 2) & 255);}

#define SET_LTREE_TREE_INDEX(a, v) {\
  a[15] = (a[15] & 3) | ((v << 2) & 255);\
  a[14] = (v >> 6) & 255;\
  a[13] = (a[13] & 252) | ((v >> 14) & 3);}
  
#define SET_NODE_PADDING(a) {\
  a[10] = 0;\
  a[11] = a[11] & 3;}  

#define SET_NODE_TREE_HEIGHT(a, v) {\
  a[12] = (a[12] & 3) | ((v << 2) & 255);\
  a[11] = (a[11] & 252) | ((v >> 6) & 3);}

#define SET_NODE_TREE_INDEX(a, v) {\
  a[15] = (a[15] & 3) | ((v << 2) & 255);\
  a[14] = (v >> 6) & 255;\
  a[13] = (v >> 14) & 255;\
  a[12] = (a[12] & 252) | ((v >> 22) & 3);}

  /**
 * Used for pseudorandom keygeneration,
 * generates the seed for the WOTS keypair at address addr
 */
static void get_seed(unsigned char seed[32], const unsigned char *sk_seed, unsigned char addr[16])
{
  // Make sure that chain addr, hash addr, and key bit are 0!
  ZEROISE_OTS_ADDR(addr);
  // Generate pseudorandom value
  prg_with_counter(seed, 32, sk_seed, 32, addr);
}

/**
 * Initialize xmss params struct
 * parameter names are the same as in the draft
 * parameter k is K as used in the BDS algorithm
 */
void xmss_set_params(xmss_params *params, int m, int n, int h, int w, int k)
{
  params->h = h;
  params->m = m;
  params->n = n;
  params->k = k;
  wots_params wots_par;
  wots_set_params(&wots_par, m, n, w);
  params->wots_par = wots_par;
}

/**
 * Initialize BDS state struct
 * parameter names are the same as used in the description of the BDS traversal
 */
void xmss_set_bds_state(bds_state *state, unsigned char *stack, int stackoffset, unsigned char *stacklevels, unsigned char *auth, unsigned char *keep, treehash_inst *treehash, unsigned char *retain)
{
  state->stack = stack;
  state->stackoffset = stackoffset;
  state->stacklevels = stacklevels;
  state->auth = auth;
  state->keep = keep;
  state->treehash = treehash;
  state->retain = retain;
}

/**
 * Initialize xmssmt_params struct
 * parameter names are the same as in the draft
 * 
 * Especially h is the total tree height, i.e. the XMSS trees have height h/d
 */
void xmssmt_set_params(xmssmt_params *params, int m, int n, int h, int d, int w, int k)
{
  if(h % d){
    fprintf(stderr, "d must devide h without remainder!\n");
    return;
  }
  params->h = h;
  params->d = d;
  params->m = m;
  params->n = n;
  params->index_len = (h + 7) / 8;
  xmss_params xmss_par;
  xmss_set_params(&xmss_par, m, n, (h/d), w, k);
  params->xmss_par = xmss_par;
}

/**
 * Computes a leaf from a WOTS public key using an L-tree.
 */
static void l_tree(unsigned char *leaf, unsigned char *wots_pk, const xmss_params *params, const unsigned char *pub_seed, unsigned char addr[16])
{ 
  unsigned int l = params->wots_par.len;
  unsigned int n = params->n;
  unsigned long i = 0;
  unsigned int height = 0;
  
  //ADRS.setTreeHeight(0);
  SET_LTREE_TREE_HEIGHT(addr,height);
  unsigned long bound;
  while ( l > 1 ) 
  {
     bound = l >> 1; //floor(l / 2); 
     for ( i = 0; i < bound; i = i + 1 ) {
       //ADRS.setTreeIndex(i);
       SET_LTREE_TREE_INDEX(addr,i);
       //wots_pk[i] = RAND_HASH(pk[2i], pk[2i + 1], SEED, ADRS);
       hash_2n_n(wots_pk+i*n,wots_pk+i*2*n, pub_seed, addr, n);
     }
     //if ( l % 2 == 1 ) {
     if(l&1)
     {
       //pk[floor(l / 2) + 1] = pk[l];
       memcpy(wots_pk+(l>>1)*n,wots_pk+(l-1)*n, n);
       //l = ceil(l / 2);
       l=(l>>1)+1;
     }
     else
     {
       //l = ceil(l / 2);
       l=(l>>1);
     }     
     //ADRS.setTreeHeight(ADRS.getTreeHeight() + 1);
     height++;
     SET_LTREE_TREE_HEIGHT(addr,height);
   }
   //return pk[0];
   memcpy(leaf,wots_pk,n);
}

/**
 * Computes the leaf at a given address. First generates the WOTS key pair, then computes leaf using l_tree. As this happens position independent, we only require that addr encodes the right ltree-address.
 */
static void gen_leaf_wots(unsigned char *leaf, const unsigned char *sk_seed, const xmss_params *params, const unsigned char *pub_seed, unsigned char ltree_addr[16], unsigned char ots_addr[16])
{
  unsigned char seed[32];
  unsigned char pk[params->wots_par.keysize];

  get_seed(seed, sk_seed, ots_addr);
  wots_pkgen(pk, seed, &(params->wots_par), pub_seed, ots_addr);

  l_tree(leaf, pk, params, pub_seed, ltree_addr); 
}

static int treehash_minheight_on_stack(bds_state* state, const xmss_params *params, const treehash_inst *treehash) {
  int r = params->h, i;
  for (i = 0; i < treehash->stackusage; i++) {
    if (state->stacklevels[state->stackoffset - i - 1] < r) {
      r = state->stacklevels[state->stackoffset - i - 1];
    }
  }
  return r;
}

/**
 * Merkle's TreeHash algorithm. The address only needs to initialize the first 78 bits of addr. Everything else will be set by treehash.
 * Currently only used for key generation.
 * 
 */
static void treehash_setup(unsigned char *node, int height, int index, bds_state *state, const unsigned char *sk_seed, const xmss_params *params, const unsigned char *pub_seed, const unsigned char addr[16])
{
  unsigned int idx = index;
  unsigned int n = params->n;
  unsigned int h = params->h;
  unsigned int k = params->k;
  // use three different addresses because at this point we use all three formats in parallel
  unsigned char ots_addr[16];
  unsigned char ltree_addr[16];
  unsigned char node_addr[16];
  memcpy(ots_addr, addr, 10);
  SET_OTS_BIT(ots_addr, 1);
  memcpy(ltree_addr, addr, 10);
  SET_OTS_BIT(ltree_addr, 0);
  SET_LTREE_BIT(ltree_addr, 1);
  memcpy(node_addr, ltree_addr, 10);
  SET_LTREE_BIT(node_addr, 0);
  SET_NODE_PADDING(node_addr);
  
  int lastnode,i;
  unsigned char stack[(height+1)*n];
  unsigned int  stacklevels[height+1];
  unsigned int  stackoffset=0;
  
  int nodeh;

  lastnode = idx+(1<<height);

  for(i = 0; i < h-k; i++) {
    state->treehash[i].h = i;
    state->treehash[i].completed = 1;
    state->treehash[i].stackusage = 0;
  }

  i = 0;
  for(;idx<lastnode;idx++) 
  {
    SET_LTREE_ADDRESS(ltree_addr,idx);
    SET_OTS_ADDRESS(ots_addr,idx);
    gen_leaf_wots(stack+stackoffset*n,sk_seed,params, pub_seed, ltree_addr, ots_addr);
    stacklevels[stackoffset] = 0;
    stackoffset++;
    if (h - k > 0 && i == 3) {
      memcpy(state->treehash[0].node, stack+stackoffset*n, n);
    }
    while(stackoffset>1 && stacklevels[stackoffset-1] == stacklevels[stackoffset-2])
    {
      nodeh = stacklevels[stackoffset-1];
      if (i >> nodeh == 1) {
        memcpy(state->auth + nodeh*n, stack+(stackoffset-1)*n, n);
      }
      else {
        if (nodeh < h - k && i >> nodeh == 3) {
          memcpy(state->treehash[nodeh].node, stack+(stackoffset-1)*n, n);
        }
        else if (nodeh >= h - k) {
          memcpy(state->retain + ((1 << (h - 1 - nodeh)) + nodeh - h + (((i >> nodeh) - 3) >> 1)) * n, stack+(stackoffset-1)*n, n);
        }
      }
      SET_NODE_TREE_HEIGHT(node_addr,stacklevels[stackoffset-1]);
      SET_NODE_TREE_INDEX(node_addr, (idx >> (stacklevels[stackoffset-1]+1)));
      hash_2n_n(stack+(stackoffset-2)*n,stack+(stackoffset-2)*n, pub_seed,
          node_addr, n);
      stacklevels[stackoffset-2]++;
      stackoffset--;
    }
    i++;
  }

  for(i=0;i<n;i++)
    node[i] = stack[i];
}

static void treehash_update(treehash_inst *treehash, bds_state *state, const unsigned char *sk_seed, const xmss_params *params, const unsigned char *pub_seed, const unsigned char addr[16]) {
  int n = params->n;

  unsigned char ots_addr[16];
  unsigned char ltree_addr[16];
  unsigned char node_addr[16];

  memcpy(ots_addr, addr, 10);
  SET_OTS_BIT(ots_addr, 1);
  memcpy(ltree_addr, addr, 10);
  SET_OTS_BIT(ltree_addr, 0);
  SET_LTREE_BIT(ltree_addr, 1);
  memcpy(node_addr, ltree_addr, 10);
  SET_LTREE_BIT(node_addr, 0);
  SET_NODE_PADDING(node_addr);

  SET_LTREE_ADDRESS(ltree_addr, treehash->next_idx);
  SET_OTS_ADDRESS(ots_addr, treehash->next_idx);

  unsigned char nodebuffer[2 * n];
  unsigned int nodeheight = 0;
  gen_leaf_wots(nodebuffer, sk_seed, params, pub_seed, ltree_addr, ots_addr);
  while (treehash->stackusage > 0 && state->stacklevels[state->stackoffset-1] == nodeheight) {
    memcpy(nodebuffer + n, nodebuffer, n);
    memcpy(nodebuffer, state->stack + (state->stackoffset-1)*n, n);
    SET_NODE_TREE_HEIGHT(node_addr, nodeheight);
    SET_NODE_TREE_INDEX(node_addr, (treehash->next_idx >> (nodeheight+1)));
    hash_2n_n(nodebuffer, nodebuffer, pub_seed, node_addr, n);
    nodeheight++;
    treehash->stackusage--;
    state->stackoffset--;
  }
  if (nodeheight == treehash->h) { // this also implies stackusage == 0
    memcpy(treehash->node, nodebuffer, n);
    treehash->completed = 1;
  }
  else {
    memcpy(state->stack + state->stackoffset*n, nodebuffer, n);
    treehash->stackusage++;
    state->stacklevels[state->stackoffset] = nodeheight;
    state->stackoffset++;
    treehash->next_idx++;
  }
}

/**
 * Computes a root node given a leaf and an authapth
 */
static void validate_authpath(unsigned char *root, const unsigned char *leaf, unsigned long leafidx, const unsigned char *authpath, const xmss_params *params, const unsigned char *pub_seed, unsigned char addr[16])
{
  unsigned int n = params->n;
  
  int i,j;
  unsigned char buffer[2*n];

  // If leafidx is odd (last bit = 1), current path element is a right child and authpath has to go to the left.
  // Otherwise, it is the other way around
  if(leafidx&1)
  {
    for(j=0;j<n;j++)
      buffer[n+j] = leaf[j];
    for(j=0;j<n;j++)
      buffer[j] = authpath[j];
  }
  else
  {
    for(j=0;j<n;j++)
      buffer[j] = leaf[j];
    for(j=0;j<n;j++)
      buffer[n+j] = authpath[j];
  }
  authpath += n;

  for(i=0;i<params->h-1;i++)
  {
    SET_NODE_TREE_HEIGHT(addr,i);
    leafidx >>= 1;
    SET_NODE_TREE_INDEX(addr, leafidx);
    if(leafidx&1)
    {
      hash_2n_n(buffer+n,buffer,pub_seed, addr, n);
      for(j=0;j<n;j++)
        buffer[j] = authpath[j];
    }
    else
    {
      hash_2n_n(buffer,buffer,pub_seed, addr, n);
      for(j=0;j<n;j++)
        buffer[j+n] = authpath[j];
    }
    authpath += n;
  }
  SET_NODE_TREE_HEIGHT(addr, (params->h-1));
  leafidx >>= 1;
  SET_NODE_TREE_INDEX(addr, leafidx);
  hash_2n_n(root,buffer,pub_seed,addr,n);
}

/**
 * Returns the auth path for node leaf_idx and computes the auth path for the
 * next leaf node, using the algorithm described by Buchmann, Dahmen and Szydlo
 * in "Post Quantum Cryptography", Springer 2009.
 */
static void compute_authpath_wots_fast(unsigned char *root, unsigned char *authpath, unsigned long leaf_idx, bds_state *state, const unsigned char *sk_seed, const xmss_params *params, unsigned char *pub_seed, unsigned char addr[16])
{
  unsigned int i, j;
  int n = params->n;
  int h = params->h;
  int k = params->k;

  // the auth path was already computed during the previous round
  memcpy(authpath, state->auth, h*n);
  // TODO but we don't have the root handy yet.
  // memcpy(root, ???, n);

  int tau = h;
  int startidx;
  int offset, rowidx;
  int level, l_min, low;
  unsigned char buf[2 * n];

  unsigned char ots_addr[16];
  unsigned char ltree_addr[16];
  unsigned char node_addr[16];
  
  memcpy(ots_addr, addr, 10);
  SET_OTS_BIT(ots_addr, 1);
  memcpy(ltree_addr, addr, 10);
  SET_OTS_BIT(ltree_addr, 0);
  SET_LTREE_BIT(ltree_addr, 1);
  memcpy(node_addr, ltree_addr, 10);
  SET_LTREE_BIT(node_addr, 0);
  SET_NODE_PADDING(node_addr);

  for (i = 0; i < h; i++) {
    if (! ((leaf_idx >> i) & 1)) {
      tau = i;
      break;
    }
  }

  if (tau > 0) {
    memcpy(buf,     state->auth + (tau-1) * n, n);
    // we need to do this before refreshing state->keep to prevent overwriting
    memcpy(buf + n, state->keep + ((tau-1) >> 1) * n, n);
  }
  if (!((leaf_idx >> (tau + 1)) & 1) && (tau < h - 1)) {
    memcpy(state->keep + (tau >> 1)*n, state->auth + tau*n, n);
  }
  if (tau == 0) {
    SET_LTREE_ADDRESS(ltree_addr,leaf_idx);
    SET_OTS_ADDRESS(ots_addr,leaf_idx);
    gen_leaf_wots(state->auth, sk_seed, params, pub_seed, ltree_addr, ots_addr);
  }
  else {
    SET_NODE_TREE_HEIGHT(node_addr, (tau-1));
    SET_NODE_TREE_INDEX(node_addr, leaf_idx >> tau);
    hash_2n_n(state->auth + tau * n, buf, pub_seed, node_addr, n);
    for (i = 0; i < tau; i++) {
      if (i < h - k) {
        memcpy(state->auth + i * n, state->treehash[i].node, n);
      }
      else {
        offset = (1 << (h - 1 - i)) + i - h;
        rowidx = ((leaf_idx >> i) - 1) >> 1;
        memcpy(state->auth + i * n, state->retain + (offset + rowidx) * n, n);
      }
    }

    for (i = 0; i < ((tau < h - k) ? tau : (h - k)); i++) {
      startidx = leaf_idx + 1 + 3 * (1 << i);
      if (startidx < 1 << h) {
        state->treehash[i].h = i;
        state->treehash[i].next_idx = startidx;
        state->treehash[i].completed = 0;
      }
    }
  }

  for (i = 0; i < (h - k) >> 1; i++) {
    l_min = h;
    level = h - k;
    for (j = 0; j < h - k; j++) {
      if (state->treehash[j].completed) {
        low = h;
      }
      else if (state->treehash[j].stackusage == 0) {
        low = j;
      }
      else {
        low = treehash_minheight_on_stack(state, params, &(state->treehash[j]));
      }
      if (low < l_min) {
        level = j;
        l_min = low;
      }
    }
    if (level != h - k) {
      treehash_update(&(state->treehash[level]), state, sk_seed, params, pub_seed, addr);
    }
  }
}

/*
 * Generates a XMSS key pair for a given parameter set.
 * Format sk: [(32bit) idx || SK_SEED || SK_PRF || PUB_SEED]
 * Format pk: [root || PUB_SEED] omitting algo oid.
 */
int xmss_keypair(unsigned char *pk, unsigned char *sk, bds_state *state, xmss_params *params)
{
  unsigned int n = params->n;
  unsigned int m = params->m;
  // Set idx = 0
  sk[0] = 0;
  sk[1] = 0;
  sk[2] = 0;
  sk[3] = 0;
  // Init SK_SEED (n byte), SK_PRF (m byte), and PUB_SEED (n byte)
  randombytes(sk+4,2*n+m);
  // Copy PUB_SEED to public key
  memcpy(pk+n, sk+4+n+m,n);

  unsigned char addr[16] = {0,0,0,0};
  // Compute root
  treehash_setup(pk, params->h, 0, state, sk+4, params, sk+4+n+m, addr);
  return 0;
}

/**
 * Signs a message.
 * Returns 
 * 1. an array containing the signature followed by the message AND
 * 2. an updated secret key!
 * 
 */
int xmss_sign(unsigned char *sk, bds_state *state, unsigned char *sig_msg, unsigned long long *sig_msg_len, const unsigned char *msg, unsigned long long msglen, const xmss_params *params)
{
  unsigned int n = params->n;
  unsigned int m = params->m;
  
  // Extract SK
  unsigned long idx = ((unsigned long)sk[0] << 24) | ((unsigned long)sk[1] << 16) | ((unsigned long)sk[2] << 8) | sk[3];
  unsigned char sk_seed[n];
  memcpy(sk_seed,sk+4,n);
  unsigned char sk_prf[m];
  memcpy(sk_prf,sk+4+n,m);
  unsigned char pub_seed[n];
  memcpy(pub_seed,sk+4+n+m,n);  
  
  // Update SK
  sk[0] = ((idx + 1) >> 24) & 255;
  sk[1] = ((idx + 1) >> 16) & 255;
  sk[2] = ((idx + 1) >> 8) & 255;
  sk[3] = (idx + 1) & 255;
  // -- Secret key for this non-forward-secure version is now updated. 
  // -- A productive implementation should use a file handle instead and write the updated secret key at this point! 
  
  // Init working params
  unsigned long long i;
  unsigned char R[m];
  unsigned char msg_h[m];
  unsigned char root[n];
  unsigned char ots_seed[n];
  unsigned char ots_addr[16] = {0,0,0,0};
  
  // ---------------------------------
  // Message Hashing
  // ---------------------------------
  
  // Message Hash: 
  // First compute pseudorandom key
  prf_m(R, msg, msglen, sk_prf, m); 
  // Then use it for message digest
  hash_m(msg_h, msg, msglen, R, m, m);
  
  // Start collecting signature
  *sig_msg_len = 0;

  // Copy index to signature
  sig_msg[0] = (idx >> 24) & 255;
  sig_msg[1] = (idx >> 16) & 255;
  sig_msg[2] = (idx >> 8) & 255;
  sig_msg[3] = idx & 255;
  
  sig_msg += 4;
  *sig_msg_len += 4;
  
  // Copy R to signature
  for(i=0; i<m; i++)
    sig_msg[i] = R[i];

  sig_msg += m;
  *sig_msg_len += m;
  
  // ----------------------------------
  // Now we start to "really sign" 
  // ----------------------------------
  
  // Prepare Address
  SET_OTS_BIT(ots_addr,1);
  SET_OTS_ADDRESS(ots_addr,idx);
  
  // Compute seed for OTS key pair
  get_seed(ots_seed, sk_seed, ots_addr);
     
  // Compute WOTS signature
  wots_sign(sig_msg, msg_h, ots_seed, &(params->wots_par), pub_seed, ots_addr);
  
  sig_msg += params->wots_par.keysize;
  *sig_msg_len += params->wots_par.keysize;

  compute_authpath_wots_fast(root, sig_msg, idx, state, sk_seed, params, pub_seed, ots_addr);
  sig_msg += params->h*n;
  *sig_msg_len += params->h*n;
  
  //Whipe secret elements?  
  //zerobytes(tsk, CRYPTO_SECRETKEYBYTES);

  memcpy(sig_msg,msg,msglen);
  *sig_msg_len += msglen;

  return 0;
}

/**
 * Verifies a given message signature pair under a given public key.
 */
int xmss_sign_open(unsigned char *msg, unsigned long long *msglen, const unsigned char *sig_msg, unsigned long long sig_msg_len, const unsigned char *pk, const xmss_params *params)
{
  unsigned int n = params->n;
  unsigned int m = params->m;
    
  unsigned long long i, m_len;
  unsigned long idx=0;
  unsigned char wots_pk[params->wots_par.keysize];
  unsigned char pkhash[n];
  unsigned char root[n];
  unsigned char msg_h[m];
  
  unsigned char pub_seed[n];
  memcpy(pub_seed,pk+n,n);  
  
  // Init addresses
  unsigned char ots_addr[16] = {0,0,0,0};
  unsigned char ltree_addr[16];
  unsigned char node_addr[16];
  
  SET_OTS_BIT(ots_addr, 1);
  
  memcpy(ltree_addr, ots_addr, 10);
  SET_OTS_BIT(ltree_addr, 0);
  SET_LTREE_BIT(ltree_addr, 1);
  
  memcpy(node_addr, ltree_addr, 10);
  SET_LTREE_BIT(node_addr, 0);
  SET_NODE_PADDING(node_addr);  
  
  // Extract index
  idx = ((unsigned long)sig_msg[0] << 24) | ((unsigned long)sig_msg[1] << 16) | ((unsigned long)sig_msg[2] << 8) | sig_msg[3];
  printf("verify:: idx = %lu\n",idx);
  sig_msg += 4;
  sig_msg_len -= 4;
  
  // hash message (recall, R is now on pole position at sig_msg
  unsigned long long tmp_sig_len = m+params->wots_par.keysize+params->h*n;
  m_len = sig_msg_len - tmp_sig_len;
  hash_m(msg_h, sig_msg + tmp_sig_len, m_len, sig_msg, m, m);

  sig_msg += m;
  sig_msg_len -= m;
  
  //-----------------------
  // Verify signature
  //-----------------------
  
  // Prepare Address
  SET_OTS_ADDRESS(ots_addr,idx);
  // Check WOTS signature 
  wots_pkFromSig(wots_pk, sig_msg, msg_h, &(params->wots_par), pub_seed, ots_addr);

  sig_msg += params->wots_par.keysize;
  sig_msg_len -= params->wots_par.keysize;
  
  // Compute Ltree
  SET_LTREE_ADDRESS(ltree_addr, idx); 
  l_tree(pkhash, wots_pk, params, pub_seed, ltree_addr);
  
  // Compute root
  validate_authpath(root, pkhash, idx, sig_msg, params, pub_seed, node_addr);  

  sig_msg += params->h*n;
  sig_msg_len -= params->h*n;
  
  for(i=0;i<n;i++)
    if(root[i] != pk[i])
      goto fail;
  
  *msglen = sig_msg_len;
  for(i=0;i<*msglen;i++)
    msg[i] = sig_msg[i];

  return 0;
  
  
fail:
  *msglen = sig_msg_len;
  for(i=0;i<*msglen;i++)
    msg[i] = 0;
  *msglen = -1;
  return -1;
}

/*
 * Generates a XMSSMT key pair for a given parameter set.
 * Format sk: [(ceil(h/8) bit) idx || SK_SEED || SK_PRF || PUB_SEED]
 * Format pk: [root || PUB_SEED] omitting algo oid.
 */
int xmssmt_keypair(unsigned char *pk, unsigned char *sk, bds_state *state, xmssmt_params *params)
{
  unsigned int n = params->n;
  unsigned int m = params->m;
  unsigned int i;
  // Set idx = 0
  for (i = 0; i < params->index_len; i++){
    sk[i] = 0;
  }
  // Init SK_SEED (n byte), SK_PRF (m byte), and PUB_SEED (n byte)
  randombytes(sk+params->index_len,2*n+m);
  // Copy PUB_SEED to public key
  memcpy(pk+n, sk+params->index_len+n+m,n);

  // Set address to point on the single tree on layer d-1
  unsigned char addr[16] = {0,0,0,0};
  SET_LAYER_ADDRESS(addr, (params->d-1));
  
  // Compute root
  treehash_setup(pk, params->xmss_par.h, 0, state, sk+params->index_len, &(params->xmss_par), pk+n, addr);
  return 0;
}

/**
 * Signs a message.
 * Returns 
 * 1. an array containing the signature followed by the message AND
 * 2. an updated secret key!
 * 
 */
int xmssmt_sign(unsigned char *sk, bds_state *state, unsigned char *sig_msg, unsigned long long *sig_msg_len, const unsigned char *msg, unsigned long long msglen, const xmssmt_params *params)
{
  unsigned int n = params->n;
  unsigned int m = params->m;
  unsigned int tree_h = params->xmss_par.h;
  unsigned int idx_len = params->index_len;
  unsigned long long idx_tree;
  unsigned long long idx_leaf;
  unsigned long long i;
  
  unsigned char sk_seed[n];
  unsigned char sk_prf[m];
  unsigned char pub_seed[n];
  // Init working params
  unsigned char R[m];
  unsigned char msg_h[m];
  unsigned char root[n];
  unsigned char ots_seed[n];
  unsigned char ots_addr[16] = {0,0,0,0};
  
  // Extract SK
  unsigned long long idx = 0;
  for(i = 0; i < idx_len; i++){
    idx |= ((unsigned long long)sk[i]) << 8*(idx_len - 1 - i);
  }
  
  memcpy(sk_seed,sk+idx_len,n);
  memcpy(sk_prf,sk+idx_len+n,m);
  memcpy(pub_seed,sk+idx_len+n+m,n);  
  
  // Update SK
  for(i = 0; i < idx_len; i++){
    sk[i] = ((idx + 1) >> 8*(idx_len - 1 - i)) & 255;
  }
  // -- Secret key for this non-forward-secure version is now updated. 
  // -- A productive implementation should use a file handle instead and write the updated secret key at this point! 
  
  
  // ---------------------------------
  // Message Hashing
  // ---------------------------------
  
  // Message Hash: 
  // First compute pseudorandom key
  prf_m(R, msg, msglen, sk_prf, m); 
  // Then use it for message digest
  hash_m(msg_h, msg, msglen, R, m, m);
  
  // Start collecting signature
  *sig_msg_len = 0;

  // Copy index to signature
  for(i = 0; i < idx_len; i++){
    sig_msg[i] = (idx >> 8*(idx_len - 1 - i)) & 255;
  }
  
  sig_msg += idx_len;
  *sig_msg_len += idx_len;
  
  // Copy R to signature
  for(i=0; i<m; i++)
    sig_msg[i] = R[i];

  sig_msg += m;
  *sig_msg_len += m;
  
  // ----------------------------------
  // Now we start to "really sign" 
  // ----------------------------------
  
  // Handle lowest layer separately as it is slightly different...
  
  // Prepare Address
  SET_OTS_BIT(ots_addr,1);
  idx_tree = idx >> tree_h;
  idx_leaf = (idx & ((1 << tree_h)-1));
  SET_LAYER_ADDRESS(ots_addr,0);
  SET_TREE_ADDRESS(ots_addr, idx_tree);
  SET_OTS_ADDRESS(ots_addr, idx_leaf);
  
  // Compute seed for OTS key pair
  get_seed(ots_seed, sk_seed, ots_addr);
     
  // Compute WOTS signature
  wots_sign(sig_msg, msg_h, ots_seed, &(params->xmss_par.wots_par), pub_seed, ots_addr);
  
  sig_msg += params->xmss_par.wots_par.keysize;
  *sig_msg_len += params->xmss_par.wots_par.keysize;

  compute_authpath_wots_fast(root, sig_msg, idx_leaf, state, sk_seed, &(params->xmss_par), pub_seed, ots_addr);
  sig_msg += tree_h*n;
  *sig_msg_len += tree_h*n;
  
  // Now loop over remaining layers...
  unsigned int j;
  for(j = 1; j < params->d; j++){
    // Prepare Address
    idx_leaf = (idx_tree & ((1 << tree_h)-1));
    idx_tree = idx_tree >> tree_h;
    SET_LAYER_ADDRESS(ots_addr,j);
    SET_TREE_ADDRESS(ots_addr, idx_tree);
    SET_OTS_ADDRESS(ots_addr, idx_leaf);
    
    // Compute seed for OTS key pair
    get_seed(ots_seed, sk_seed, ots_addr);
      
    // Compute WOTS signature
    wots_sign(sig_msg, root, ots_seed, &(params->xmss_par.wots_par), pub_seed, ots_addr);
    
    sig_msg += params->xmss_par.wots_par.keysize;
    *sig_msg_len += params->xmss_par.wots_par.keysize;

    compute_authpath_wots_fast(root, sig_msg, idx_leaf, state, sk_seed, &(params->xmss_par), pub_seed, ots_addr);
    sig_msg += tree_h*n;
    *sig_msg_len += tree_h*n;   
  }
  
  //Whipe secret elements?  
  //zerobytes(tsk, CRYPTO_SECRETKEYBYTES);

  memcpy(sig_msg,msg,msglen);
  *sig_msg_len += msglen;

  return 0;
}

/**
 * Verifies a given message signature pair under a given public key.
 */
int xmssmt_sign_open(unsigned char *msg, unsigned long long *msglen, const unsigned char *sig_msg, unsigned long long sig_msg_len, const unsigned char *pk, const xmssmt_params *params)
{
  unsigned int n = params->n;
  unsigned int m = params->m;
  
  unsigned int tree_h = params->xmss_par.h;
  unsigned int idx_len = params->index_len;
  unsigned long long idx_tree;
  unsigned long long idx_leaf;
  
  unsigned long long i, m_len;
  unsigned long long idx=0;
  unsigned char wots_pk[params->xmss_par.wots_par.keysize];
  unsigned char pkhash[n];
  unsigned char root[n];
  unsigned char msg_h[m];
  
  unsigned char pub_seed[n];
  memcpy(pub_seed,pk+n,n);  
  
  // Init addresses
  unsigned char ots_addr[16] = {0,0,0,0};
  unsigned char ltree_addr[16];
  unsigned char node_addr[16];
  
  // Extract index
  for(i = 0; i < idx_len; i++){
    idx |= ((unsigned long long)sig_msg[i]) << (8*(idx_len - 1 - i));
  }
  printf("verify:: idx = %llu\n",idx);
  sig_msg += idx_len;
  sig_msg_len -= idx_len;
  
  // hash message (recall, R is now on pole position at sig_msg
  unsigned long long tmp_sig_len = m+ (params->d * params->xmss_par.wots_par.keysize) + (params->h * n);
  m_len = sig_msg_len - tmp_sig_len;
  hash_m(msg_h, sig_msg + tmp_sig_len, m_len, sig_msg, m, m);

  sig_msg += m;
  sig_msg_len -= m;
  
  //-----------------------
  // Verify signature
  //-----------------------
  
  // Prepare Address
  idx_tree = idx >> tree_h;
  idx_leaf = (idx & ((1 << tree_h)-1));
  SET_LAYER_ADDRESS(ots_addr,0);
  SET_TREE_ADDRESS(ots_addr, idx_tree);
  SET_OTS_BIT(ots_addr, 1);
  
  memcpy(ltree_addr, ots_addr, 10);
  SET_OTS_BIT(ltree_addr, 0);
  SET_LTREE_BIT(ltree_addr, 1);
  
  memcpy(node_addr, ltree_addr, 10);
  SET_LTREE_BIT(node_addr, 0);
  SET_NODE_PADDING(node_addr);  
  
  SET_OTS_ADDRESS(ots_addr,idx_leaf);
  
  // Check WOTS signature 
  wots_pkFromSig(wots_pk, sig_msg, msg_h, &(params->xmss_par.wots_par), pub_seed, ots_addr);

  sig_msg += params->xmss_par.wots_par.keysize;
  sig_msg_len -= params->xmss_par.wots_par.keysize;
  
  // Compute Ltree
  SET_LTREE_ADDRESS(ltree_addr, idx_leaf); 
  l_tree(pkhash, wots_pk, &(params->xmss_par), pub_seed, ltree_addr);
  
  // Compute root
  validate_authpath(root, pkhash, idx_leaf, sig_msg, &(params->xmss_par), pub_seed, node_addr);  

  sig_msg += tree_h*n;
  sig_msg_len -= tree_h*n;
  
  for(i = 1; i < params->d; i++){
    // Prepare Address
    idx_leaf = (idx_tree & ((1 << tree_h)-1));
    idx_tree = idx_tree >> tree_h;
    
    SET_LAYER_ADDRESS(ots_addr,i);
    SET_TREE_ADDRESS(ots_addr, idx_tree);
    SET_OTS_BIT(ots_addr, 1);
    
    memcpy(ltree_addr, ots_addr, 10);
    SET_OTS_BIT(ltree_addr, 0);
    SET_LTREE_BIT(ltree_addr, 1);
    
    memcpy(node_addr, ltree_addr, 10);
    SET_LTREE_BIT(node_addr, 0);
    SET_NODE_PADDING(node_addr);  
    
    SET_OTS_ADDRESS(ots_addr,idx_leaf);
    
    // Check WOTS signature 
    wots_pkFromSig(wots_pk, sig_msg, root, &(params->xmss_par.wots_par), pub_seed, ots_addr);

    sig_msg += params->xmss_par.wots_par.keysize;
    sig_msg_len -= params->xmss_par.wots_par.keysize;
    
    // Compute Ltree
    SET_LTREE_ADDRESS(ltree_addr, idx_leaf); 
    l_tree(pkhash, wots_pk, &(params->xmss_par), pub_seed, ltree_addr);
    
    // Compute root
    validate_authpath(root, pkhash, idx_leaf, sig_msg, &(params->xmss_par), pub_seed, node_addr);  

    sig_msg += tree_h*n;
    sig_msg_len -= tree_h*n;
    
  }
  
  for(i=0;i<n;i++)
    if(root[i] != pk[i])
      goto fail;
  
  *msglen = sig_msg_len;
  for(i=0;i<*msglen;i++)
    msg[i] = sig_msg[i];

  return 0;
  
  
fail:
  *msglen = sig_msg_len;
  for(i=0;i<*msglen;i++)
    msg[i] = 0;
  *msglen = -1;
  return -1;
}