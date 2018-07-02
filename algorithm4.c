//secp192k1 711 secp256k1 714 openssl/obj_mac.h
//gcc -fopenmp -O2 -o Me2 searchable_encryption_Me2.c -L/usr/local/lib -I/usr/local/include -lssl -lcrypto

#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<time.h>
#include<omp.h>
#include<gmp.h>
#include<openssl/ec.h>
#include<openssl/bn.h>
#include<openssl/sha.h>

typedef struct//Me関数のためのデータ一式
{
  EC_GROUP *ec;//楕円曲線 y^2=x^3+ax+b
  BIGNUM *a;
  BIGNUM *b;
  BIGNUM *p;//標数
  mpz_t p_mpz;//標数 mpz_t版
  BIGNUM *order;//位数
  EC_POINT *Z;//Meスカラー倍の補助元
  int Z_sign;//補助元のsignの値
  BIGNUM *k;//k>1
}Me_DATA[1];

typedef struct
{
  EC_POINT *P;
  BIGNUM *k;
}Me_instance[1];

#define Me_inst_init(inst,me_data) do { inst->P=EC_POINT_new(me_data->ec); inst->k=BN_new();} while(0)
#define Me_inst_set(inst,A,B) do { EC_POINT_copy(inst->P,A); BN_copy(inst->k,B);} while(0)
#define Me_inst_clear(inst) do { EC_POINT_clear_free(inst->P); BN_clear_free(inst->k);} while(0)

void P_Q(Me_instance R,const Me_instance P,const Me_instance Q,const Me_DATA me_data){
  BN_CTX *ctx;
  ctx=BN_CTX_new();
  EC_POINT *A;
  A=EC_POINT_new(me_data->ec);
  BIGNUM *B;
  B=BN_new();

  EC_POINT_add(me_data->ec,A,P->P,Q->P,ctx);
  BN_add(B,P->k,Q->k);
  Me_inst_set(R,A,B);

  EC_POINT_clear_free(A);
  BN_clear_free(B);
  BN_CTX_free(ctx);
}

int Sign(const Me_DATA me_data,const EC_POINT *P,BN_CTX *ctx){
  BIGNUM *y0,*z0;
  BN_CTX_start(ctx);
  y0=BN_CTX_get(ctx);
  z0=BN_CTX_get(ctx);
  EC_POINT_get_Jprojective_coordinates_GFp(me_data->ec,P,NULL,y0,z0,ctx);

  mpz_t Y0,Z0;
  mpz_inits(Y0,Z0,NULL);
  char *str_y,*str_z;
  str_y=BN_bn2hex(y0);
  str_z=BN_bn2hex(z0);
  mpz_set_str(Y0,str_y,16);
  mpz_set_str(Z0,str_z,16);
  mpz_mul_mod(Y0,Y0,Z0,me_data->p_mpz);
  int k=mpz_kronecker(Y0,me_data->p_mpz);
  free(str_y);
  free(str_z);
  mpz_clears(Y0,Z0,NULL);

  //BN_mod_mul(y0,y0,z0,me_data->p,ctx);
  //int k=BN_kronecker(y0,me_data->p,ctx);
  //int k=BN_is_bit_set(y0,0);
  BN_CTX_end(ctx);
  return k;
}

void Me_P_Q(Me_instance R,const Me_instance P,const Me_instance Q,const Me_DATA me_data){
  BN_CTX *ctx;
  ctx=BN_CTX_new();
  EC_POINT *A,*B;
  A=EC_POINT_new(me_data->ec);
  B=EC_POINT_new(me_data->ec);
  BIGNUM *C;
  C=BN_new();

  EC_POINT_copy(A,Q->P);
  EC_POINT_invert(me_data->ec,A,ctx);
  EC_POINT_add(me_data->ec,A,A,P->P,ctx);
  int k=Sign(me_data,A,ctx);
  //k=2
  if(!EC_POINT_cmp(me_data->ec,P->P,Q->P,ctx)){
    Me_inst_set(R,P->P,P->k);
  }else if(k==1){
    EC_POINT_dbl(me_data->ec,A,P->P,ctx);
    EC_POINT_copy(B,Q->P);
    EC_POINT_invert(me_data->ec,B,ctx);
    EC_POINT_add(me_data->ec,A,A,B,ctx);

    BN_copy(C,P->k);
    BN_mul_word(C,2);
    BN_sub(C,C,Q->k);
  }else{
    EC_POINT_dbl(me_data->ec,A,Q->P,ctx);
    EC_POINT_copy(B,P->P);
    EC_POINT_invert(me_data->ec,B,ctx);
    EC_POINT_add(me_data->ec,A,A,B,ctx);

    BN_copy(C,Q->k);
    BN_mul_word(C,2);
    BN_sub(C,C,P->k);
  }

  EC_POINT_clear_free(A);
  EC_POINT_clear_free(B);
  BN_clear_free(C);
  BN_CTX_free(ctx);
}

int main(){
  int i,n=5;
  double start,end;

  BN_CTX *ctx;
  ctx=BN_CTX_new();

  Me_DATA me_data;
  Me_data_init(me_data);
  Me_data_set(me_data);

  EC_POINT *P,*Z;
  P=EC_POINT_new(me_data->ec);
  Z=EC_POINT_new(me_data->ec);
  BIGNUM *k,*z;
  k=BN_new();
  z=BN_new();

  Me_instance ins,ins_Z;
  Me_inst_init(ins,me_data);
  Me_inst_init(ins_Z,me_data);

  Me_inst_set(ins,P,)



  BN_CTX_free(ctx);
}
