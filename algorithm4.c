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
  BIGNUM *z;
  EC_POINT *Z;//Meスカラー倍の補助元
  int Z_sign;//補助元のsignの値
  BIGNUM *k;//k>1
}Me_DATA[1];

typedef struct
{
  EC_POINT *P;
  BIGNUM *k;
}Me_instance[1];

#define mpz_mul_mod(a,b,c,p) do { mpz_mul(a,b,c); mpz_mod(a,a,p); } while(0)
#define Me_data_init(me_data) do { me_data->ec=EC_GROUP_new_by_curve_name(714); me_data->a=BN_new(); me_data->b=BN_new(); me_data->p=BN_new(); mpz_init(me_data->p_mpz); me_data->order=BN_new(); me_data->z=BN_new(); me_data->Z=EC_POINT_new(me_data->ec); me_data->k=BN_new(); } while(0)
#define Me_data_set(me_data) do { EC_GROUP_get_curve_GFp(me_data->ec,me_data->p,me_data->a,me_data->b,NULL); char *str; str=BN_bn2hex(me_data->p); mpz_set_str(me_data->p_mpz,str,16); free(str); EC_GROUP_get_order(me_data->ec,me_data->order,NULL); } while(0)
#define Me_data_set_Zk(me_data,Z,z,k) do { EC_POINT_copy(me_data->Z,Z); BN_copy(me_data->z,z); BN_copy(me_data->k,k); } while(0)
#define Me_data_clear(me_data) do { EC_POINT_clear_free(me_data->Z); BN_clear_free(me_data->k); BN_clear_free(me_data->p); } while(0)
#define Me_inst_init(inst,me_data) do { inst->P=EC_POINT_new(me_data->ec); inst->k=BN_new();} while(0)
#define Me_inst_set(inst,A,B) do { EC_POINT_copy(inst->P,A); BN_copy(inst->k,B);} while(0)
#define Me_inst_clear(inst) do { EC_POINT_clear_free(inst->P); BN_clear_free(inst->k);} while(0)

void EC_POINT_print(const EC_POINT *P,const Me_DATA me_data,BN_CTX *ctx){
  BIGNUM *Px,*Py;
  Px=BN_new();
  Py=BN_new();
  EC_POINT_get_affine_coordinates_GFp(me_data->ec,P,Px,Py,ctx);

  fprintf(stdout,"[ ");
  BN_print_fp(stdout,Px);
  fprintf(stdout," , ");
  BN_print_fp(stdout,Py);
  fprintf(stdout," ]");
  puts("");

  BN_clear_free(Px);
  BN_clear_free(Py);
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

void Me(EC_POINT *R,const EC_POINT *P,const EC_POINT *Q,const Me_DATA me_data,BN_CTX *ctx){
  //BIGNUM *k_1;
  //k_1=BN_new();
  //BN_copy(k_1,me_data->k);
  //BN_sub_word(k_1,1);
  //double start,end;
  //start=omp_get_wtime();

  EC_POINT *AA,*minus;
  AA=EC_POINT_new(me_data->ec);
  minus=EC_POINT_new(me_data->ec);

  EC_POINT_copy(minus,Q);
  EC_POINT_invert(me_data->ec,minus,ctx);
  EC_POINT_add(me_data->ec,AA,P,minus,ctx);
  //end=omp_get_wtime();
  //printf("zyunbi %f seconds\n",end-start);

  //start=omp_get_wtime();
  int sign=Sign(me_data,AA,ctx);
  //end=omp_get_wtime();
  //printf("sign %f seconds\n",end-start);

  //start=omp_get_wtime();
  if(EC_POINT_is_at_infinity(me_data->ec,AA)){
    EC_POINT_copy(R,P);
  }else if(sign==-1){
    //EC_POINT_mul(me_data->ec,kQ,NULL,Q,me_data->k,ctx);
    EC_POINT_dbl(me_data->ec,AA,Q,ctx);
    //EC_POINT_mul(me_data->ec,kP,NULL,P,k_1,ctx);
    //EC_POINT_invert(me_data->ec,kP,ctx);
    EC_POINT_copy(minus,P);
    EC_POINT_invert(me_data->ec,minus,ctx);
    EC_POINT_add(me_data->ec,R,AA,minus,ctx);
  }else if(sign==1){
    //EC_POINT_mul(me_data->ec,kP,NULL,P,me_data->k,ctx);
    EC_POINT_dbl(me_data->ec,AA,P,ctx);
    //EC_POINT_mul(me_data->ec,kQ,NULL,Q,k_1,ctx);
    //EC_POINT_invert(me_data->ec,kQ,ctx);
    EC_POINT_add(me_data->ec,R,AA,minus,ctx);
  }else{
    EC_POINT_set_to_infinity(me_data->ec,R);//error
    printf("error!!!!\n");
  }
  //end=omp_get_wtime();
  //printf("if %f seconds\n",end-start);

  //BN_clear_free(k_1);
  EC_POINT_clear_free(AA);
  EC_POINT_clear_free(minus);
}

void Me_Z(EC_POINT *R,const EC_POINT *P,const EC_POINT *Q,const Me_DATA me_data,BN_CTX *ctx){
  //BIGNUM *k_1;
  //k_1=BN_new();
  //BN_copy(k_1,me_data->k);
  //BN_sub_word(k_1,1);
  //double start,end;
  //start=omp_get_wtime();

  EC_POINT *dbl,*minus;
  dbl=EC_POINT_new(me_data->ec);
  minus=EC_POINT_new(me_data->ec);
  //printf("Me_second AA: ");
  //EC_POINT_print(AA,me_data);
  //end=omp_get_wtime();
  //printf("zyunbi %f seconds\n",end-start);

  //start=omp_get_wtime();
  if(EC_POINT_is_at_infinity(me_data->ec,me_data->Z)){
    EC_POINT_copy(R,P);
  }else if(me_data->Z_sign==-1){
    //EC_POINT_mul(me_data->ec,kQ,NULL,Q,me_data->k,ctx);
    EC_POINT_dbl(me_data->ec,dbl,Q,ctx);
    //EC_POINT_mul(me_data->ec,kP,NULL,P,k_1,ctx);
    //EC_POINT_invert(me_data->ec,kP,ctx);
    EC_POINT_copy(minus,P);
    EC_POINT_invert(me_data->ec,minus,ctx);
    EC_POINT_add(me_data->ec,R,dbl,minus,ctx);
  }else if(me_data->Z_sign==1){
    //EC_POINT_mul(me_data->ec,kP,NULL,P,me_data->k,ctx);
    EC_POINT_dbl(me_data->ec,dbl,P,ctx);
    //EC_POINT_mul(me_data->ec,kQ,NULL,Q,k_1,ctx);
    //EC_POINT_invert(me_data->ec,kQ,ctx);
    EC_POINT_copy(minus,Q);
    EC_POINT_invert(me_data->ec,minus,ctx);
    EC_POINT_add(me_data->ec,R,dbl,minus,ctx);
  }else{
    EC_POINT_set_to_infinity(me_data->ec,R);//error
    printf("error!!!!\n");
  }
  //end=omp_get_wtime();
  //printf("if %f seconds\n",end-start);

  //BN_clear_free(k_1);
  EC_POINT_clear_free(dbl);
  EC_POINT_clear_free(minus);
}

void Me_mul_1(EC_POINT *R, const EC_POINT *P,const BIGNUM *n,const Me_DATA me_data){
  BN_CTX *ctx;
  ctx=BN_CTX_new();

  EC_POINT *Y,*ZY;
  Y=EC_POINT_new(me_data->ec);
  ZY=EC_POINT_new(me_data->ec);

  int i,len;
  len=BN_num_bits(n);
  EC_POINT_copy(Y,P);
  for(i=len-2;i>=0;i--){
    EC_POINT_add(me_data->ec,ZY,me_data->Z,Y,ctx);
    Me_Z(Y,ZY,Y,me_data,ctx);
    if(BN_is_bit_set(n,i)){
      Me(Y,Y,P,me_data,ctx);
    }
  }
  EC_POINT_copy(R,Y);

  EC_POINT_clear_free(Y);
  EC_POINT_clear_free(ZY);
  BN_CTX_free(ctx);
  //free(str);
}

void Me_mul_2(EC_POINT *R, const EC_POINT *P,const BIGNUM *n,const Me_DATA me_data){
  BN_CTX *ctx;
  ctx=BN_CTX_new();

  EC_POINT *Y,*ZY;
  Y=EC_POINT_new(me_data->ec);
  ZY=EC_POINT_new(me_data->ec);

  int i,len;
  len=BN_num_bits(n);
  EC_POINT_copy(Y,P);
  for(i=len-2;i>=0;i--){
    Me(ZY,me_data->Z,Y,me_data,ctx);
    Me(Y,ZY,Y,me_data,ctx);
    if(BN_is_bit_set(n,i)){
      Me(Y,Y,P,me_data,ctx);
    }
  }
  EC_POINT_copy(R,Y);

  EC_POINT_clear_free(Y);
  EC_POINT_clear_free(ZY);
  BN_CTX_free(ctx);
  //free(str);
}

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
    Me_inst_set(R,A,C);
  }else{
    EC_POINT_dbl(me_data->ec,A,Q->P,ctx);
    EC_POINT_copy(B,P->P);
    EC_POINT_invert(me_data->ec,B,ctx);
    EC_POINT_add(me_data->ec,A,A,B,ctx);

    BN_copy(C,Q->k);
    BN_mul_word(C,2);
    BN_sub(C,C,P->k);
    Me_inst_set(R,A,C);
  }

  EC_POINT_clear_free(A);
  EC_POINT_clear_free(B);
  BN_clear_free(C);
  BN_CTX_free(ctx);
}

void Me_mul_algo(Me_instance ins,const EC_POINT *P,const BIGNUM *n,const Me_DATA me_data){
  Me_instance PP,ZZ,YY,ZZYY;
  Me_inst_init(PP,me_data);
  Me_inst_init(ZZ,me_data);
  Me_inst_init(YY,me_data);
  Me_inst_init(ZZYY,me_data);
  Me_inst_set(PP,P,BN_value_one());
  Me_inst_set(ZZ,me_data->Z,me_data->z);
  Me_inst_set(YY,P,BN_value_one());

  int i,len;
  len=BN_num_bits(n);
  for(i=len-2;i>=0;i--){
    P_Q(ZZYY,ZZ,YY,me_data);
    Me_P_Q(YY,ZZYY,YY,me_data);
    if(BN_is_bit_set(n,i)){
      Me_P_Q(YY,YY,PP,me_data);
    }
  }
  Me_inst_set(ins,YY->P,YY->k);

  Me_inst_clear(PP);
  Me_inst_clear(ZZ);
  Me_inst_clear(YY);
  Me_inst_clear(ZZYY);
}

void Me_mul_2_algo(Me_instance ins,const EC_POINT *P,const BIGNUM *n,const Me_DATA me_data){
  Me_instance PP,ZZ,YY,ZZYY;
  Me_inst_init(PP,me_data);
  Me_inst_init(ZZ,me_data);
  Me_inst_init(YY,me_data);
  Me_inst_init(ZZYY,me_data);
  Me_inst_set(PP,P,BN_value_one());
  Me_inst_set(ZZ,me_data->Z,me_data->z);
  Me_inst_set(YY,P,BN_value_one());

  int i,len;
  len=BN_num_bits(n);
  for(i=len-2;i>=0;i--){
    Me_P_Q(ZZYY,ZZ,YY,me_data);
    Me_P_Q(YY,ZZYY,YY,me_data);
    if(BN_is_bit_set(n,i)){
      Me_P_Q(YY,YY,PP,me_data);
    }
  }
  Me_inst_set(ins,YY->P,YY->k);

  Me_inst_clear(PP);
  Me_inst_clear(ZZ);
  Me_inst_clear(YY);
  Me_inst_clear(ZZYY);
}

int main(){
  int i,n=5;
  double start,end;

  BN_CTX *ctx;
  ctx=BN_CTX_new();

  Me_DATA me_data;
  Me_data_init(me_data);
  Me_data_set(me_data);

  EC_POINT *P,*Z,*Q,*R,*S;
  P=EC_POINT_new(me_data->ec);
  Z=EC_POINT_new(me_data->ec);
  Q=EC_POINT_new(me_data->ec);
  R=EC_POINT_new(me_data->ec);
  S=EC_POINT_new(me_data->ec);
  BIGNUM *a,*z,*k,*r;
  a=BN_new();
  z=BN_new();
  k=BN_new();
  r=BN_new();

  Me_instance ins;
  Me_inst_init(ins,me_data);

  //テストかく
  BN_rand_range(a,me_data->order);
  BN_rand_range(z,me_data->order);
  BN_set_word(k,2);
  EC_POINT_mul(me_data->ec,Z,z,NULL,NULL,ctx);
  Me_data_set_Zk(me_data,Z,z,k);
  me_data->Z_sign=Sign(me_data,Z,ctx);
  P=EC_GROUP_get0_generator(me_data->ec);
  printf("a : ");
  BN_print_fp(stdout,a);
  puts("");
  printf("z : ");
  BN_print_fp(stdout,z);
  puts("");
  printf("Z : ");
  EC_POINT_print(Z,me_data,ctx);
  printf("P : ");
  EC_POINT_print(P,me_data,ctx);
  printf("---------------------------------\n");

  //culculate Pa,z
  Me_mul_2(Q,P,a,me_data);
  printf("Pa,z = Q : ");
  EC_POINT_print(Q,me_data,ctx);
  printf("---------------------------------\n");

  Me_mul_2_algo(ins,P,a,me_data);
  printf("ins[0] : ");
  EC_POINT_print(ins->P,me_data,ctx);
  printf("ins[1] : ");
  BN_print_fp(stdout,ins->k);
  puts("");

  EC_POINT_mul(me_data->ec,R,ins->k,NULL,NULL,ctx);
  printf("t*P : ");
  EC_POINT_print(R,me_data,ctx);
  printf("---------------------------------\n");

  BN_rand_range(r,me_data->order);
  EC_POINT_mul(me_data->ec,R,r,NULL,NULL,ctx);
  printf("R : ");
  EC_POINT_print(R,me_data,ctx);

  Me_mul_2(S,R,a,me_data);
  printf("Ra,z : ");
  EC_POINT_print(S,me_data,ctx);

  EC_POINT_mul(me_data->ec,S,NULL,R,ins->k,ctx);
  printf("t*R : ");
  EC_POINT_print(S,me_data,ctx);
  BN_CTX_free(ctx);
}
