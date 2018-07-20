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

#define mpz_mul_mod(a,b,c,p) do { mpz_mul(a,b,c); mpz_mod(a,a,p); } while(0)
#define Me_data_init(me_data) do { me_data->ec=EC_GROUP_new_by_curve_name(714); me_data->a=BN_new(); me_data->b=BN_new(); me_data->p=BN_new(); mpz_init(me_data->p_mpz); me_data->order=BN_new(); me_data->z=BN_new(); me_data->Z=EC_POINT_new(me_data->ec); me_data->k=BN_new(); } while(0)
#define Me_data_set(me_data) do { EC_GROUP_get_curve_GFp(me_data->ec,me_data->p,me_data->a,me_data->b,NULL); char *str; str=BN_bn2hex(me_data->p); mpz_set_str(me_data->p_mpz,str,16); free(str); EC_GROUP_get_order(me_data->ec,me_data->order,NULL); } while(0)
#define Me_data_set_Zk(me_data,Z,z,k) do { EC_POINT_copy(me_data->Z,Z); BN_copy(me_data->z,z); BN_copy(me_data->k,k); } while(0)
#define Me_data_clear(me_data) do { EC_POINT_clear_free(me_data->Z); BN_clear_free(me_data->k); BN_clear_free(me_data->p); } while(0)

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

void Me_mul_rtol(EC_POINT *R, const EC_POINT *P,const BIGNUM *n,const Me_DATA me_data){
  BN_CTX *ctx;
  ctx=BN_CTX_new();

  EC_POINT *RR,*S,*ZS;
  RR=EC_POINT_new(me_data->ec);
  S=EC_POINT_new(me_data->ec);
  ZS=EC_POINT_new(me_data->ec);

  int i,len;
  len=BN_num_bits(n);
  //EC_POINT_set_to_infinity(me_data->ec,RR);
  EC_POINT_copy(RR,P);
  EC_POINT_copy(S,P);
  for(i=0;i<len-1;i++){
    if(BN_is_bit_set(n,i)){
      Me(RR,RR,S,me_data,ctx);
    }
    EC_POINT_add(me_data->ec,ZS,me_data->Z,S,ctx);
    Me_Z(S,ZS,S,me_data,ctx);
  }
  EC_POINT_copy(R,RR);

  EC_POINT_clear_free(RR);
  EC_POINT_clear_free(S);
  EC_POINT_clear_free(ZS);
  BN_CTX_free(ctx);
}

void private_key_create(BIGNUM *private_key,const Me_DATA me_data){
  BN_rand_range(private_key,me_data->order);
}

void hash1(EC_POINT *P,const unsigned char *keyword,const Me_DATA me_data){
  BN_CTX *ctx;
  ctx=BN_CTX_new();
  BIGNUM *x0,*y0;
  x0=BN_new();
  y0=BN_new();

	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256(keyword,strlen(keyword),hash);
  /*
  for ( size_t i = 0; i < SHA256_DIGEST_LENGTH; i++ ){
		printf("%02x", hash[i] );
	}
	printf("\n");
  */
  BN_bin2bn(hash,32,x0);
  //BN_print_fp(stdout,x0);
  //puts("");
  do{
    BN_add_word(x0,1);
    BN_mod_sqr(y0,x0,me_data->p,ctx);
    //BN_mod_add(y0,y0,me_data->a,me_data->p,ctx);  //曲線を自由に選ぶとき用
    BN_mod_mul(y0,y0,x0,me_data->p,ctx);
    //BN_mod_add(y0,y0,me_data->b,me_data->p,ctx);
    BN_add_word(y0,7);
  }while(BN_kronecker(y0,me_data->p,ctx)<1);
  BN_mod_sqrt(y0,y0,me_data->p,ctx);
  EC_POINT_set_affine_coordinates_GFp(me_data->ec,P,x0,y0,ctx);
  /*
  BN_print_fp(stdout,x0);
  puts("");
  BN_print_fp(stdout,y0);
  puts("");
  */
  BN_clear_free(x0);
  BN_clear_free(y0);
  BN_CTX_free(ctx);
}

int main(){

  int i,n=5;
  double start,end;
  /*start=omp_get_wtime();
  for(i=0;i<5000;i++)
    keyword_encrypt(peks[0],keyword[0],public_key,me_data);
  end=omp_get_wtime();
  printf("encrypt %f seconds\n",(end-start)/5000);
  */
  BN_CTX *ctx;
  ctx=BN_CTX_new();

  Me_DATA me_data;
  Me_data_init(me_data);
  Me_data_set(me_data);

  EC_POINT *P,*Z,*Q,*R,*A,*B,*C,*D;
  P=EC_POINT_new(me_data->ec);//ベースポイント
  Z=EC_POINT_new(me_data->ec);//補助元Z=z*P
  Q=EC_POINT_new(me_data->ec);//2つ目の点
  R=EC_POINT_new(me_data->ec);
  A=EC_POINT_new(me_data->ec);
  B=EC_POINT_new(me_data->ec);
  C=EC_POINT_new(me_data->ec);
  D=EC_POINT_new(me_data->ec);
  BIGNUM *a,*b,*z,*k,*r;
  a=BN_new();//秘密鍵
  b=BN_new();
  z=BN_new();//補助元
  k=BN_new();
  r=BN_new();

  BN_rand_range(a,me_data->order);
  BN_rand_range(z,me_data->order);
  BN_set_word(k,2);
  EC_POINT_mul(me_data->ec,Z,z,NULL,NULL,ctx);//Z=z*P
  Me_data_set_Zk(me_data,Z,z,k);
  me_data->Z_sign=Sign(me_data,Z,ctx);
  P=EC_GROUP_get0_generator(me_data->ec);
  BN_rand_range(b,me_data->order);
  EC_POINT_mul(me_data->ec,Q,b,NULL,NULL,ctx);//Q=b*P

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
  printf("Q : ");
  EC_POINT_print(Q,me_data,ctx);
  printf("---------------------------------\n");

  //culculate Pa,z
  Me_mul_1(A,P,a,me_data);
  printf("Pa,z→ = A : ");
  EC_POINT_print(A,me_data,ctx);

  Me_mul_1(B,Q,a,me_data);
  printf("Qa,z→ = B : ");
  EC_POINT_print(B,me_data,ctx);

  Me_mul_rtol(C,P,a,me_data);
  printf("Pa,z← = C : ");
  EC_POINT_print(C,me_data,ctx);

  Me_mul_rtol(D,Q,a,me_data);
  printf("Qa,z← = D : ");
  EC_POINT_print(D,me_data,ctx);
  printf("---------------------------------\n");

  EC_POINT_add(me_data->ec,R,A,Q,ctx);
  printf("Pa,z→ + Q : ");
  EC_POINT_print(R,me_data,ctx);
  EC_POINT_add(me_data->ec,R,P,B,ctx);
  printf("P + Qa,z→ : ");
  EC_POINT_print(R,me_data,ctx);

  EC_POINT_add(me_data->ec,R,C,Q,ctx);
  printf("Pa,z← + Q : ");
  EC_POINT_print(R,me_data,ctx);
  EC_POINT_add(me_data->ec,R,P,D,ctx);
  printf("P + Qa,z← : ");
  EC_POINT_print(R,me_data,ctx);
  printf("---------------------------------\n");



  return 0;
}
