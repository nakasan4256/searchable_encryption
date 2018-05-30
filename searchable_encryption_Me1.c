//secp192k1 711 secp256k1 714 openssl/obj_mac.h
//gcc -fopenmp -O2 -o Me1 searchable_encryption_Me1.c -L/usr/local/lib -I/usr/local/include -lssl -lcrypto

#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<time.h>
#include<omp.h>
#include<openssl/ec.h>
#include<openssl/bn.h>
#include<openssl/sha.h>

typedef struct//Me関数のためのデータ一式
{
  EC_GROUP *ec;//楕円曲線 y^2=x^3+ax+b
  BIGNUM *a;
  BIGNUM *b;
  BIGNUM *p;//標数
  BIGNUM *order;//位数
  EC_POINT *Z;//Meスカラー倍の補助元
  int Z_sign;//補助元のsignの値
  BIGNUM *k;//k>1
}Me_DATA[1];

typedef struct//公開鍵
{
  EC_POINT *P;//ベースポイント
  EC_POINT *Q;//秘密鍵*P
} Public_Key[1];

typedef struct//暗号化されたキーワード
{
  EC_POINT *A;
  EC_POINT *B;
} Peks[1];

#define Me_data_init(me_data) do { me_data->ec=EC_GROUP_new_by_curve_name(714); me_data->a=BN_new(); me_data->b=BN_new(); me_data->p=BN_new(); me_data->order=BN_new(); me_data->Z=EC_POINT_new(me_data->ec); me_data->k=BN_new(); } while(0)
#define Me_data_set(me_data) do { EC_GROUP_get_curve_GFp(me_data->ec,me_data->p,me_data->a,me_data->b,NULL); EC_GROUP_get_order(me_data->ec,me_data->order,NULL); } while(0)
#define Me_data_set_Zk(me_data,Z,k) do { EC_POINT_copy(me_data->Z,Z); BN_copy(me_data->k,k); } while(0)
#define Me_data_clear(me_data) do { EC_POINT_clear_free(me_data->Z); BN_clear_free(me_data->k); BN_clear_free(me_data->p); } while(0)
#define public_key_init(pub,me_data) do { pub->P=EC_POINT_new(me_data->ec); pub->Q=EC_POINT_new(me_data->ec);} while(0)
#define public_key_clear(pub) do { EC_POINT_clear_free(pub->P); EC_POINT_clear_free(pub->Q);} while(0)
#define peks_init(peks,me_data) do { peks->A=EC_POINT_new(me_data->ec); peks->B=EC_POINT_new(me_data->ec);} while(0)
#define peks_clear(peks) do { EC_POINT_clear_free(peks->A); EC_POINT_clear_free(peks->B);} while(0)

void EC_POINT_print(const EC_POINT *P,const Me_DATA me_data){
  BN_CTX *ctx;
  ctx=BN_CTX_new();
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
  BN_CTX_free(ctx);
}

/*
void BN_new_mod_pow(BIGNUM *ret,const BIGNUM *a,const BIGNUM *p,const BIGNUM *mod){
  BN_CTX *ctx;
  ctx=BN_CTX_new();
  unsigned char *str;
  int len,i,j;

  len=BN_num_bytes(p);
  str=(unsigned char *)malloc(len);
  len=BN_bn2bin(p,str);

  int count=8*len-BN_num_bits(p);
  int aa=7-count;
  BIGNUM *x;
  x=BN_new();
  BN_copy(x,a);
  BN_one(ret);
  for(i=len-1;i>0;i--){
    for(j=7;j>=0;j--){
      if(*(str+i) & 1)
        BN_mod_mul(ret,ret,x,mod,ctx);
      BN_mod_sqr(x,x,mod,ctx);
      *(str+i) >>= 1;
    }
  }
  while (*str != 0) {
    if(*str & 1)
      BN_mod_mul(ret,ret,x,mod,ctx);
    BN_mod_sqr(x,x,mod,ctx);
    *str >>= 1;
    aa--;
  }
  free(str);
  BN_clear_free(x);
  BN_CTX_free(ctx);
}
int BN_new_kronecker(BIGNUM *a,BIGNUM *p,BN_CTX *ctx){
  BIGNUM *ret,*pp;
  ret=BN_new();
  pp=BN_new();
  BN_copy(pp,p);
  BN_sub_word(pp,1);
  BN_div_word(pp,2);
  BN_new_mod_pow(ret,a,pp,p);
  BN_clear_free(pp);
  if(BN_is_one(ret)){
    BN_clear_free(ret);
    return 1;
  }else{
    BN_clear_free(ret);
    return -1;
  }
}
int new_sign(const Me_DATA me_data,const EC_POINT *P,BN_CTX *ctx){
  int k;
  BIGNUM *y0;
  y0=BN_new();
  EC_POINT_get_affine_coordinates_GFp(me_data->ec,P,NULL,y0,ctx);
  k=BN_new_kronecker(y0,me_data->p,ctx);
  BN_clear_free(y0);
  return k;
}
*/

int Sign(const Me_DATA me_data,const EC_POINT *P,BN_CTX *ctx){
  double start,end;
  start=omp_get_wtime();
  BIGNUM *x0;
  x0=BN_new();

  end=omp_get_wtime();
  printf("zyunbi %f seconds\n",end-start);

  start=omp_get_wtime();
  EC_POINT_get_affine_coordinates_GFp(me_data->ec,P,x0,NULL,ctx);

  end=omp_get_wtime();
  printf("getpoint %f seconds\n",end-start);

  start=omp_get_wtime();
  //int k=BN_kronecker(x0,me_data->p,ctx);
  int k=BN_is_bit_set(x0,1);
  end=omp_get_wtime();
  printf("kron %f seconds\n",end-start);

  start=omp_get_wtime();
  BN_clear_free(x0);
  end=omp_get_wtime();
  printf("clear %f seconds\n",end-start);
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
  }else if(!sign){
    //EC_POINT_mul(me_data->ec,kQ,NULL,Q,me_data->k,ctx);
    EC_POINT_dbl(me_data->ec,AA,Q,ctx);
    //EC_POINT_mul(me_data->ec,kP,NULL,P,k_1,ctx);
    //EC_POINT_invert(me_data->ec,kP,ctx);
    EC_POINT_copy(minus,P);
    EC_POINT_invert(me_data->ec,minus,ctx);
    EC_POINT_add(me_data->ec,R,AA,minus,ctx);
  }else if(sign){
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
  }else if(!me_data->Z_sign){
    //EC_POINT_mul(me_data->ec,kQ,NULL,Q,me_data->k,ctx);
    EC_POINT_dbl(me_data->ec,dbl,Q,ctx);
    //EC_POINT_mul(me_data->ec,kP,NULL,P,k_1,ctx);
    //EC_POINT_invert(me_data->ec,kP,ctx);
    EC_POINT_copy(minus,P);
    EC_POINT_invert(me_data->ec,minus,ctx);
    EC_POINT_add(me_data->ec,R,dbl,minus,ctx);
  }else if(me_data->Z_sign){
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
  /*
  unsigned char *str;
  int len,i,j;

  len=BN_num_bytes(n);
  str=(unsigned char *)malloc(len);
  len=BN_bn2bin(n,str);

  int binary[BN_num_bits(n)];
  int count=8*len-BN_num_bits(n);
  int aa=7-count;
  for(i=len-1;i>0;i--){
    for(j=7;j>=0;j--){
      binary[8*i+j-count]= *(str+i) & 1;
      *(str+i) >>= 1;
    }
  }
  while (*str != 0) {
    binary[aa]=*str & 1;
    *str >>= 1;
    aa--;
  }

  for(i=0;i<BN_num_bits(n);i++){
    printf("%d",binary[i]);
  }
  printf("\n");
  printf("len : %d\n",len);
  printf("count : %d\n",count);
  printf("aa : %d\n",aa);
  */
  int i,len;
  len=BN_num_bits(n);
  EC_POINT_copy(Y,P);
  for(i=1;i<len;i++){
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

void private_key_create(BIGNUM *private_key,const Me_DATA me_data){
  BN_rand_range(private_key,me_data->order);
}

void public_key_create(Public_Key public_key,const BIGNUM *private_key,const EC_POINT *base,const Me_DATA me_data){
  EC_POINT_copy(public_key->P,base);
  Me_mul_1(public_key->Q,base,private_key,me_data);
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
  BN_bin2bn(hash,24,x0);
  //BN_print_fp(stdout,x0);
  //puts("");
  do{
    BN_add_word(x0,1);
    BN_mod_sqr(y0,x0,me_data->p,ctx);
    //BN_mod_add(y0,y0,me_data->a,me_data->p,ctx);  //曲線を自由に選ぶとき用
    BN_mod_mul(y0,y0,x0,me_data->p,ctx);
    //BN_mod_add(y0,y0,me_data->b,me_data->p,ctx);
    BN_add_word(y0,7);
  }while(BN_kronecker(y0,me_data->p,ctx)==-1);
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

void trapdoor_create(EC_POINT *trapdoor,const BIGNUM *private_key,const char *keyword,const Me_DATA me_data){
  hash1(trapdoor,keyword,me_data);
  Me_mul_1(trapdoor,trapdoor,private_key,me_data);
}

void keyword_encrypt(Peks peks,const unsigned char *keyword,const Public_Key public_key,const Me_DATA me_data){
  BN_CTX *ctx;
  ctx=BN_CTX_new();
  BIGNUM *r;
  r=BN_new();

  BN_rand_range(r,me_data->order);

  hash1(peks->A,keyword,me_data);
  Me_mul_1(peks->B,public_key->Q,r,me_data);
  EC_POINT_add(me_data->ec,peks->B,peks->B,peks->A,ctx);
  Me_mul_1(peks->A,public_key->P,r,me_data);

  BN_clear_free(r);
  BN_CTX_free(ctx);
}

void test(const Peks peks,const EC_POINT *trapdoor,const Me_DATA me_data){
  //BN_CTX *ctx;
  //ctx=BN_CTX_new();
  EC_POINT *check;
  check=EC_POINT_new(me_data->ec);

  EC_POINT_add(me_data->ec,check,trapdoor,peks->A,NULL);
  if(EC_POINT_cmp(me_data->ec,check,peks->B,NULL)){
    printf("---test fail!!---\n");
  }else{
    printf("---test success!!---\n");
  }
  EC_POINT_clear_free(check);
  //BN_CTX_free(ctx);
}

int main(void){
  BN_CTX *ctx;
  ctx=BN_CTX_new();

  Me_DATA me_data;
  Me_data_init(me_data);
  Me_data_set(me_data);

  EC_POINT *P,*Z,*trapdoor;
  P=EC_POINT_new(me_data->ec);
  Z=EC_POINT_new(me_data->ec);
  trapdoor=EC_POINT_new(me_data->ec);
  BIGNUM *k,*private_key;
  k=BN_new();
  private_key=BN_new();

  Public_Key public_key;
  public_key_init(public_key,me_data);

  BN_rand_range(k,me_data->order);
  //BN_set_word(k,11);
  EC_POINT_mul(me_data->ec,Z,k,NULL,NULL,ctx);

  Me_data_set_Zk(me_data,Z,k);
  me_data->Z_sign=Sign(me_data,Z,ctx);
  P=EC_GROUP_get0_generator(me_data->ec);

  private_key_create(private_key,me_data);
  //BN_set_word(private_key,100);
  printf("private_key : ");
  BN_print_fp(stdout,private_key);
  puts("");

  public_key_create(public_key,private_key,P,me_data);
  printf("public_key : P ");
  EC_POINT_print(public_key->P,me_data);
  printf("             Q ");
  EC_POINT_print(public_key->Q,me_data);
  printf("------------------------------------\n");

  int i,n=5;
  unsigned char keyword[n][32];
  double start,end;
  Peks peks[n];
  //for(i=0;i<11;i++)
  //  printf("BN_is_bit_set : %d\n",BN_is_bit_set(k,i));

  for(i=0;i<n;i++){
    printf("keyword[%d] : ",i);
    scanf("%s",keyword[i]);
    peks_init(peks[i],me_data);
    start=omp_get_wtime();
    keyword_encrypt(peks[i],keyword[i],public_key,me_data);
    end=omp_get_wtime();
    printf("encrypt %f seconds\n",end-start);
    printf("keyword_enc : A ");
    EC_POINT_print(peks[i]->A,me_data);
    printf("              B ");
    EC_POINT_print(peks[i]->B,me_data);
  }


  while(1){
    unsigned char word[32];
    printf("search : ");
    scanf("%s",word);
    start=omp_get_wtime();
    trapdoor_create(trapdoor,private_key,word,me_data);
    end=omp_get_wtime();
    printf("trapdoor %f seconds\n",end-start);
    printf("trapdoor : ");
    EC_POINT_print(trapdoor,me_data);
    for(i=0;i<n;i++){
      printf("keyword[%d] : %s ",i,keyword[i]);
      start=omp_get_wtime();
      test(peks[i],trapdoor,me_data);
      end=omp_get_wtime();
      printf("test %f seconds\n",end-start);
    }
  }

  /*
  BIGNUM *Rx;
  BIGNUM *Ry;
  BIGNUM *Sx;
  BIGNUM *Sy;
  Rx=BN_new();
  Ry=BN_new();
  Sx=BN_new();
  Sy=BN_new();

  EC_POINT_get_affine_coordinates_GFp(ec,R,Rx,Ry,ctx);
  EC_POINT_get_affine_coordinates_GFp(ec,S,Sx,Sy,ctx);
  BN_print_fp(stdout,Rx);
  puts("");
  BN_print_fp(stdout,Ry);
  puts("");
  BN_print_fp(stdout,Sx);
  puts("");
  BN_print_fp(stdout,Sy);
  puts("");
  */

  /*
  EC_POINT *R,*S;
  R=EC_POINT_new(me_data->ec);
  S=EC_POINT_new(me_data->ec);
  BIGNUM *Rx,*Ry,*Sx,*Sy;
  Rx=BN_new();
  Ry=BN_new();
  Sx=BN_new();
  Sy=BN_new();
  BN_rand_range(Rx,me_data->order);
  BN_rand_range(Ry,me_data->order);

  Me_mul_1(R,P,Rx,me_data);
  Me_mul_1(R,R,Ry,me_data);

  Me_mul_1(S,P,Ry,me_data);
  Me_mul_1(S,S,Rx,me_data);

  EC_POINT_get_affine_coordinates_GFp(me_data->ec,R,Rx,Ry,ctx);
  EC_POINT_get_affine_coordinates_GFp(me_data->ec,S,Sx,Sy,ctx);
  BN_print_fp(stdout,Rx);
  puts("");
  BN_print_fp(stdout,Ry);
  puts("");
  BN_print_fp(stdout,Sx);
  puts("");
  BN_print_fp(stdout,Sy);
  puts("");
  */

  EC_POINT_clear_free(P);
  EC_POINT_clear_free(Z);
  EC_POINT_clear_free(trapdoor);
  BN_clear_free(k);
  BN_clear_free(private_key);
  public_key_clear(public_key);
  for(i=0;i<n;i++){
    peks_clear(peks[i]);
  }
  Me_data_clear(me_data);
  BN_CTX_free(ctx);
}
