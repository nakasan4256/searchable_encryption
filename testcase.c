//secp192k1 711 secp256k1 714 openssl/obj_mac.h
//gcc -fopenmp -O2 -o testcase testcase.c -L/usr/local/lib -I/usr/local/include -lssl -lcrypto -lgmp
//gcc -fopenmp -O2 -o testcase testcase.c -L/home/b1015014/lib -I/home/b1015104/include -lssl -lcrypto -lgmp
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
  mpz_t p_mpz2;//(p+1)/4
  BIGNUM *order;//位数
  EC_POINT *Z;//Meスカラー倍の補助元
  int Z_sign;//補助元のsignの値
  BIGNUM *k;//k>1
}Me_DATA[1];

typedef struct//公開鍵
{
  EC_POINT *P;//ベースポイント
  EC_POINT *Q;//P_a,Z
} Public_Key[1];

typedef struct//trapdoor
{
  EC_POINT *H;//H(w)_a,Z
} Trapdoor[1];

typedef struct//暗号化されたキーワード
{
  EC_POINT *A;//P_r,Z
  unsigned char C[SHA256_DIGEST_LENGTH];//h(H(w)+Q_r,Z)
} Peks[1];

#define mpz_mul_mod(a,b,c,p) do { mpz_mul(a,b,c); mpz_mod(a,a,p); } while(0)
#define Me_data_init(me_data) do { me_data->ec=EC_GROUP_new_by_curve_name(714); me_data->a=BN_new(); me_data->b=BN_new(); me_data->p=BN_new(); mpz_inits(me_data->p_mpz,me_data->p_mpz2,NULL); me_data->order=BN_new(); me_data->Z=EC_POINT_new(me_data->ec); me_data->k=BN_new(); } while(0)
#define Me_data_set(me_data) do { EC_GROUP_get_curve_GFp(me_data->ec,me_data->p,me_data->a,me_data->b,NULL); char *str; str=BN_bn2hex(me_data->p); mpz_set_str(me_data->p_mpz,str,16); free(str); mpz_add_ui(me_data->p_mpz2,me_data->p_mpz,1); mpz_tdiv_q_ui(me_data->p_mpz2,me_data->p_mpz2,4); EC_GROUP_get_order(me_data->ec,me_data->order,NULL); } while(0)
#define Me_data_set_Zk(me_data,Z,k) do { EC_POINT_copy(me_data->Z,Z); BN_copy(me_data->k,k); } while(0)
#define Me_data_clear(me_data) do { EC_POINT_clear_free(me_data->Z); BN_clear_free(me_data->k); BN_clear_free(me_data->p); } while(0)
#define public_key_init(pub,me_data) do { pub->P=EC_POINT_new(me_data->ec); pub->Q=EC_POINT_new(me_data->ec);} while(0)
#define public_key_clear(pub) do { EC_POINT_clear_free(pub->P); EC_POINT_clear_free(pub->Q);} while(0)
#define trapdoor_init(trapdoor,me_data) do { trapdoor->H=EC_POINT_new(me_data->ec);} while(0)
#define trapdoor_clear(trapdoor) do { EC_POINT_clear_free(trapdoor->H);} while(0)
#define peks_init(peks,me_data) do { peks->A=EC_POINT_new(me_data->ec);} while(0)
#define peks_clear(peks) do { EC_POINT_clear_free(peks->A);} while(0)

void EC_POINT_print(const EC_POINT *P,const Me_DATA me_data,BN_CTX *ctx){
  BN_CTX_start(ctx);
  BIGNUM *Px,*Py;
  Px=BN_CTX_get(ctx);
  Py=BN_CTX_get(ctx);
  EC_POINT_get_affine_coordinates_GFp(me_data->ec,P,Px,Py,ctx);

  fprintf(stdout,"[ ");
  BN_print_fp(stdout,Px);
  fprintf(stdout," , ");
  BN_print_fp(stdout,Py);
  fprintf(stdout," ]");
  puts("");

  BN_CTX_end(ctx);
}

void EC_POINT_fprint(FILE *outputfile,const EC_POINT *P,const Me_DATA me_data,BN_CTX *ctx){
  BN_CTX_start(ctx);
  BIGNUM *Px,*Py;
  Px=BN_CTX_get(ctx);
  Py=BN_CTX_get(ctx);

  EC_POINT_get_affine_coordinates_GFp(me_data->ec,P,Px,Py,ctx);

  fprintf(outputfile,"[ ");
  BN_print_fp(outputfile,Px);
  fprintf(outputfile," , ");
  BN_print_fp(outputfile,Py);
  fprintf(outputfile," ]\n");

  BN_CTX_end(ctx);
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
  BN_CTX_end(ctx);
  return k;
}

void Me(EC_POINT *R,const EC_POINT *P,const EC_POINT *Q,const Me_DATA me_data,BN_CTX *ctx){
  EC_POINT *AA,*minus;
  AA=EC_POINT_new(me_data->ec);
  minus=EC_POINT_new(me_data->ec);

  EC_POINT_copy(minus,Q);
  EC_POINT_invert(me_data->ec,minus,ctx);
  EC_POINT_add(me_data->ec,AA,P,minus,ctx);

  int sign=Sign(me_data,AA,ctx);
  if(EC_POINT_is_at_infinity(me_data->ec,AA)){
    EC_POINT_copy(R,P);
  }else if(sign==-1){
    EC_POINT_dbl(me_data->ec,AA,Q,ctx);
    EC_POINT_copy(minus,P);
    EC_POINT_invert(me_data->ec,minus,ctx);
    EC_POINT_add(me_data->ec,R,AA,minus,ctx);
  }else if(sign==1){
    EC_POINT_dbl(me_data->ec,AA,P,ctx);
    EC_POINT_add(me_data->ec,R,AA,minus,ctx);
  }else{
    EC_POINT_set_to_infinity(me_data->ec,R);//error
    printf("error!!!!\n");
  }
  EC_POINT_clear_free(AA);
  EC_POINT_clear_free(minus);
}

void Me_Z(EC_POINT *R,const EC_POINT *P,const EC_POINT *Q,const Me_DATA me_data,BN_CTX *ctx){
  EC_POINT *dbl,*minus;
  dbl=EC_POINT_new(me_data->ec);
  minus=EC_POINT_new(me_data->ec);

  if(EC_POINT_is_at_infinity(me_data->ec,me_data->Z)){
    EC_POINT_copy(R,P);
  }else if(me_data->Z_sign==-1){
    EC_POINT_dbl(me_data->ec,dbl,Q,ctx);
    EC_POINT_copy(minus,P);
    EC_POINT_invert(me_data->ec,minus,ctx);
    EC_POINT_add(me_data->ec,R,dbl,minus,ctx);
  }else if(me_data->Z_sign==1){
    EC_POINT_dbl(me_data->ec,dbl,P,ctx);
    EC_POINT_copy(minus,Q);
    EC_POINT_invert(me_data->ec,minus,ctx);
    EC_POINT_add(me_data->ec,R,dbl,minus,ctx);
  }else{
    EC_POINT_set_to_infinity(me_data->ec,R);//error
    printf("error!!!!\n");
  }
  EC_POINT_clear_free(dbl);
  EC_POINT_clear_free(minus);
}

void Me_mul_1(EC_POINT *R, const EC_POINT *P,const BIGNUM *n,const Me_DATA me_data){
  BN_CTX *ctx;
  ctx=BN_CTX_secure_new();

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
}

void private_key_create(BIGNUM *private_key,const Me_DATA me_data){
  BN_rand_range(private_key,me_data->order);
}

void public_key_create(Public_Key public_key,const BIGNUM *private_key,const EC_POINT *base,const Me_DATA me_data){
  EC_POINT_copy(public_key->P,base);
  Me_mul_1(public_key->Q,base,private_key,me_data);
}

void hash1(EC_POINT *P,const unsigned char *keyword,const Me_DATA me_data,BN_CTX *ctx){
  BIGNUM *x0,*y0;
  BN_CTX_start(ctx);
  x0=BN_CTX_get(ctx);
  y0=BN_CTX_get(ctx);

	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256(keyword,strlen(keyword),hash);
  BN_bin2bn(hash,32,x0);
  do{
    BN_add_word(x0,1);
    BN_mod_sqr(y0,x0,me_data->p,ctx);
    BN_mod_mul(y0,y0,x0,me_data->p,ctx);
    BN_add_word(y0,7);
  }while(BN_kronecker(y0,me_data->p,ctx)<1);
  BN_mod_sqrt(y0,y0,me_data->p,ctx);
  EC_POINT_set_affine_coordinates_GFp(me_data->ec,P,x0,y0,ctx);

  BN_CTX_end(ctx);
}

void hash1_mpz(EC_POINT *P,const unsigned char *keyword,const Me_DATA me_data,BN_CTX *ctx){
  BIGNUM **xx0,**yy0;
  BIGNUM *x0,*y0;
  BN_CTX_start(ctx);
  x0=BN_new();
  y0=BN_new();
  xx0=&x0;
  yy0=&y0;

  mpz_t X0,Y0;
  mpz_inits(X0,Y0,NULL);
  int i;

	unsigned char hash[SHA256_DIGEST_LENGTH];
  char aa[SHA256_DIGEST_LENGTH*2+1];
	SHA256(keyword,strlen(keyword),hash);

  for(i=0;i<SHA256_DIGEST_LENGTH;i++)
    sprintf(aa+i*2,"%02x",hash[i]);
  aa[SHA256_DIGEST_LENGTH*2]='\0';
  mpz_set_str(X0,aa,16);

  do{
    //BN_add_word(x0,1);
    //BN_mod_sqr(y0,x0,me_data->p,ctx);
    //BN_mod_mul(y0,y0,x0,me_data->p,ctx);
    //BN_add_word(y0,7);

    mpz_add_ui(X0,X0,1);
    mpz_powm_ui(Y0,X0,3,me_data->p_mpz);
    mpz_add_ui(Y0,Y0,7);
  }while(mpz_kronecker(Y0,me_data->p_mpz)<1);
  //BN_mod_sqrt(y0,y0,me_data->p,ctx);
  mpz_powm(Y0,Y0,me_data->p_mpz2,me_data->p_mpz);
  char *str_x,*str_y;
  str_x=mpz_get_str(NULL,16,X0);
  str_y=mpz_get_str(NULL,16,Y0);
  BN_hex2bn(xx0,str_x);
  BN_hex2bn(yy0,str_y);

  EC_POINT_set_affine_coordinates_GFp(me_data->ec,P,x0,y0,ctx);

  free(str_x);
  free(str_y);
  BN_CTX_end(ctx);
}

void trapdoor_create(Trapdoor trapdoor,const BIGNUM *private_key,const char *keyword,const Me_DATA me_data,BN_CTX *ctx){
  hash1(trapdoor->H,keyword,me_data,ctx);
  Me_mul_1(trapdoor->H,trapdoor->H,private_key,me_data);
}

void trapdoor_create_mpz(Trapdoor trapdoor,const BIGNUM *private_key,const char *keyword,const Me_DATA me_data,BN_CTX *ctx){
  hash1_mpz(trapdoor->H,keyword,me_data,ctx);
  Me_mul_1(trapdoor->H,trapdoor->H,private_key,me_data);
}

void keyword_encrypt(Peks peks,const unsigned char *keyword,const Public_Key public_key,const Me_DATA me_data){
  BN_CTX *ctx;
  ctx=BN_CTX_secure_new();
  BIGNUM *r;
  r=BN_new();
  EC_POINT *C1;
  EC_POINT *C2;
  C1=EC_POINT_new(me_data->ec);
  C2=EC_POINT_new(me_data->ec);
  unsigned char *a=NULL;

  BN_rand_range(r,me_data->order);

  Me_mul_1(peks->A,public_key->P,r,me_data);
  hash1(C1,keyword,me_data,ctx);
  EC_POINT_copy(C2,public_key->P);
  EC_POINT_invert(me_data->ec,C2,ctx);
  EC_POINT_add(me_data->ec,C1,C1,C2,ctx);
  EC_POINT_add(me_data->ec,C1,C1,public_key->Q,ctx);
  EC_POINT_add(me_data->ec,C1,C1,peks->A,ctx);

  EC_POINT_get_affine_coordinates_GFp(me_data->ec,C1,r,NULL,ctx);
  a = (unsigned char *)malloc(BN_num_bytes(r));
  a = BN_bn2hex(r);
  SHA256(a,strlen(a),peks->C);

  free(a);
  EC_POINT_clear_free(C1);
  EC_POINT_clear_free(C2);
  BN_clear_free(r);
  BN_CTX_free(ctx);
}

void keyword_encrypt_mpz(Peks peks,const unsigned char *keyword,const Public_Key public_key,const Me_DATA me_data){
  BN_CTX *ctx;
  ctx=BN_CTX_secure_new();
  BIGNUM *r;
  r=BN_new();
  EC_POINT *C1;
  EC_POINT *C2;
  C1=EC_POINT_new(me_data->ec);
  C2=EC_POINT_new(me_data->ec);
  unsigned char *a=NULL;

  BN_rand_range(r,me_data->order);

  Me_mul_1(peks->A,public_key->P,r,me_data);
  hash1_mpz(C1,keyword,me_data,ctx);
  EC_POINT_copy(C2,public_key->P);
  EC_POINT_invert(me_data->ec,C2,ctx);
  EC_POINT_add(me_data->ec,C1,C1,C2,ctx);
  EC_POINT_add(me_data->ec,C1,C1,public_key->Q,ctx);
  EC_POINT_add(me_data->ec,C1,C1,peks->A,ctx);

  EC_POINT_get_affine_coordinates_GFp(me_data->ec,C1,r,NULL,ctx);
  a = (unsigned char *)malloc(BN_num_bytes(r));
  a = BN_bn2hex(r);
  SHA256(a,strlen(a),peks->C);

  free(a);
  EC_POINT_clear_free(C1);
  EC_POINT_clear_free(C2);
  BN_clear_free(r);
  BN_CTX_free(ctx);
}

int test(const Peks peks,const Trapdoor trapdoor,const Me_DATA me_data){
  BN_CTX *ctx;
  ctx=BN_CTX_secure_new();
  EC_POINT *check;
  BIGNUM *x0;
  check=EC_POINT_new(me_data->ec);
  x0=BN_new();
  unsigned char *a=NULL;
  unsigned char hash[SHA256_DIGEST_LENGTH];

  EC_POINT_add(me_data->ec,check,peks->A,trapdoor->H,ctx);
  EC_POINT_get_affine_coordinates_GFp(me_data->ec,check,x0,NULL,ctx);
  a = (unsigned char *)malloc(BN_num_bytes(x0));
  a = BN_bn2hex(x0);
  SHA256(a,strlen(a),hash);

  int k=memcmp(hash,peks->C,32);
  EC_POINT_clear_free(check);
  BN_clear_free(x0);
  BN_CTX_free(ctx);
  free(a);
  return k;
}

int main(void){
  int i,j,n=5;//テスト用キーワードの個数
  int count=10000;//テスト実行回数
  FILE *outputfile;
  outputfile = fopen("d.txt", "w");
  if (outputfile == NULL) {
    printf("cannot open\n");
    exit(1);
  }
  size_t m;

  double start,end;
  /*start=omp_get_wtime();
  for(i=0;i<5000;i++)
    keyword_encrypt(peks[0],keyword[0],public_key,me_data);
  end=omp_get_wtime();
  printf("encrypt %f seconds\n",(end-start)/5000);
  */
  BN_CTX *ctx;
  ctx=BN_CTX_secure_new();

  Me_DATA me_data;
  Me_data_init(me_data);
  Me_data_set(me_data);

  EC_POINT *P,*Z;
  P=EC_POINT_new(me_data->ec);
  Z=EC_POINT_new(me_data->ec);
  BIGNUM *k,*private_key;
  k=BN_new();
  private_key=BN_new();

  Public_Key public_key;
  public_key_init(public_key,me_data);

  Trapdoor trapdoor;
  trapdoor_init(trapdoor,me_data);

  BN_rand_range(k,me_data->order);
  EC_POINT_mul(me_data->ec,Z,k,NULL,NULL,ctx);
  BN_set_word(k,2);

  Me_data_set_Zk(me_data,Z,k);
  me_data->Z_sign=Sign(me_data,Z,ctx);
  P=EC_GROUP_get0_generator(me_data->ec);

  hash1(P,"keyword",me_data,ctx);
  EC_POINT_print(P,me_data,ctx);
  hash1_mpz(P,"keyword",me_data,ctx);
  EC_POINT_print(P,me_data,ctx);

  printf("テスト回数：%d\n",count);
  printf("テスト単語数：%d\n",n);
  printf("------------------------------------\n");
  fprintf(outputfile,"テスト回数：%d\n",count);
  fprintf(outputfile,"テスト単語数：%d\n",n);
  fprintf(outputfile,"------------------------------------\n");

  printf("補助元 Z を決める\n");
  printf("Z : ");
  EC_POINT_print(Z,me_data,ctx);
  fprintf(outputfile,"Z : ");
  EC_POINT_fprint(outputfile,Z,me_data,ctx);

  private_key_create(private_key,me_data);
  //BN_set_word(private_key,100);
  printf("秘密鍵を決める\n");
  printf("private_key : ");
  BN_print_fp(stdout,private_key);
  puts("");
  fprintf(outputfile,"private_key : ");
  BN_print_fp(outputfile,private_key);
  fprintf(outputfile,"\n");

  public_key_create(public_key,private_key,P,me_data);
  printf("公開鍵を計算\n");
  printf("public_key : P ");
  EC_POINT_print(public_key->P,me_data,ctx);
  printf("             Q ");
  EC_POINT_print(public_key->Q,me_data,ctx);
  fprintf(outputfile,"public_key : P ");
  EC_POINT_fprint(outputfile,public_key->P,me_data,ctx);
  fprintf(outputfile,"             Q ");
  EC_POINT_fprint(outputfile,public_key->Q,me_data,ctx);

  start=omp_get_wtime();
  for(i=0;i<count;i++)
     public_key_create(public_key,private_key,P,me_data);
  end=omp_get_wtime();
  //printf("public_key %f seconds\n",(end-start));
  printf("public_key ave %f seconds\n",(end-start)/count);
  printf("------------------------------------\n");
  //fprintf(outputfile,"public_key %f seconds\n",(end-start));
  fprintf(outputfile,"public_key ave %f seconds\n",(end-start)/count);
  fprintf(outputfile,"------------------------------------\n");

  unsigned char keyword[5][32]={"Alice","Bob","Charlie","Dave","Ellen"};
  Peks peks[n];
  printf("キーワード(検索タグ)を %d 個入力してください\n",n);
  for(i=0;i<n;i++){//1度暗号化
    printf("keyword[%d] : %s\n",i,keyword[i]);
    fprintf(outputfile,"keyword[%d] : %s\n",i,keyword[i]);

    peks_init(peks[i],me_data);
    keyword_encrypt(peks[i],keyword[i],public_key,me_data);

    printf("keyword_enc : A ");
    EC_POINT_print(peks[i]->A,me_data,ctx);
    printf("              C ");
    for (m = 0; m < SHA256_DIGEST_LENGTH; m++ ){
      printf("%02x", peks[i]->C[m] );
    }
    printf("\n");
    fprintf(outputfile,"keyword_enc : A ");
    EC_POINT_fprint(outputfile,peks[i]->A,me_data,ctx);
    fprintf(outputfile,"              C ");
    for (m = 0; m < SHA256_DIGEST_LENGTH; m++ ){
      fprintf(outputfile,"%02x", peks[i]->C[m] );
    }
    fprintf(outputfile,"\n");
  }

  for(i=0;i<n;i++){
    start=omp_get_wtime();
    for(j=0;j<count;j++)
      keyword_encrypt(peks[i],keyword[i],public_key,me_data);
    end=omp_get_wtime();
    printf("encrypt keyword[%d] ave %f seconds\n",i,(end-start)/count);
    fprintf(outputfile,"encrypt keyword[%d] ave %f seconds\n",i,(end-start)/count);
  }

  for(i=0;i<n;i++){
    start=omp_get_wtime();
    for(j=0;j<count;j++)
      keyword_encrypt_mpz(peks[i],keyword[i],public_key,me_data);
    end=omp_get_wtime();
    printf("encrypt keyword[%d] mpz %f seconds\n",i,(end-start)/count);
    fprintf(outputfile,"encrypt keyword[%d] mpz %f seconds\n",i,(end-start)/count);
  }

  printf("------------------------------------\n");
  fprintf(outputfile,"------------------------------------\n");

  unsigned char word[32]="Bob";
  printf("検索するキーワードを入力してください\n");
  printf("search : %s\n",word);
  fprintf(outputfile,"search : %s\n",word);

  trapdoor_create(trapdoor,private_key,word,me_data,ctx);

  printf("trapdoor : ");
  EC_POINT_print(trapdoor->H,me_data,ctx);
  fprintf(outputfile,"trapdoor : ");
  EC_POINT_fprint(outputfile,trapdoor->H,me_data,ctx);

  start=omp_get_wtime();
  for(i=0;i<count;i++)
    trapdoor_create(trapdoor,private_key,word,me_data,ctx);
  end=omp_get_wtime();

  printf("trapdoor ave %f seconds\n",(end-start)/count);
  fprintf(outputfile,"trapdoor ave %f seconds\n",(end-start)/count);
  printf("------------------------------------\n");
  fprintf(outputfile,"------------------------------------\n");

  start=omp_get_wtime();
  for(i=0;i<count;i++)
    trapdoor_create_mpz(trapdoor,private_key,word,me_data,ctx);
  end=omp_get_wtime();

  printf("trapdoor mpz %f seconds\n",(end-start)/count);
  fprintf(outputfile,"trapdoor mpz %f seconds\n",(end-start)/count);
  printf("------------------------------------\n");
  fprintf(outputfile,"------------------------------------\n");

  for(i=0;i<n;i++){
    printf("keyword[%d] : %s ",i,keyword[i]);
    fprintf(outputfile,"keyword[%d] : %s ",i,keyword[i]);
    if(test(peks[i],trapdoor,me_data)){
      printf("---test fail!!---\n");
      fprintf(outputfile,"---test fail!!---\n");
    }else{
      printf("---test success!!---\n");
      fprintf(outputfile,"---test success!!---\n");
    }
  }
  printf("------------------------------------\n");
  fprintf(outputfile,"------------------------------------\n");

  for(i=0;i<n;i++){
    start=omp_get_wtime();
    for(j=0;j<count;j++)
      test(peks[i],trapdoor,me_data);
    end=omp_get_wtime();
    //printf("test[%d] %f seconds\n",i,(end-start));
    printf("keyword[%d] test ave %f seconds\n",i,(end-start)/count);
    fprintf(outputfile,"keyword[%d] test ave %f seconds\n",i,(end-start)/count);
  }

  EC_POINT_clear_free(P);
  EC_POINT_clear_free(Z);
  BN_clear_free(k);
  BN_clear_free(private_key);
  public_key_clear(public_key);
  trapdoor_clear(trapdoor);
  for(i=0;i<n;i++){
    peks_clear(peks[i]);
  }
  Me_data_clear(me_data);
  BN_CTX_free(ctx);
  fclose(outputfile);
}
