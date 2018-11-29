//gcc -fopenmp -O2 -o test_pair testcase_pair.c -L/usr/local/lib -I/usr/local/include -ltepla -lssl -lcrypto -lgmp
//gcc -fopenmp -O2 -o test_pair testcase_pair.c -L/home/b1015014/lib -I/home/b1015014/include -ltepla -lssl -lcrypto -lgmp

#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<time.h>
#include<omp.h>
#include<gmp.h>
#include<tepla/ec.h>
#include<openssl/sha.h>

typedef struct
{
  EC_POINT P;
  EC_POINT Q;
} Public_Key[1];

typedef struct
{
  EC_POINT A;
  unsigned char B[SHA256_DIGEST_LENGTH];
} Peks[1];

#define public_key_init(pub,ec) do { point_init(pub->P,ec); point_init(pub->Q,ec);} while(0)
#define public_key_clear(pub) do { point_clear(pub->P); point_clear(pub->Q);} while(0)
#define peks_init(peks,ec) do{ point_init(peks->A,ec);} while(0)
#define peks_clear(peks) do{point_clear(peks->A);} while(0)

char os[500];

void element_fprint(FILE *outputfile,Element e){
  element_get_str(os,e);
  fprintf(outputfile,"%s\n",os);
}

void point_fprint(FILE *outputfile,EC_POINT P){
  point_get_str(os,P);
  fprintf(outputfile,"%s\n",os);
}

void private_key_create(mpz_t private_key,mpz_t p){
  gmp_randstate_t state;
  gmp_randinit_default(state);
  gmp_randseed_ui(state, (unsigned long int)time(NULL));
  mpz_urandomm(private_key,state,p);
}

void public_key_create(Public_Key public_key,mpz_t private_key,EC_POINT P){
  point_set(public_key->P,P);
  point_mul(public_key->Q,private_key,P);
}

void hash1(EC_POINT P,char *keyword){
  point_map_to_point(P,keyword,strlen(keyword),128);
}

void trapdoor_create(EC_POINT trapdoor,mpz_t private_key,char *keyword,EC_PAIRING pair){
  EC_POINT hash;
  point_init(hash,pair->g1);
  hash1(hash,keyword);
  point_mul(trapdoor,private_key,hash);
  point_clear(hash);
}

void keyword_encrypt(Peks peks,char *keyword,Public_Key public_key,EC_PAIRING pair,mpz_t p){
  mpz_t r;
  mpz_init(r);
  gmp_randstate_t state;
  gmp_randinit_default(state);
  gmp_randseed_ui(state, (unsigned long int)time(NULL));
  mpz_urandomm(r,state,p);

  point_mul(peks->A,r,public_key->P);

  EC_POINT A;
  EC_POINT hash;
  Element B;
  point_init(A,pair->g2);
  point_init(hash,pair->g1);
  element_init(B,pair->g3);

  point_mul(A,r,public_key->Q);
  hash1(hash,keyword);
  pairing_map(B,hash,A,pair);
  element_get_str(os,B);
  SHA256(os,strlen(os),peks->B);

  mpz_clear(r);
  point_clear(A);
  point_clear(hash);
  element_clear(B);
}

int test(Peks peks,EC_POINT trapdoor,EC_PAIRING pair){
  Element check;
  element_init(check,pair->g3);
  unsigned char hash[SHA256_DIGEST_LENGTH];

  pairing_map(check,trapdoor,peks->A,pair);
  element_get_str(os,check);
  SHA256(os,strlen(os),hash);

  int k=memcmp(hash,peks->B,32);

  element_clear(check);
  return k;
}

int main(void){

  int i,j,n=5;
  int count=100000;
  FILE *outputfile;
  outputfile = fopen("pair.txt", "w");
  if (outputfile == NULL) {
    printf("cannot open\n");
    exit(1);
  }
  size_t m;
  double start,end;

  mpz_t p;
  mpz_t private_key;
  mpz_inits(p,private_key,NULL);

  EC_PAIRING pair;
  pairing_init(pair,"ECBN254a");

  mpz_set(p,pairing_get_order(pair));

  EC_POINT P;
  point_init(P,pair->g2);
  point_random(P);

  //point_fprint(stdout,P);

  Public_Key public_key;
  public_key_init(public_key,pair->g2);

  printf("テスト回数：%d\n",count);
  printf("テスト単語数：%d\n",n);
  printf("------------------------------------\n");
  fprintf(outputfile,"テスト回数：%d\n",count);
  fprintf(outputfile,"テスト単語数：%d\n",n);
  fprintf(outputfile,"------------------------------------\n");

  private_key_create(private_key,p);
  printf("秘密鍵を決める\n");
  gmp_printf("private_key : %ZX\n",private_key);
  gmp_fprintf(outputfile,"private_key : %ZX\n",private_key);

  public_key_create(public_key,private_key,P);
  printf("公開鍵を計算\n");
  printf("public_key : P ");
  point_print(public_key->P);
  printf("             Q ");
  point_print(public_key->Q);

  fprintf(outputfile,"public_key : P ");
  point_fprint(outputfile,public_key->P);
  fprintf(outputfile,"             Q ");
  point_fprint(outputfile,public_key->Q);

  start=omp_get_wtime();
  for(i=0;i<count;i++)
    public_key_create(public_key,private_key,P);
  end=omp_get_wtime();
  printf("public_key ave %f seconds\n",(end-start)/count);
  printf("-------------------------------------\n");
  fprintf(outputfile,"public_key ave %f seconds\n",(end-start)/count);
  fprintf(outputfile,"-------------------------------------\n");

  char keyword[5][32]={"Alice","Bob","Charlie","Dave","Ellen"};
  Peks peks[n];

  printf("キーワード(検索タグ)を %d 個入力してください\n",n);
  for(i=0;i<n;i++){
    printf("keyword[%d] : %s\n",i,keyword[i]);
    fprintf(outputfile,"keyword[%d] : %s\n",i,keyword[i]);

    peks_init(peks[i],pair->g2);
    keyword_encrypt(peks[i],keyword[i],public_key,pair,p);

    printf("keyword_enc : A ");
    point_print(peks[i]->A);
    printf("              B ");
    for (m = 0; m < SHA256_DIGEST_LENGTH; m++ ){
      printf("%02x", peks[i]->B[m] );
    }
    printf("\n");
    fprintf(outputfile,"keyword_enc : A ");
    point_fprint(outputfile,peks[i]->A);
    fprintf(outputfile,"              B ");
    for (m = 0; m < SHA256_DIGEST_LENGTH; m++ ){
      fprintf(outputfile,"%02x", peks[i]->B[m] );
    }
    fprintf(outputfile,"\n");
  }

  start=omp_get_wtime();
  for(i=0;i<count;i++)
    keyword_encrypt(peks[0],keyword[0],public_key,pair,p);
  end=omp_get_wtime();
  printf("encrypt ave %f seconds\n",(end-start)/count);
  printf("------------------------------------\n");
  fprintf(outputfile,"encrypt ave %f seconds\n",(end-start)/count);
  fprintf(outputfile,"------------------------------------\n");

  EC_POINT trapdoor;
  point_init(trapdoor,pair->g1);

  char word[32]="Bob";
  printf("検索するキーワードを入力してください\n");
  printf("search : %s\n",word);
  fprintf(outputfile,"search : %s\n",word);

  trapdoor_create(trapdoor,private_key,word,pair);

  printf("trapdoor : ");
  point_print(trapdoor);
  fprintf(outputfile,"trapdoor : ");
  point_fprint(outputfile,trapdoor);

  start=omp_get_wtime();
  for(i=0;i<count;i++)
    trapdoor_create(trapdoor,private_key,word,pair);
  end=omp_get_wtime();
  printf("trapdoor ave %f seconds\n",(end-start)/count);
  printf("------------------------------------\n");
  fprintf(outputfile,"trapdoor ave %f seconds\n",(end-start)/count);
  fprintf(outputfile,"------------------------------------\n");

  for(i=0;i<n;i++){
    printf("keyword[%d] : %s ",i,keyword[i]);
    fprintf(outputfile,"keyword[%d] : %s ",i,keyword[i]);
    if(test(peks[i],trapdoor,pair)){
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
      test(peks[i],trapdoor,pair);
    end=omp_get_wtime();
    printf("keyword[%d] test ave %f seconds\n",i,(end-start)/count);
    fprintf(outputfile,"keyword[%d] test ave %f seconds\n",i,(end-start)/count);
  }

  mpz_clears(p,private_key,NULL);

  point_clear(trapdoor);
  point_clear(P);

  for(i=0;i<n;i++){
    peks_clear(peks[i]);
  }
  public_key_clear(public_key);
  pairing_clear(pair);
  fclose(outputfile);
}
