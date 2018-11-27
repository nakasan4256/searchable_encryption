//gcc -fopenmp -O2 -o pair searchable_encryption_pairing.c -L/usr/local/lib -I/usr/local/include -ltepla -lssl -lcrypto -lgmp

#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<time.h>
#include<omp.h>
#include<gmp.h>
#include<tepla/ec.h>

typedef struct
{
  EC_POINT P;
  EC_POINT Q;
} Public_Key[1];

typedef struct
{
  EC_POINT A;
  Element B;
} Peks[1];

#define public_key_init(pub,ec) do { point_init(pub->P,ec); point_init(pub->Q,ec);} while(0)
#define public_key_clear(pub) do { point_clear(pub->P); point_clear(pub->Q);} while(0)
#define peks_init(peks,ec,f) do{ point_init(peks->A,ec); element_init(peks->B,f);} while(0)
#define peks_clear(peks) do{point_clear(peks->A); element_clear(peks->B);} while(0)

void point_fprint(FILE *outputfile,EC_POINT P){
  unsigned char* os;

  point_to_oct(os,NULL,P);

}

void private_key_create(mpz_t private_key,mpz_t p){
  gmp_randstate_t state;
  gmp_randinit_default(state);
  gmp_randseed_ui(state, (unsigned long int)time(NULL));
  mpz_urandomm(private_key,state,p);
}

void public_key_create(Public_Key public_key,mpz_t private_key,EC_POINT P){
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
  point_init(A,pair->g2);
  point_init(hash,pair->g1);

  point_mul(A,r,public_key->Q);
  hash1(hash,keyword);
  pairing_map(peks->B,hash,A,pair);

  mpz_clear(r);
  point_clear(A);
  point_clear(hash);
}

int test(Peks peks,EC_POINT trapdoor,EC_PAIRING pair){
  Element check;
  int k=-1;
  element_init(check,pair->g3);
  pairing_map(check,trapdoor,peks->A,pair);
  k=element_cmp(check,peks->B);

  element_clear(check);
  return k;
}

int main(void){

  int i,j,n=5;
  int count=1000;
  FILE *outputfile;
  outputfile = fopen("pair.txt", "w");
  if (outputfile == NULL) {
    printf("cannot open\n");
    exit(1);
  }

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
/*
  unsigned char* os;
  size_t *size;
  os=(char *)malloc(1000);
  size=(size_t *)malloc(10);
  point_to_oct(os,size,P);
  for (size_t m = 0; m < 1000; m++ ){
    printf("%02x", os[m] );
  }
*/
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
  gmp_printf("private_key : %ZXd\n",private_key);
  gmp_fprintf(outputfile,"private_key : %ZXd\n",private_key);

  point_set(public_key->P,P);
  public_key_create(public_key,private_key,P);
  printf("公開鍵を計算\n");
  printf("public_key : P ");
  point_print(public_key->P);
  printf("             Q ");
  point_print(public_key->Q);


  start=omp_get_wtime();
  for(i=0;i<count;i++)
    public_key_create(public_key,private_key,P);
  end=omp_get_wtime();
  printf("public_key ave %f seconds\n",(end-start)/count);
  printf("-------------------------------------\n");
  fprintf(outputfile,"public_key ave %f seconds\n",(end-start)/count);
  fprintf(outputfile,"-------------------------------------\n");

  char keyword[n][32];
  Peks peks[n];
  printf("キーワード(検索タグ)を %d 個入力してください\n",n);
  for(i=0;i<n;i++){
    printf("keyword[%d] : ",i);
    scanf("%s",keyword[i]);
    fprintf(outputfile,"keyword[%d] : %s\n",i,keyword[i]);

    peks_init(peks[i],pair->g2,pair->g3);
    keyword_encrypt(peks[i],keyword[i],public_key,pair,p);

    printf("keyword_enc : A ");
    point_print(peks[i]->A);
    printf("              B ");
    element_print(peks[i]->B);
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

  char word[32];
  printf("検索するキーワードを入力してください\n");
  printf("search : ");
  scanf("%s",word);
  fprintf(outputfile,"search : %s\n",word);

  trapdoor_create(trapdoor,private_key,word,pair);

  printf("trapdoor : ");
  point_print(trapdoor);

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
