//gcc -fopenmp -O2 -o pair searchable_encryption_pairing.c -L/usr/local/lib -I/usr/local/include -ltepla -lssl -lcrypto -lgmp

#include<stdio.h>
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

void private_key_create(mpz_t private_key,mpz_t limit){

  gmp_randstate_t state;
  gmp_randinit_default(state);
  gmp_randseed_ui(state, (unsigned long int)time(NULL));
  mpz_urandomm(private_key,state,limit);

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

void keyword_encrypt(Peks peks,char *keyword,Public_Key public_key,EC_PAIRING pair,mpz_t limit){

  mpz_t r;
  mpz_init(r);
  gmp_randstate_t state;
  gmp_randinit_default(state);
  gmp_randseed_ui(state, (unsigned long int)time(NULL));
  mpz_urandomm(r,state,limit);

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
  /*
  double start,end;
  start=omp_get_wtime();
  for(i=0;i<5000;i++)
    private_key_create(private_key,limit);
  end=omp_get_wtime();
  printf("time : %f seconds\n",(end-start)/5000);
  */
  int i;

  mpz_t limit;
  mpz_t private_key;
  mpz_inits(limit,private_key,NULL);

  EC_PAIRING pair;
  pairing_init(pair,"ECBN254a");
  EC_POINT P;
  point_init(P,pair->g2);
  point_random(P);

  Public_Key public_key;
  public_key_init(public_key,pair->g2);

  mpz_set_ui(limit,2);
  mpz_pow_ui(limit,limit,254);
  private_key_create(private_key,limit);
  gmp_printf("private_key : %Zd\n",private_key);

  public_key_create(public_key,private_key,P);
  printf("public_key : \n");
  point_print(public_key->P);
  point_print(public_key->Q);
  printf("-------------------------------------\n");

  /*
  EC_POINT hash;
  point_init(hash,ec);
  char *s="nakasan1";
  printf("%d\n",strlen(s));
  hash1(hash,s);
  point_print(hash);
  */


  int n=5;
  char keyword[n][128];

  Peks peks[n];
  for(i=0;i<n;i++){
    printf("keyword[%d] : ",i);
    scanf("%s",keyword[i]);
    peks_init(peks[i],pair->g2,pair->g3);
    keyword_encrypt(peks[i],keyword[i],public_key,pair,limit);
  }

  EC_POINT trapdoor;
  point_init(trapdoor,pair->g1);

  while(1){
    char word[128];
    printf("search : ");
    scanf("%s",word);

    trapdoor_create(trapdoor,private_key,word,pair);

    for(i=0;i<n;i++){
      if(test(peks[i],trapdoor,pair)==0){
        printf("keyword[%d] : %s Good!\n",i,keyword[i]);
      }else{
        printf("keyword[%d] : %s bad!\n",i,keyword[i]);
      }
    }
  }
/*
  EC_POINT trapdoor;
  point_init(trapdoor,pair->g1);
//  char *keyword="nakanakanasdfew";
//  char *keyword_2="akdnfqewpqe";
  trapdoor_create(trapdoor,private_key,keyword,pair->g1);
  //point_print(trapdoor);

  Peks peks;
  peks_init(peks,pair->g2,pair->g3);
  keyword_encrypt(peks,keyword,public_key,pair,limit);
  //point_print(peks->A);
  //element_print(peks->B);

  printf("test : %d\n",test(peks,trapdoor,pair));
*/

  mpz_clears(limit,private_key,NULL);

  point_clear(trapdoor);
  point_clear(P);

  for(i=0;i<n;i++){
    peks_clear(peks[i]);
  }
  //point_clear(hash);
  public_key_clear(public_key);
  pairing_clear(pair);

  return 0;
}
