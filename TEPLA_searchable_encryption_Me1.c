#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<time.h>
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
  EC_POINT B;
} Peks[1];

#define public_key_init(pub,ec) do { point_init(pub->P,ec); point_init(pub->Q,ec);} while(0)
#define public_key_clear(pub) do { point_clear(pub->P); point_clear(pub->Q);} while(0)

#define peks_init(peks,ec) do{ point_init(peks->A,ec); point_init(peks->B,ec);} while(0)
#define peks_clear(peks) do{point_clear(peks->A); point_clear(peks->B);} while(0)

int Sign(EC_POINT P,const mpz_t p){
  int k=0;
  char str[1000];
  char *y;
  char *x;
  mpz_t y0;
  mpz_init(y0);
  point_get_str(str,P);
  x=strtok(str+1,",");
  y=strtok(str+2+strlen(x),"]");
  //printf("%s\n",y);
  mpz_set_str(y0,y,16);
  //gmp_printf("y0 : %Zd\n",y0);

  k=mpz_legendre(y0,p);
  return k;
}

void Me(EC_POINT R,const EC_POINT P,const EC_POINT Q,const EC_GROUP ec,const mpz_t k,const mpz_t p){
  mpz_t k_1;
  mpz_init(k_1);
  mpz_sub_ui(k_1,k,1);

  EC_POINT kP;
  EC_POINT kQ;
  point_init(kP,ec);
  point_init(kQ,ec);

  point_sub(R,P,Q);
  printf("Me : \n");
  if(point_is_infinity(R)==1){
    point_set(R,P);
  }else if(Sign(R,p)==1){
    point_mul(kP,k,P);
    point_mul(kQ,k_1,Q);
    point_sub(R,kP,kQ);
  }else if(Sign(R,p)==-1){
    point_mul(kQ,k,Q);
    point_mul(kP,k_1,P);
    point_sub(R,kQ,kP);
  }else{
    point_set_infinity(R);//error
  }

  mpz_clear(k_1);
  point_clear(kP);
  point_clear(kQ);
}

void Me_mul_1(EC_POINT R,const EC_POINT P,const mpz_t n,const EC_GROUP ec,const EC_POINT Z,const mpz_t k,const mpz_t p){
  EC_POINT Y;
  point_init(Y,ec);
  EC_POINT ZY;
  point_init(ZY,ec);

  char *str;
  int i,len;
  str=mpz_get_str(NULL,2,n);
  len=strlen(str);

  point_set(Y,P);
  for(i=1;i<len;i++){
    point_add(ZY,Z,Y);
    Me(Y,ZY,Y,ec,k,p);
    if(str[i]=='1'){
      Me(Y,Y,P,ec,k,p);
    }
  }
  point_set(R,Y);

  point_clear(Y);
  point_clear(ZY);
}

int main(void){

  mpz_t k,p,ff;
  mpz_inits(k,p,ff,NULL);
  mpz_set_ui(k,100);
  mpz_set_ui(ff,4);

  EC_GROUP ec;
  curve_init(ec,"ec_bn254_fpb");
  mpz_set(p,*curve_get_order(ec));
  mpz_mod(ff,p,ff);
  gmp_printf("%Zd\n",ff);
  //gmp_printf("%Zd\n",p);

  EC_POINT P;
  point_init(P,ec);
  point_random(P);
  printf("P : ");
  point_print(P);

  EC_POINT Q;
  point_init(Q,ec);
  point_random(Q);
  printf("Q : ");
  point_print(Q);

  EC_POINT R;
  point_init(R,ec);
  EC_POINT S;
  point_init(S,ec);
  printf("---------------------------\n");

  Me(R,P,Q,ec,k,p);
  printf("R : ");
  point_print(R);
  Me(S,Q,P,ec,k,p);
  printf("S : ");
  point_print(S);
}
