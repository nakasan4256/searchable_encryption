//gcc -fopenmp -O2 -o test gmp_bignum.c -L/home/b1015014/lib -I/home/b1015014/include -lssl -lcrypto -lgmp
#include<stdio.h>
#include<string.h>
#include<time.h>
#include<omp.h>
#include<gmp.h>
#include<openssl/bn.h>

typedef struct{
  mpz_t x;
  mpz_t y;
  mpz_t z;
}gmp_EC_POINT[1];

#define gmp_EC_POINT_init(p) do { mpz_inits(p->x,p->y,p->z,NULL); } while(0)
#define gmp_EC_POINT_set(p,X,Y,Z) do { mpz_set(p->x,X); mpz_set(p->y,Y); mpz_set(p->z,Z); } while(0)
#define gmp_EC_POINT_clear(p) do { mpz_clears(p->x,p->y,p->z,NULL)} while(0)
#define mpz_add_mod(a,b,c,p) do { mpz_add(a,b,c); mpz_mod(a,a,p); } while(0)
#define mpz_sub_mod(a,b,c,p) do { mpz_sub(a,b,c); mpz_mod(a,a,p); } while(0)
#define mpz_mul_mod(a,b,c,p) do { mpz_mul(a,b,c); mpz_mod(a,a,p); } while(0)

void gmp_point_add(gmp_EC_POINT R,const gmp_EC_POINT P,const gmp_EC_POINT Q,const mpz_t p){
  //y^2=x^3+7 mod p
  mpz_t Z1Z1,Z2Z2,U1,U2,S1,S2,H,I,J,r,V,aa;
  mpz_inits(Z1Z1,Z2Z2,U1,U2,S1,S2,H,I,J,r,V,aa,NULL);

  mpz_pow_ui(Z1Z1,P->z,2,p);
  mpz_pow_ui(Z2Z2,Q->z,2,p);
  mpz_mul_mod(U1,P->x,Z2Z2,p);
  mpz_mul_mod(U2,Q->x,Z1Z1,p);

  mpz_mul_mod(S1,P->y,Q->z,p);
  mpz_mul_mod(S1,S1,Z2Z2,p);

  mpz_mul_mod(S2,Q->y,P->z,p);
  mpz_mul_mod(S2,S2,Z1Z1,p);

  mpz_sub_mod(H,U2,U1,p);
  mpz_mul_ui(I,H,2);
  mpz_pow_ui(I,I,2,p);
  mpz_mul_mod(J,H,I,p);
  mpz_sub_mod(r,S2,S1,p);
  mpz_mul_ui(r,r,2);
  mpz_mod(r,r,p);
  mpz_mul_mod(V,U1,I,p);

  mpz_pow_ui(R->x,r,2,p);
  mpz_sub_mod(R->x,R->x,J,p);
  mpz_mul_ui(aa,V,2);
  mpz_sub_mod(R->x,R->x,aa,p);

  mpz_sub_mod(R->y,V,R->x,p);
  mpz_mul_mod(R->y,R->y,r,p);
  mpz_mul_ui(aa,S1,2);
  mpz_mul_mod(aa,aa,J,p);
  mpz_sub_mod(R->y,R->y,aa,p);

  mpz_add_mod(R->z,Z1,Z2,p);
  mpz_pow_ui(R->z,R->z,2,p);
  mpz_sub_mod(R->z,R->z,Z1Z1,p);
  mpz_sub_mod(R->z,R->z,Z2Z2,p);
  mpz_mul_mod(R->z,R->z,H,p);

  mpz_clears(Z1Z1,Z2Z2,U1,U2,S1,S2,H,I,J,r,V,aa,NULL);
}

void gmp_point_double(gmp_EC_POINT R,const gmp_EC_POINT P,const mpz_t p){
  //y^2=x^3+7 mod p
  mpz_t A,B,C,D,E,F;
  mpz_inits(A,B,C,D,E,F,NULL);

  mpz_pow_ui(A,P->x,2,p);
  mpz_pow_ui(B,P->y,2,p);
  mpz_pow_ui(C,B,2,p);

  mpz_add_mod(D,P->x,B,p);
  mpz_pow_ui(D,D,2,p);
  mpz_sub_mod(D,D,A,p);
  mpz_sub_mod(D,D,C,p);
  mpz_mul_ui(D,D,2);
  mpz_mod(D,D,p);

  mpz_mul_ui(E,A,3);
  mpz_mod(E,E,p);
  mpz_pow_ui(F,E,2,p);

  mpz_mul_ui(R->x,D,2);
  mpz_sub_mod(R->x,F,R->x,p);

  mpz_sub_mod(R->y,D,R->x,p);
  mpz_mul_mod(R->y,R->y,E,p);
  mpz_mul_ui(C,C,8);
  mpz_mod(C,C,p);
  mpz_sub_mod(R->y,R->y,C,p);

  mpz_mul_ui(R->z,P->y,2);
  mpz_mul_mod(R->z,R->z,P->z,p);

  mpz_clears(A,B,C,D,E,F,NULL);
}

int main(){
  double start,end;
  int i,len;

  BN_CTX *ctx;
  ctx=BN_CTX_new();
  BIGNUM *a,*b,*c,*d,*e,*p,*order;

  a=BN_new();
  b=BN_new();
  c=BN_new();
  d=BN_new();
  e=BN_new();
  p=BN_new();
  order=BN_new();

  BN_one(order);
  BN_lshift(order,order,256);//order=2^256

  BN_rand_range(a,order);
  BN_rand_range(b,order);
  BN_rand_range(p,order);
  printf("a : ");
  BN_print_fp(stdout,a);
  puts("");
  printf("b : ");
  BN_print_fp(stdout,b);
  puts("");
  printf("p : ");
  BN_print_fp(stdout,p);
  puts("");

  printf("-----------------------------\n");

  char *AA,*BB,*PP;
  AA=BN_bn2hex(a);
  BB=BN_bn2hex(b);
  PP=BN_bn2hex(p);

  start=omp_get_wtime();
  for(i=0;i<1000000;i++)
    BN_mod_add(c,a,b,p,ctx);
  end=omp_get_wtime();
  printf("a+b mod p : ");
  BN_print_fp(stdout,c);
  puts("");
  printf("openssl a+b mod p : %f seconds\n",(end-start));

  start=omp_get_wtime();
  for(i=0;i<1000000;i++)
    BN_mod_sub(c,a,b,p,ctx);
  end=omp_get_wtime();
  printf("a-b mod p : ");
  BN_print_fp(stdout,c);
  puts("");
  printf("openssl a-b mod p : %f seconds\n",(end-start));

  start=omp_get_wtime();
  for(i=0;i<1000000;i++)
    BN_mod_mul(c,a,b,p,ctx);
  end=omp_get_wtime();
  printf("a*b mod p : ");
  BN_print_fp(stdout,c);
  puts("");
  printf("openssl a*b mod p : %f seconds\n",(end-start));

  start=omp_get_wtime();
  for(i=0;i<100000;i++){
    BN_mod_inverse(c,a,p,ctx);
  }
  end=omp_get_wtime();
  printf("inverse of a mod p : ");
  BN_print_fp(stdout,c);
  puts("");
  printf("openssl inverse of a mod p : %f seconds\n",(end-start));

  BN_free(a);
  BN_free(b);
  BN_free(c);
  BN_free(d);
  BN_free(e);
  BN_free(p);
  BN_free(order);
  printf("-----------------------------\n");

  mpz_t A,B,C,D,E,P;
  mpz_inits(A,B,C,D,E,P,NULL);

  mpz_set_str(A,AA,16);
  mpz_set_str(B,BB,16);
  mpz_set_str(P,PP,16);

  start=omp_get_wtime();
  for(i=0;i<1000000;i++){
    mpz_add(C,A,B);
    mpz_mod(C,C,P);
  }
  end=omp_get_wtime();
  gmp_printf("a+b mod p : %ZX\n",C);
  printf("gmp    a+b mod p : %f seconds\n",(end-start));

  start=omp_get_wtime();
  for(i=0;i<1000000;i++){
    mpz_sub(C,A,B);
    mpz_mod(C,C,P);
  }
  end=omp_get_wtime();
  gmp_printf("a-b mod p : %ZX\n",C);
  printf("gmp    a-b mod p : %f seconds\n",(end-start));

  start=omp_get_wtime();
  for(i=0;i<1000000;i++){
    mpz_mul(C,A,B);
    mpz_mod(C,C,P);
  }
  end=omp_get_wtime();
  gmp_printf("a*b mod p : %ZX\n",C);
  printf("gmp    a*b mod p : %f seconds\n",(end-start));

  start=omp_get_wtime();
  for(i=0;i<100000;i++){
    mpz_invert(C,A,P);
  }
  end=omp_get_wtime();
  gmp_printf("inverse of a mod p : %ZX\n",C);
  printf("gmp   inverse of a mod p : %f seconds\n",(end-start));

  mpz_clears(A,B,C,D,E,NULL);

  printf("-------------------------------------\n");






  mpz_t gmp_p;
  gmp_EC_POINT gmp_P,gmp_Q,gmp_R,gmp_S;
  gmp_EC_POINT_init(gmp_P);
  gmp_EC_POINT_init(gmp_Q);
  gmp_EC_POINT_init(gmp_R);
  gmp_EC_POINT_init(gmp_S);

  mpz_set_ui(gmp_P->x,0);
  mpz_set_ui(gmp_P->y,7);
  mpz_set_ui(gmp_P->z,1);


  return 0;
}
