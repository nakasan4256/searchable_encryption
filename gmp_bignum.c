//gcc -fopenmp -O2 -o test gmp_bignum.c -L/home/b1015014/lib -I/home/b1015014/include -lssl -lcrypto -lgmp
#include<stdio.h>
#include<string.h>
#include<time.h>
#include<omp.h>
#include<gmp.h>
#include<openssl/bn.h>

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
    BN_mod_mul(c,a,b,p,ctx);
  end=omp_get_wtime();
  printf("a*b : ");
  BN_print_fp(stdout,c);
  puts("");
  printf("openssl a*b : %f seconds\n",(end-start));

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
  for(i=0;i<1000000;i++)
    mpz_mul_mod(C,A,B,P);
  end=omp_get_wtime();
  gmp_printf("a*b : %ZX\n",C);
  printf("gmp    a*b : %f seconds\n",(end-start));

  mpz_clears(A,B,C,D,E,NULL);

  return 0;
}
