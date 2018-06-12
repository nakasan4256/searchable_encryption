//gcc -fopenmp -O2 -o test gmp_bignum.c -L/home/b1015014/lib -I/home/b1015014/include -lssl -lcrypto -lgmp
#include<stdio.h>
#include<string.h>
#include<time.h>
#include<omp.h>
#include<gmp.h>
#include<openssl/ec.h>
#include<openssl/bn.h>

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

typedef struct{
  mpz_t x;
  mpz_t y;
  mpz_t z;
}gmp_EC_POINT[1];

#define Me_data_init(me_data) do { me_data->ec=EC_GROUP_new_by_curve_name(714); me_data->a=BN_new(); me_data->b=BN_new(); me_data->p=BN_new(); me_data->order=BN_new(); me_data->Z=EC_POINT_new(me_data->ec); me_data->k=BN_new(); } while(0)
#define Me_data_set(me_data) do { EC_GROUP_get_curve_GFp(me_data->ec,me_data->p,me_data->a,me_data->b,NULL); EC_GROUP_get_order(me_data->ec,me_data->order,NULL); } while(0)
#define Me_data_set_Zk(me_data,Z,k) do { EC_POINT_copy(me_data->Z,Z); BN_copy(me_data->k,k); } while(0)
#define Me_data_clear(me_data) do { EC_POINT_clear_free(me_data->Z); BN_clear_free(me_data->k); BN_clear_free(me_data->p); } while(0)
#define gmp_EC_POINT_init(p) do { mpz_inits(p->x,p->y,p->z,NULL); } while(0)
#define gmp_EC_POINT_set(p,X,Y,Z) do { mpz_set(p->x,X); mpz_set(p->y,Y); mpz_set(p->z,Z); } while(0)
#define gmp_EC_POINT_clear(p) do { mpz_clears(p->x,p->y,p->z,NULL)} while(0)
#define mpz_add_mod(a,b,c,p) do { mpz_add(a,b,c); mpz_mod(a,a,p); } while(0)
#define mpz_sub_mod(a,b,c,p) do { mpz_sub(a,b,c); mpz_mod(a,a,p); } while(0)
#define mpz_mul_mod(a,b,c,p) do { mpz_mul(a,b,c); mpz_mod(a,a,p); } while(0)

void EC_POINT_print(const EC_POINT *P,const Me_DATA me_data,BN_CTX *ctx){
  BIGNUM *Px,*Py,*Pz;
  Px=BN_new();
  Py=BN_new();
  //Pz=BN_new();
  //EC_POINT_get_Jprojective_coordinates_GFp(me_data->ec,P,Px,Py,Pz,ctx);
  EC_POINT_get_affine_coordinates_GFp(me_data->ec,P,Px,Py,ctx);

  fprintf(stdout,"[ ");
  BN_print_fp(stdout,Px);
  fprintf(stdout," , ");
  BN_print_fp(stdout,Py);
  //fprintf(stdout," , ");
  //BN_print_fp(stdout,Pz);
  fprintf(stdout," ]");
  puts("");

  BN_clear_free(Px);
  BN_clear_free(Py);
  //BN_clear_free(Pz);
}

void gmp_EC_POINT_print(const gmp_EC_POINT P,const mpz_t p){
  mpz_t inv2,inv3;
  mpz_inits(inv2,inv3,NULL);

  mpz_invert(inv3,P->z,p);
  mpz_powm_ui(inv2,inv3,2,p);
  mpz_mul_mod(inv3,inv3,inv2,p);
  mpz_mul_mod(inv2,inv2,P->x,p);
  mpz_mul_mod(inv3,inv3,P->y,p);

  gmp_printf("[ %ZX , %ZX ]\n",inv2,inv3);

  mpz_clears(inv2,inv3,NULL);
}

int gmp_EC_POINT_cmp(const gmp_EC_POINT P, const gmp_EC_POINT Q,const mpz_t p){

  mpz_t Za23,Zb23;
  mpz_inits(Za23,Zb23,NULL);

  mpz_powm_ui(Zb23,Q->z,2,p);
  mpz_mul_mod(Zb23,Zb23,P->x,p);
  mpz_powm_ui(Za23,P->z,2,p);
  mpz_mul_mod(Za23,Za23,Q->x,p);

  int ret=mpz_cmp(Za23,Zb23);

  mpz_clears(Za23,Zb23,NULL);

  return ret;
}

void gmp_point_double(gmp_EC_POINT R,const gmp_EC_POINT P,const mpz_t p){
  //y^2=x^3+7 mod p
  mpz_t A,B,C,D,E,F;
  mpz_inits(A,B,C,D,E,F,NULL);

  mpz_powm_ui(A,P->x,2,p);
  mpz_powm_ui(B,P->y,2,p);
  mpz_powm_ui(C,B,2,p);

  mpz_add_mod(D,P->x,B,p);
  mpz_powm_ui(D,D,2,p);
  mpz_sub_mod(D,D,A,p);
  mpz_sub_mod(D,D,C,p);
  mpz_mul_ui(D,D,2);
  mpz_mod(D,D,p);

  mpz_mul_ui(E,A,3);
  mpz_mod(E,E,p);
  mpz_powm_ui(F,E,2,p);

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

void gmp_point_add(gmp_EC_POINT R, const gmp_EC_POINT P, const gmp_EC_POINT Q, mpz_t p){

  if(!mpz_cmp_d(P->z,0)){
    mpz_set(R->x,Q->x);
    mpz_set(R->y,Q->y);
    mpz_set(R->z,Q->z);
    return;
  }
  if(!mpz_cmp_d(Q->z,0)){
    mpz_set(R->x,P->x);
    mpz_set(R->y,P->y);
    mpz_set(R->z,P->z);
    return;
  }
  /*
  if(!gmp_EC_POINT_cmp(P,Q,p)){
    gmp_point_double(R,P,p);
    return;
  }
  */
  //y^2=x^3+7 mod p
  mpz_t Z1Z1,Z2Z2,U1,U2,S1,S2,H,I,J,r,V,aa;
  mpz_inits(Z1Z1,Z2Z2,U1,U2,S1,S2,H,I,J,r,V,aa,NULL);

  mpz_powm_ui(Z1Z1,P->z,2,p);
  mpz_powm_ui(Z2Z2,Q->z,2,p);
  mpz_mul_mod(U1,P->x,Z2Z2,p);
  mpz_mul_mod(U2,Q->x,Z1Z1,p);

  mpz_mul_mod(S1,P->y,Q->z,p);
  mpz_mul_mod(S1,S1,Z2Z2,p);

  mpz_mul_mod(S2,Q->y,P->z,p);
  mpz_mul_mod(S2,S2,Z1Z1,p);

  mpz_sub_mod(H,U2,U1,p);
  mpz_mul_ui(I,H,2);
  mpz_powm_ui(I,I,2,p);

  mpz_mul_mod(J,H,I,p);
  mpz_sub_mod(r,S2,S1,p);
  mpz_mul_ui(r,r,2);
  mpz_mod(r,r,p);
  mpz_mul_mod(V,U1,I,p);

  mpz_powm_ui(R->x,r,2,p);
  mpz_sub_mod(R->x,R->x,J,p);
  mpz_mul_ui(aa,V,2);
  mpz_sub_mod(R->x,R->x,aa,p);

  mpz_sub_mod(R->y,V,R->x,p);
  mpz_mul_mod(R->y,R->y,r,p);
  mpz_mul_ui(aa,S1,2);
  mpz_mul_mod(aa,aa,J,p);
  mpz_sub_mod(R->y,R->y,aa,p);

  mpz_add_mod(R->z,P->z,Q->z,p);
  mpz_powm_ui(R->z,R->z,2,p);
  mpz_sub_mod(R->z,R->z,Z1Z1,p);
  mpz_sub_mod(R->z,R->z,Z2Z2,p);
  mpz_mul_mod(R->z,R->z,H,p);

  mpz_clears(Z1Z1,Z2Z2,U1,U2,S1,S2,H,I,J,r,V,aa,NULL);
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

  Me_DATA me_data;
  Me_data_init(me_data);
  Me_data_set(me_data);

  EC_POINT *X,*Y,*Z;
  X=EC_POINT_new(me_data->ec);
  Y=EC_POINT_new(me_data->ec);
  Z=EC_POINT_new(me_data->ec);
  BIGNUM *k;
  k=BN_new();
  //BN_rand_range(k,me_data->order);
  BN_set_word(k,1);
  EC_POINT_mul(me_data->ec,Y,k,NULL,NULL,ctx);
  //BN_rand_range(k,me_data->order);
  BN_set_word(k,2);
  EC_POINT_mul(me_data->ec,Z,k,NULL,NULL,ctx);

  BIGNUM *Y_co[3];
  BIGNUM *Z_co[3];
  for(i=0;i<3;i++){
    Y_co[i]=BN_new();
    Z_co[i]=BN_new();
  }
  EC_POINT_get_Jprojective_coordinates_GFp(me_data->ec,Y,Y_co[0],Y_co[1],Y_co[2],ctx);
  EC_POINT_get_Jprojective_coordinates_GFp(me_data->ec,Z,Z_co[0],Z_co[1],Z_co[2],ctx);

  EC_POINT_print(Y,me_data,ctx);
  EC_POINT_print(Z,me_data,ctx);
  printf("-------------------------------------\n");

  start=omp_get_wtime();
  for(i=0;i<1000000;i++){
    EC_POINT_add(me_data->ec,X,Y,Z,ctx);
  }
  end=omp_get_wtime();
  EC_POINT_print(X,me_data,ctx);
  printf("openssl point_add : %f seconds\n",(end-start));

  start=omp_get_wtime();
  for(i=0;i<1000000;i++){
    EC_POINT_dbl(me_data->ec,X,Y,ctx);
  }
  end=omp_get_wtime();
  EC_POINT_print(X,me_data,ctx);
  printf("openssl point_dbl : %f seconds\n",(end-start));
  printf("-------------------------------------\n");

  char *ppp;
  ppp=BN_bn2hex(me_data->p);
  char *Ya[3];
  char *Za[3];
  for(i=0;i<3;i++){
    Ya[i]=BN_bn2hex(Y_co[i]);
    Za[i]=BN_bn2hex(Z_co[i]);
  }

  mpz_t gmp_p;
  mpz_init(gmp_p);
  mpz_set_str(gmp_p,ppp,16);

  gmp_EC_POINT gmp_P,gmp_Q,gmp_R,gmp_S;
  gmp_EC_POINT_init(gmp_P);
  gmp_EC_POINT_init(gmp_Q);
  gmp_EC_POINT_init(gmp_R);
  gmp_EC_POINT_init(gmp_S);

  mpz_set_str(gmp_P->x,Ya[0],16);
  mpz_set_str(gmp_P->y,Ya[1],16);
  mpz_set_str(gmp_P->z,Ya[2],16);
  mpz_set_str(gmp_Q->x,Za[0],16);
  mpz_set_str(gmp_Q->y,Za[1],16);
  mpz_set_str(gmp_Q->z,Za[2],16);


  gmp_EC_POINT_print(gmp_P,gmp_p);
  gmp_EC_POINT_print(gmp_Q,gmp_p);
  printf("-------------------------------------\n");

  gmp_point_add(gmp_R,gmp_P,gmp_Q,gmp_p);
  start=omp_get_wtime();
  for(i=0;i<1000000;i++){
    gmp_point_add(gmp_R,gmp_P,gmp_Q,gmp_p);
  }
  end=omp_get_wtime();
  gmp_EC_POINT_print(gmp_R,gmp_p);
  printf("gmp point_add : %f seconds\n",(end-start));

  start=omp_get_wtime();
  for(i=0;i<1000000;i++){
    gmp_point_double(gmp_R,gmp_P,gmp_p);
  }
  end=omp_get_wtime();
  gmp_EC_POINT_print(gmp_R,gmp_p);
  printf("gmp point_dbl : %f seconds\n",(end-start));

  return 0;
}
