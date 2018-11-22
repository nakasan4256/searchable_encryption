#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<time.h>
#include<omp.h>
#include<gmp.h>
#include<openssl/ec.h>
#include<openssl/bn.h>
#include<openssl/sha.h>

void EC_POINT_print(const EC_POINT *P,const EC_GROUP *ec){
  BN_CTX *ctx;
  ctx=BN_CTX_new();
  BIGNUM *Px,*Py;
  Px=BN_new();
  Py=BN_new();
  EC_POINT_get_affine_coordinates_GFp(ec,P,Px,Py,ctx);

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

int main(void){
  BN_CTX *ctx;
  ctx=BN_CTX_new();
  BIGNUM *Ax,*Ay,*Bx,*By,*order;
  Ax=BN_new();
  Ay=BN_new();
  Bx=BN_new();
  By=BN_new();
  order=BN_new();

  EC_GROUP *ec;
  ec=EC_GROUP_new_by_curve_name(714);
  EC_GROUP_get_order(ec,order,NULL);

  EC_POINT *A;
  EC_POINT *B;
  A=EC_POINT_new(ec);
  B=EC_POINT_new(ec);

  int len=-1;
  unsigned char *buf =NULL;
  unsigned char *buf2 =NULL;

  BN_rand_range(Ax,order);
  EC_POINT_mul(ec,A,Ax,NULL,NULL,ctx);
  BN_rand_range(Bx,order);
  EC_POINT_mul(ec,B,Bx,NULL,NULL,ctx);

  EC_POINT_get_affine_coordinates_GFp(ec,A,Ax,Ay,ctx);
  EC_POINT_get_affine_coordinates_GFp(ec,B,Bx,By,ctx);

  printf("A : ");
  EC_POINT_print(A,ec);
  printf("B : ");
  EC_POINT_print(B,ec);

  len = BN_num_bytes(Ax);
  buf = (unsigned char *)malloc(len);
  len = BN_bn2bin(Ax, buf);
  printf("%s\n",buf);
  /* binaryからBIGNUMへの変換 */
  BN_bin2bn(buf, len, Ax);
  Ax = BN_bin2bn(buf, len, NULL);
  buf2 = (unsigned char *)malloc(len);
  len = BN_bn2bin(Ax, buf2);
  printf("%s\n",buf2);


  BN_print_fp(stdout,Ax);


}
