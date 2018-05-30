
Sign(P,p)=
{
  return(kronecker(lift(P[2]),p));
}

Me(E,P,Q,k)=
{
  if(
    ellsub(E,P,Q)==[0], return(P),
    Sign(ellsub(E,P,Q),E.p)==1, return(ellsub(E,ellmul(E,P,k),ellmul(E,Q,k-1))),
    Sign(ellsub(E,P,Q),E.p)==-1,return(ellsub(E,ellmul(E,Q,k),ellmul(E,P,k-1))),
    return([0]);\\error
  );
}

Me_mul_1(E,P,n,Z,k)=\\Meスカラー倍
{
  local(bin,l,Y);
  bin=binary(n);
  l=length(bin);

  Y=P;
  for(i=2,l,
    Y=Me(E,elladd(E,Z,Y),Y,k);
    if(bin[i]==1,
      Y=Me(E,Y,P,k);
    );
  );
  return(Y);
}

private_key_create(limit)=\\同じ
{
  local(private_key);
  private_key=random(limit);
  return(private_key);
}

public_key_create(private_key,Ell,P,Z,k)=
{
  local(public_key);
  public_key=matrix(2,2);
  public_key[1,]=P;
  public_key[2,]=Me_mul_1(Ell,P,private_key,Z,k);
  return(public_key);
}

hash1(keyword)=
{
  return(keyword);
}

trapdoor_create(private_key,keyword,Ell,Z,k)=
{
  local(trapdoor);
  trapdoor=Me_mul_1(Ell,hash1(keyword),private_key,Z,k);
  return(trapdoor);
}

keyword_encrypt(keyword,public_key,Ell,Z,k,limit)=
{
  local(r,A,B,C,peks);
  r=random(limit);

  A=hash1(keyword);
  B=Me_mul_1(Ell,public_key[1,],r,Z,k);
  C=Me_mul_1(Ell,public_key[2,],r,Z,k);

  peks=matrix(2,2);
  peks[1,]=B;
  peks[2,]=elladd(Ell,Me(E,A,B,k),C);
  return(peks);
}

test(keyword,peks,trapdoor,Ell)=
{
  local(check_left,check_right,A,B);

  A=Me(E,hash1(keyword),peks[1,],k);
  B=ellsub(E,peks[2,],A);

  check_left=Me(E,trapdoor,B,k);
  check_right=ellsub(E,peks[2,],peks[1,]);
  if(ellsub(Ell,check_left,check_right)==[0],
		return(1),return(0)
  );
}


{
  limit=2^192;
  k=2;

  /*secp-192k1*/
  p=6277101735386680763835789423207666416102355444459739541047;
  E=ellinit([0,0,0,0,3],p);
  \\P=[3805108391982600717572440947423858335415441070543209377693,2471993343404080046263348475783808080686914373916530163354]*Mod(1,p);
  P=random(E);
  Z=random(E);



/*test a*r*P ?= r*a*P
  check=0;
  while(check==0,
    a=0;
    b=0;
    while(a<=2||b<=2||a==b,
      a=random(100000000);
      b=random(100000000);
    );
    A=Me_mul_1(E,P,a,Z,k);
    AB=Me_mul_1(E,A,b,Z,k);
    print(AB);
    B=Me_mul_1(E,P,b,Z,k);
    BA=Me_mul_1(E,B,a,Z,k);
    print(BA);
    print("A : ",a);
    print("B : ",b);
    if(ellsub(E,AB,BA)==[0],
      check=1
    );
  );
*/

/*test sousenkeisei
  n=random(2^255);
  P=random(E);
  Q=random(E);
  R=elladd(E,P,Q);
  S=random(E);
  A=Me_mul_1(E,P,n,Z,k);
  B=Me_mul_1(E,Q,n,Z,k);
  C=Me_mul_1(E,R,n,Z,k);
  print(elladd(E,A,Q));
  print(elladd(E,P,B));
  print(C);
  A=elladd(E,P,Me(E,Q,S,k));
  B=Me(E,elladd(E,P,Q),elladd(E,P,S),k);
  print(A);
  print(B);
*/

  private_key=private_key_create(limit);
  public_key=matrix(2,2);
  public_key=public_key_create(private_key,E,P,Z,k);

  print("private_key : ",private_key);
  print(" public_key : P = ",public_key[1,]);
  print("           a**P = ",public_key[2,]);
  print("-------------------------------------------------");

  n=10;

  keyword=matrix(n,2);
  trapdoor=matrix(n,2);
  for(i=1,n,
		keyword[i,]=random(E);
    \\print("keyword  : ",keyword[i,]);
    trapdoor[i,]=trapdoor_create(private_key,keyword[i,],E,Z,k);
    \\print("trapdoor : ",trapdoor[i,]);
  );

  data=matrix(n,n);
  peks=matrix(2,2);
  for(i=1,n,
    peks=keyword_encrypt(keyword[i,],public_key,E,Z,k,limit);
    \\print(peks);
    for(j=1,n,
      data[i,j]=-1;
      data[i,j]=test(keyword[i,],peks,trapdoor[j,],E);
    );
  );
  data

}
