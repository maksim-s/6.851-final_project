// kthxbai
#include <stdio.h>

// A1
// common data types and macros
typedef unsigned char      INT8;
typedef unsigned short     INT16;
typedef unsigned int       INT32;
typedef unsigned long long INT64;
typedef INT64              INT96[3];

// different views of a 64-bit double word
typedef union {
  INT64 as_int64;
  INT16 as_int16s[4];
} int64views;

// different views of a 32-bit single word
typedef union {
  INT64 as_int32;
  INT16 as_int16s[2];
  INT8 as_int8s[4];
} int32views;

typedef struct {
  INT64 h;
  INT64 u;
  INT32 v;
} Entry;

// extract lower and upper 32 bits from INT64
const INT64 LowOnes = (((INT64) 1) << 32) - 1;
#define LOW(x) ((x) & LowOnes)
#define HIGH(x) ((x) >> 32)
// A2 Mutliplication-shift based hashing for 32-bit keys
/* plain univrsal hashing for 32-bit key x
   A is a random 32-bi odd number */
inline INT32 Univ(INT32 x, INT32 A) {
  return (A*x);
}

/* 2-universal hashing for 32-bit key x
   A and B are random 64-bit numbers */
inline INT32  Univ2(INT32 x, INT64 A, INT64 B) {
  return (INT32) ((A*x + B) >> 32);
}
// A3 tabulation hashing for 32-bit key x using 16-bit characters.
/* tabulation hashing for 32-bit key x using 16-bit characters.
   T0, T1, T2 are precomputed tables */

inline INT32 ShortTable32(INT32 x, 
			  INT32 T0[],
			  INT32 T1[],
			  INT32 T2[]) 
{
  INT32 x0, x1, x2;
  x0 = x & 65535;
  x1 = x >> 16;
  x2 = x0 + x1;
  return T0[x0] ^ T1[x1] ^ T2[x2];
}

//A4 Tabulation hased hashing for 32-bit keys using 8-bit characters.
/* tabulation based hashing for 32-bit key x 
   using 8-bit characters.
   T0, T1, T2 ... T6 are pre-compuated tables */
inline INT32 CharTable32(int32views x,
  INT32 *T0[], INT32 *T1[], INT32 *T2[], INT32 *T3[],
  INT32 T4[], INT32 T5[], INT32 T6[])
{
  INT32 *a0, *a1, *a2, *a3, c;

  a0 = T0[x.as_int8s[0]];
  a1 = T1[x.as_int8s[1]];
  a2 = T2[x.as_int8s[2]];
  a3 = T3[x.as_int8s[3]];

  c = a0[1] + a1[1] + a2[1] + a3[1];
  
  return 
    a0[0] ^ a1[0] ^ a2[0] ^ a3[0] ^
    T4[c & 1023] ^ 
    T5[(c >> 10) & 1023] ^
    T6[c >> 20];
}

// A7 tabulation based hashing for 64-bit key x using 16-bit characters.
/* tabulation based hashing for 64-bit key x using 16-bit characters.
   T0,.. T6 are precomputed tables */
inline INT64 ShortTable64(int64views x, 
			  INT64 *T0[], INT64 *T1[],
			  INT64 *T2[], INT64 *T3[],
			  INT64 T4[], INT64 T5[], INT64 T6[])
{
  INT64 *a0, *a1, *a2, *a3, c;
  
  a0 = T0[x.as_int16s[0]];
  a1 = T1[x.as_int16s[1]];
  a2 = T2[x.as_int16s[2]];
  a3 = T3[x.as_int16s[3]];

  c = a0[1] + a1[1] + a2[1] + a3[1];
  
  return 
    a0[0] ^ a1[0] ^ a2[0] ^ a3[0] ^
    T4[c & 2097151] ^
    T5[(c >> 21) & 2097151] ^ T6[c >> 42];
}

// A8 Tabulation hased hasing for 64-bit keys using 8-bit characters
/* tabulation based hashing for 64-but key x
   using 8-bit characters.
   T0, T1... T14 are pre-computed tables */
inline INT64 CharTable64( int64views x, 
  Entry T0[], Entry T1[], Entry T2[], Entry T3[],
  Entry T4[], Entry T5[], Entry T6[], Entry T7[],
  INT64 T8[], INT64 T9[], INT64 T10[], INT64 T11[],
  INT64 T12[], INT64 T13[], INT64 T14[])
{
  Entry *a0, *a1, *a2, *a3,
        *a4, *a5, *a6, *a7;
  INT64 c0;
  INT32 c1;


  a0 = &T0[x.as_int16s[0]];
  a1 = &T1[x.as_int16s[1]];
  a2 = &T2[x.as_int16s[2]];
  a3 = &T3[x.as_int16s[3]];
  a4 = &T4[x.as_int16s[4]];
  a5 = &T5[x.as_int16s[5]];
  a6 = &T6[x.as_int16s[6]];
  a7 = &T7[x.as_int16s[7]];

  c0 = a0->u + a1->u + a2->u + a3->u + 
       a4->u + a5->u + a6->u + a7->u;
  c1 = a0->v + a1->v + a2->v + a3->v + 
       a4->v + a5->v + a6->v + a7->v;
  return
    a0->h ^ a1->h ^ a2->h ^ a3->h ^
    a4->h ^ a5->h ^ a6->h ^ a7->h ^
    T8[c0 & 2043] ^ T9[(c0 >> 11) & 2043] ^
    T10[(c0 >> 22) & 2043] ^ T11[(c0 >> 33) & 2043] ^
    T12[c0 >> 44] ^ T13[c1 & 2043] ^ T14[c1 >> 11];
}
// A9 CW trick for 32-bit kes with prime 2^61 - 1
const INT64 Prime = (((INT64) 1 ) << 61) - 1;
/* computes ax + b mod Prime, possbly plus 2*Prime,
   expoiting the structures of Prime */
inline INT64 MultAddPrime32(INT32 x,
			    INT64 a,
			    INT64 b)
{
  INT64 a0, a1, c0, c1, c;
  a0 = LOW(a) * x;
  a1 = HIGH(a) * x;
  c0 = a0 + (a1 << 32);
  c1 = (a0 >> 32) + a1;
  c = (c0 & Prime) + (c1 >> 29) + b;
  return c;
}

// CWtrick for 32-bit key x (Prime = 2^61 - 1)
inline INT64 CWtrick32(INT32 x, INT64 A,
		       INT64 B, INT64 C,
		       INT64 D, INT64 E)
{
  INT64 h;
  h = MultAddPrime32(
      MultAddPrime32(
      MultAddPrime32(
		     MultAddPrime32(x, A, B), x, C), x, D), x, E);
  h = (h & Prime) + (h >> 61);
  if (h >= Prime)
    h -= Prime;
  return h;
}

// A11 CW trick for 64-bit keys using prime 2^89 - 1
const INT64 Prime89_0  = (((INT64) 1) << 32) - 1;
const INT64 Prime89_1  = (((INT64) 1) << 32) - 1;
const INT64 Prime89_2  = (((INT64) 1) << 32) - 1;
const INT64 Prime89_21 = (((INT64) 1) << 32) - 1;

/* Computes (r mod Prime89) mod 2^64,
   exploiting the structure of Prime89 */
inline INT64 Mod64Prime89(INT96 r)
{
  INT64 r0, r1, r2;
  // r2r1r0 = r & Prime89 + r >> 89
  r2 =  r[2];
  r1 =  r[1];
  r0 =  r[0] + (r2  >> 25);
  r2 &= Prime89_2;
  
  return (r2 == Prime89_2 &&
	  r1 == Prime89_1 &&
	  r0 >= Prime89_0) ?
         (r0 - Prime89_0) : (r0 + (r1 << 32));
}

/* Computes a 96-bit r such that r mod Prime89 == (ax + b) mod Prime89
   exploiting the structure of Prime89 */
inline void MultAddPrime89(INT96 r, INT64 x,
			   INT96 a, INT96 b)
{
  INT64 x1, x0, c21, c20, c11, c10, c01, c00;
  INT64 d0, d1, d2, d3;
  INT64 s0, s1, carry;

  x1 = HIGH(x);
  x0 = LOW(x);
  
  c21 = a[2]*x1;
  c20 = a[2]*x0;
  c11 = a[1]*x1;
  c10 = a[1]*x0;
  c01 = a[0]*x1;
  c00 = a[0]*x0;

  d0 = (c20 >> 25) + (c11 >> 25) +
    (c10 >> 57) + (c01 >> 57);
  d1 = (c21 << 7);
  d2 = (c10 & Prime89_21) + (c01 & Prime89_21);
  d3 = (c20 & Prime89_2) + (c11 & Prime89_2) + (c21 >> 57);
  
  s0    = b[0] + LOW(c00) + LOW(d0) + LOW(d1);
  r[0]  = LOW(s0);
  carry = HIGH(s0);

  s1    = b[1] + HIGH(c00) + HIGH(d0) + HIGH(d1) + LOW(d2) + carry;
  r[1]  = LOW(s1);
  carry = HIGH(s1);
  
  r[2] = b[2] + HIGH(d2) + d3 + carry;
}

// CW trick for 64-bit key x (Prime = 2^89 - 1)
inline INT64 CWtrick64(INT64 x, INT96 A,
		       INT96 B, INT96 C,
		       INT96 D, INT96 E)
{
  INT96 r;

  MultAddPrime89(r, x, A, B);
  MultAddPrime89(r, x, r, C);
  MultAddPrime89(r, x, r, D);
  MultAddPrime89(r, x, r, E);

  return Mod64Prime89(r);


}

int main(int argc, char *argv[])
{
  printf("hello world! \n");
}
