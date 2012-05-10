#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
// kthxbai

// different views of a 64-bit double word
typedef union {
  uint64_t as_uint64_t;
  uint16_t as_uint16_ts[4];
} uint64_tviews;

// different views of a 32-bit single word
typedef union {
  uint64_t as_uint32_t;
  uint16_t as_uint16_ts[2];
  uint8_t as_uint8_ts[4];
} uint32_tviews;

typedef struct {
  uint64_t h;
  uint64_t u;
  uint32_t v;
} Entry;

// extract lower and upper 32 bits from uint64_t
const uint64_t LowOnes = (((uint64_t) 1) << 32) - 1;
#define LOW(x) ((x) & LowOnes)
#define HIGH(x) ((x) >> 32)

// A2 Mutliplication-shift based hashing for 32-bit keys
/* plain univrsal hashing for 32-bit key x
   A is a random 32-bi odd number */
inline uint32_t Univ(uint32_t x, uint32_t A) {
  return (A*x);
}

/* 2-universal hashing for 32-bit key x
   A and B are random 64-bit numbers */
inline uint32_t  Univ2(uint32_t x, uint64_t A, uint64_t B) {
  return (uint32_t) ((A*x + B) >> 32);
}

/*
 * Pieces together a 32-bit random number from rand()
 *  since rand() only gets random number from 0 to 32767 which is also 15-bits
 */
inline uint32_t rand32(){
  uint32_t rand32 = (((uint32_t)rand() & 32767) << 17) |
                    (((uint32_t)rand() & 32767) << 2)  |
                    ((uint32_t)rand() & 3);  

  return rand32;
}
/*
 * Pieces together a 64-bit  random number from rand()
 *  since rand() only gets random number from 0 to 32767 which is also 15-bits
 */
inline uint64_t rand64(){
  uint64_t rand64 = (((uint64_t)rand() & 32767) << 49) |
                    (((uint64_t)rand() & 32767) << 34) |
                    (((uint64_t)rand() & 32767) << 19) |
                    (((uint64_t)rand() & 32767) << 4)  |
                    ((uint64_t)rand() & 15);  

  return rand64;
}
// A3 tabulation hashing for 32-bit key x using 16-bit characters.
/* tabulation hashing for 32-bit key x using 16-bit characters.
   T0, T1, T2 are precomputed tables */

inline uint32_t ShortTable32(uint32_t x, 
			  uint32_t T0[],
			  uint32_t T1[],
			  uint32_t T2[]) 
{
  uint32_t x0, x1, x2;
  x0 = x & 65535;
  x1 = x >> 16;
  x2 = x0 + x1;
  x2 = 2 - (x2 >> 16) + (x2 & 65535); //compression
  if(x2 > 65535){
    printf("ERROR: ShortTable32 has x2 greater than 16 bits \n");    
  }
  return T0[x0] ^ T1[x1] ^ T2[x2];
}


/*
 * fills the random number tables for hashing ShortTable32
 */
void makeRandShort32(uint32_t** T0, uint32_t** T1, uint32_t** T2){
  *T0 = malloc(65536 * 4); //tables of 2^16 32-bit numbers
  *T1 = malloc(65536 * 4); //tables of 2^16 32-bit numbers
  *T2 = malloc(65536 * 4); //tables of 2^16 32-bit numbers
  int i;
  for(i = 0; i < 65536; i++){
    (*T0)[i] = rand32();
    (*T1)[i] = rand32();
    (*T2)[i] = rand32();
  }
}

/*
 * Clears the random number tables for hashing ShortTable32
 */
void clearRandShort32(uint32_t** T0, uint32_t** T1, uint32_t** T2){
  free(*T0);
  free(*T1);
  free(*T2);
}
//A4 Tabulation hased hashing for 32-bit keys using 8-bit characters.
/* tabulation based hashing for 32-bit key x 
   using 8-bit characters.
   T0, T1, T2 ... T6 are pre-compuated tables */
inline uint32_t CharTable32(uint32_t x,
  uint32_t T0[], uint32_t T1[], uint32_t T2[], uint32_t T3[],
  uint32_t T4[], uint32_t T5[], uint32_t T6[])
{
  uint32_t *a0, *a1, *a2, *a3, c;

  a0 = &T0[(x & 255) * 2];
  a1 = &T1[((x>>8) & 255) * 2];
  a2 = &T2[((x>>16) & 255) * 2];
  a3 = &T3[((x>>24) & 255) *2];

  c = a0[1] + a1[1] + a2[1] + a3[1];
  
  return 
    a0[0] ^ a1[0] ^ a2[0] ^ a3[0] ^
    T4[c & 1023] ^ 
    T5[(c >> 10) & 1023] ^
    T6[c >> 20];
}

/*
 * fills the random number tables for hashing CharTable32
 */
void makeRandChar32(uint32_t** T0 ,uint32_t** T1,uint32_t** T2, uint32_t** T3,
                    uint32_t** T4, uint32_t** T5, uint32_t** T6)
{
  *T0 = malloc(256 *2 * 4); // table of 2^8 pairs of 32-bit integers
  *T1 = malloc(256 *2 * 4); // table of 2^8 pairs of 32-bit integers
  *T2 = malloc(256 *2 * 4); // table of 2^8 pairs of 32-bit integers
  *T3 = malloc(256 *2 * 4); // table of 2^8 pairs of 32-bit integers
  *T4 = malloc(1024 * 4); // table of 2^10 32-bit integers
  *T5 = malloc(1024 * 4); // table of 2^10 32-bit integers
  *T6 = malloc(4096 * 4); // table of 2^12 32-bit integers
  int i; 
  for(i = 0; i < 512; i++){
    (*T0)[i] = rand32();
    (*T1)[i] = rand32();
    (*T2)[i] = rand32();
    (*T3)[i] = rand32();
  }
  for(i = 0; i < 1024; i++){
    (*T4)[i] = rand32();
    (*T5)[i] = rand32();
  }
  for(i = 0; i < 4096; i++){
    (*T6)[i] = rand32();
  }
}

/*
 * Clears the random number tables for hashing CharTable32
 */
void clearRandChar32(uint32_t** T0, uint32_t** T1, uint32_t** T2, uint32_t** T3,
                    uint32_t** T4, uint32_t** T5, uint32_t** T6)
{
  free(*T0);
  free(*T1);
  free(*T2);
  free(*T3);
  free(*T4);
  free(*T5);
  free(*T6);
}
// A7 tabulation based hashing for 64-bit key x using 16-bit characters.
/* tabulation based hashing for 64-bit key x using 16-bit characters.
   T0,.. T6 are precomputed tables */
inline uint64_t ShortTable64(uint64_tviews x, 
			  uint64_t *T0[], uint64_t *T1[],
			  uint64_t *T2[], uint64_t *T3[],
			  uint64_t T4[], uint64_t T5[], uint64_t T6[])
{
  uint64_t *a0, *a1, *a2, *a3, c;
  
  a0 = T0[x.as_uint16_ts[0]];
  a1 = T1[x.as_uint16_ts[1]];
  a2 = T2[x.as_uint16_ts[2]];
  a3 = T3[x.as_uint16_ts[3]];

  c = a0[1] + a1[1] + a2[1] + a3[1];
  
  return 
    a0[0] ^ a1[0] ^ a2[0] ^ a3[0] ^
    T4[c & 2097151] ^
    T5[(c >> 21) & 2097151] ^ T6[c >> 42];
}

/*
 * fills the random number tables for hashing ShortTable64
 */
void makeRandShort64(uint32_t *T0[],uint32_t *T1[],uint32_t *T2[], uint32_t *T3[],
                     uint32_t *T4[], uint32_t *T5[], uint32_t *T6[])
{
}

/*
 * Clears the random number tables for hashing ShortTable64
 */
void clearRandShort64(uint32_t *T0[],uint32_t *T1[],uint32_t *T2[], uint32_t *T3[],
                      uint32_t *T4[], uint32_t *T5[], uint32_t *T6[])
{
}
// A8 Tabulation hased hasing for 64-bit keys using 8-bit characters
/* tabulation based hashing for 64-but key x
   using 8-bit characters.
   T0, T1... T14 are pre-computed tables */
inline uint64_t CharTable64( uint64_tviews x, 
  Entry T0[], Entry T1[], Entry T2[], Entry T3[],
  Entry T4[], Entry T5[], Entry T6[], Entry T7[],
  uint64_t T8[], uint64_t T9[], uint64_t T10[], uint64_t T11[],
  uint64_t T12[], uint64_t T13[], uint64_t T14[])
{
  Entry *a0, *a1, *a2, *a3,
        *a4, *a5, *a6, *a7;
  uint64_t c0;
  uint32_t c1;


  a0 = &T0[x.as_uint16_ts[0]];
  a1 = &T1[x.as_uint16_ts[1]];
  a2 = &T2[x.as_uint16_ts[2]];
  a3 = &T3[x.as_uint16_ts[3]];
  a4 = &T4[x.as_uint16_ts[4]];
  a5 = &T5[x.as_uint16_ts[5]];
  a6 = &T6[x.as_uint16_ts[6]];
  a7 = &T7[x.as_uint16_ts[7]];

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


/*
 * fills the random number tables for hashing CharTable64
 */
void makeRandChar64(Entry *T0[],Entry *T1[],Entry *T2[], Entry *T3[],
                     Entry *T4[], Entry *T5[], Entry *T6[], Entry *T7,
                     uint64_t *T8[], uint64_t *T9[], uint64_t *T10[], uint64_t *T11[],
                     uint64_t *T12[], uint64_t *T13[], uint64_t *T14[])
{
}

/*
 * Clears the random number tables for hashing ShortTable64
 */
void clearRandChar64(Entry *T0[],Entry *T1[],Entry *T2[], Entry *T3[],
                     Entry *T4[], Entry *T5[], Entry *T6[], Entry *T7,
                     uint64_t *T8[], uint64_t *T9[], uint64_t *T10[], uint64_t *T11[],
                     uint64_t *T12[], uint64_t *T13[], uint64_t *T14[])
{

}


int main(int argc, char *argv[])
{
  printf("hello world! \n");
  void* T0;
  void* T1;
  void* T2;
  void* T3;
  void* T4;
  void* T5;
  void* T6;
  void* T7;
  void* T8;
  void* T9;
  void* T10;
  void* T11;
  void* T12;
  void* T13;
  void* T14;
  void* T15;

  printf("The address of T0: %p , T1: %p, T2: %p \n", T0, T1, T2); 
  makeRandShort32((uint32_t**) &T0, (uint32_t**) &T1, (uint32_t**) &T2);
  
  printf("The address of T0: %p , T1: %p, T2: %p \n", T0, T1, T2); 
  printf("First few numbers  %u , %u \n", ((uint32_t*)T0)[0], ((uint32_t*)T0)[5]);
 
  //Test for randomness
  /*
  printf("Rand is at most %x, %d \n" , RAND_MAX, RAND_MAX); 
  int i;
  for( i =0 ; i < 1000; i++){
    printf("%u, \n",ShortTable32(rand32(), (uint32_t*) T0,(uint32_t*) T1, (uint32_t*) T2 ));
  }
  */
  clearRandShort32((uint32_t**) &T0, (uint32_t**) &T1, (uint32_t**) &T2);

  makeRandChar32((uint32_t**) &T0, (uint32_t**) &T1, (uint32_t**) &T2,
                 (uint32_t**) &T0, (uint32_t**) &T1, (uint32_t**) &T2,
                 (uint32_t**) &T6);
  
  int i;
  for( i =0 ; i < 1; i++){
    printf("%u, \n",CharTable32(rand32(), (uint32_t*) T0,(uint32_t*) T1, (uint32_t*) T2,
                                (uint32_t*) T3, (uint32_t*) T4, (uint32_t*) T5, (uint32_t*) T6));
  }
  makeRandChar32((uint32_t**) &T0, (uint32_t**) &T1, (uint32_t**) &T2,
                 (uint32_t**) &T0, (uint32_t**) &T1, (uint32_t**) &T2,
                 (uint32_t**) &T6);
  
}
