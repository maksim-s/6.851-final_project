#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <time.h>
// kthxbai

#define TABLE_SIZE 1000
#define N_HASHES   1000

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

enum ProbingType {
  linear = 0,
  quadratic,
};

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
  return T0[x0] ^ T1[x1] ^ T2[x2];
}


/*
 * fills the random number tables for hashing ShortTable32
 */
void makeRandShort32(uint32_t** T0, uint32_t** T1, uint32_t** T2){
  *T0 = malloc(65536 * 4); //tables of 2^16 32-bit numbers
  *T1 = malloc(65536 * 4); //tables of 2^16 32-bit numbers
  *T2 = malloc(131072 * 4); //tables of 2^17 32-bit numbers
  int i;
  for(i = 0; i < 65536; i++){
    (*T0)[i] = rand32();
    (*T1)[i] = rand32();
  }
  for(i = 0; i < 131072;i++){
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
  a3 = &T3[((x>>24)) * 2];
  /*
  printf("T0 address: %p, a0 address: %p,\
          \nT1 address: %p, a1 address: %p,\
          \nT2 address: %p, a2 address: %p,\
          \nT3 address: %p, a3 address: %p,\
          \nT4 address: %p,\
          \nT5 address: %p,\
          \nT6 address: %p \n",\
          T0, a0, T1, a1, T2, a2, T3, a3, T4, T5, T6);
  */
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
  *T0 = malloc(256 * 2 * 4); // table of 2^8 pairs of 32-bit integers
  *T1 = malloc(256 * 2 * 4); // table of 2^8 pairs of 32-bit integers
  *T2 = malloc(256 * 2 * 4); // table of 2^8 pairs of 32-bit integers
  *T3 = malloc(256 * 2 * 4); // table of 2^8 pairs of 32-bit integers
  *T4 = malloc(1024 * 4); // table of 2^10 32-bit integers
  *T5 = malloc(1024 * 4); // table of 2^10 32-bit integers
  *T6 = malloc(4096 * 4); // table of 2^12 32-bit integers
 /* 
  printf("T0 address: %p,\
          \nT1 address: %p,\
          \nT2 address: %p,\ 
          \nT3 address: %p,\
          \nT4 address: %p, \ 
          \nT5 address: %p, \
          \nT6 address: %p \n ",\
          *T0, *T1, *T2, *T3, *T4, *T5, *T6);
  */
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
inline uint64_t ShortTable64(uint64_t x, 
			     uint64_t T0[], uint64_t T1[],
			     uint64_t T2[], uint64_t T3[],
			     uint64_t T4[], uint64_t T5[], uint64_t T6[])
{
  uint64_t a00, a01, a10, a11,  a20, a21,  a30, a31, c;
  uint16_t x0, x1, x2, x3;
  x0 = (uint16_t) x;
  x1 = (uint16_t) (x >> 16);
  x2 = (uint16_t) (x >> 32);
  x3 = (uint16_t) (x >> 48);
  a01 = T0[x0];
  a11 = T1[x1];
  a21 = T2[x2];
  a31 = T3[x3];
  a00 = T0[x0 + 65536]; // 2^16
  a10 = T1[x1 + 65536];
  a20 = T2[x2 + 65536];
  a30 = T3[x3 + 65536];

  c = a01 + a11 + a21 + a31;
  
  return 
    a00 ^ a10 ^ a20 ^ a30 ^
    T4[c & 2097151] ^
    T5[(c >> 21) & 2097151] ^ T6[c >> 42];
}

/*
 * fills the random number tables for hashing ShortTable64
 */
void makeRandShort64(uint64_t** T0, uint64_t** T1, uint64_t** T2, uint64_t** T3,
                     uint64_t** T4, uint64_t** T5, uint64_t** T6)
{
  *T0 = malloc(65536 * 16);
  *T1 = malloc(65536 * 16);
  *T2 = malloc(65536 * 16);
  *T3 = malloc(65536 * 16);
  *T4 = malloc(2097152 * 8);
  *T5 = malloc(2097152 * 8); // 2^ 21
  *T6 = malloc(4194304 * 8); // 2^22
  
  int i;
  for(i = 0; i < 65536*2; i++){
    (*T0)[i] = rand64();
    (*T1)[i] = rand64();
    (*T2)[i] = rand64();
    (*T3)[i] = rand64();
  }
  for (i = 0; i < 2097152; i++) {
    (*T4)[i] = rand64();
    (*T5)[i] = rand64();
  }
  for (i = 0; i < 4194304; i++) {
    (*T6)[i] = rand64();
  }
}

/*
 * Clears the random number tables for hashing ShortTable64
 */
void clearRandShort64(uint64_t** T0, uint64_t** T1, uint64_t** T2, uint64_t** T3,
                      uint64_t** T4, uint64_t** T5, uint64_t** T6)
{
  free(*T0);
  free(*T1);
  free(*T2);
  free(*T3);
  free(*T4);
  free(*T5);
  free(*T6);
}

// A8 Tabulation hased hasing for 64-bit keys using 8-bit characters
/* tabulation based hashing for 64-but key x
   using 8-bit characters.
   T0, T1... T14 are pre-computed tables */
inline uint64_t CharTable64( uint64_t x, 
  Entry T0[], Entry T1[], Entry T2[], Entry T3[],
  Entry T4[], Entry T5[], Entry T6[], Entry T7[],
  uint64_t T8[], uint64_t T9[], uint64_t T10[], uint64_t T11[],
  uint64_t T12[], uint64_t T13[], uint64_t T14[])
{
  Entry *a0, *a1, *a2, *a3,
        *a4, *a5, *a6, *a7;
  uint64_t c0;
  uint32_t c1;
  

  a0 = &T0[(uint8_t) x];
  a1 = &T1[(uint8_t) (x >> 8)];
  a2 = &T2[(uint8_t) (x >> 16)];
  a3 = &T3[(uint8_t) (x >> 24)];
  a4 = &T4[(uint8_t) (x >> 32)];
  a5 = &T5[(uint8_t) (x >> 40)];
  a6 = &T6[(uint8_t) (x >> 48)];
  a7 = &T7[(uint8_t) (x >> 56)];

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
void makeRandChar64(Entry** T0,Entry** T1,Entry** T2, Entry** T3,
                     Entry** T4, Entry** T5, Entry** T6, Entry** T7,
                     uint64_t** T8, uint64_t** T9, uint64_t** T10, uint64_t** T11,
                     uint64_t** T12, uint64_t** T13, uint64_t** T14)
{
  *T0 = malloc(65536 * 20); //tables of 2^16 (32-bit + 64-bit + 64-bit) Entries
  *T1 = malloc(65536 * 20); //tables of 2^16 (32-bit + 64-bit + 64-bit) Entries
  *T2 = malloc(65536 * 20); //tables of 2^16 (32-bit + 64-bit + 64-bit) Entries
  *T3 = malloc(65536 * 20); //tables of 2^16 (32-bit + 64-bit + 64-bit) Entries
  *T4 = malloc(65536 * 20); //tables of 2^16 (32-bit + 64-bit + 64-bit) Entries
  *T5 = malloc(65536 * 20); //tables of 2^16 (32-bit + 64-bit + 64-bit) Entries
  *T6 = malloc(65536 * 20); //tables of 2^16 (32-bit + 64-bit + 64-bit) Entries
  *T7 = malloc(65536 * 20); //tables of 2^16 (32-bit + 64-bit + 64-bit) Entries
  *T8 = malloc(2048 * 8); //tables of 2^11 64-bit numbers
  *T9 = malloc(2048 * 8); //tables of 2^11 64-bit numbers
  *T10 = malloc(2048 * 8); //tables of 2^11 64-bit numbers
  *T11 = malloc(2048 * 8); //tables of 2^11 64-bit numbers
  *T12 = malloc(2097152 * 8); //tables of 2^21 64-bit numbers
  *T13 = malloc(2048 * 8); //tables of 2^11 64-bit numbers
  *T14 = malloc(2097152 * 8); //tables of 2^21 64-bit numbers
  
  int i;
  for (i  = 0; i < 256; i++) {
    (*T0)[i].h = rand64();
    (*T0)[i].u = rand64();
    (*T0)[i].v = rand32();
    (*T1)[i].h = rand64();
    (*T1)[i].u = rand64();
    (*T1)[i].v = rand32();
    (*T2)[i].h = rand64();
    (*T2)[i].u = rand64();
    (*T2)[i].v = rand32();
    (*T3)[i].h = rand64();
    (*T3)[i].u = rand64();
    (*T3)[i].v = rand32();
    (*T4)[i].h = rand64();
    (*T4)[i].u = rand64();
    (*T4)[i].v = rand32();
    (*T5)[i].h = rand64();
    (*T5)[i].u = rand64();
    (*T5)[i].v = rand32();
    (*T6)[i].h = rand64();
    (*T6)[i].u = rand64();
    (*T6)[i].v = rand32();
    (*T7)[i].h = rand64();
    (*T7)[i].u = rand64();
    (*T7)[i].v = rand32();
  }

  for (i = 0; i < 2048; i++) {
    (*T9)[i] = rand64();
    (*T10)[i] = rand64();
    (*T11)[i] = rand64();
    (*T13)[i] = rand64();
  }
  for (i = 0; i < 2097152; i++) {
    (*T12)[i] = rand64();
    (*T14)[i] = rand64();
  }
}

/*
 * Clears the random number tables for hashing ShortTable64
 */
void clearRandChar64(Entry** T0,Entry** T1,Entry** T2, Entry** T3,
                     Entry** T4, Entry** T5, Entry** T6, Entry** T7,
                     uint64_t** T8, uint64_t** T9, uint64_t** T10, uint64_t** T11,
                     uint64_t** T12, uint64_t** T13, uint64_t** T14)
{
  free(*T0);
  free(*T1);
  free(*T2);
  free(*T3);
  free(*T4);
  free(*T5);
  free(*T6);
  free(*T7); 
  free(*T8);
  free(*T9);
  free(*T10);
  free(*T11);
  free(*T12);
  free(*T13);
  free(*T14);
}







/*
 *     QUADRATIC and LINEAR PROBING 
 *     BEGINS
 */
void probingShort32(uint32_t** T0,
		    uint32_t** T1,
		    uint32_t** T2,
		    enum ProbingType type)
{
  uint32_t* hash_table;
  int i;
  int n_collisions = 0;
  uint32_t index_hash;
  uint32_t new_index_hash;
  uint32_t counter;
  hash_table = malloc(TABLE_SIZE * 4);
  for (i = 0; i < TABLE_SIZE; i++) {
    hash_table[i] = (uint32_t) 0;
  }

  for(i = 0; i < N_HASHES; i++) {
    counter = 0;
    index_hash = ShortTable32((uint32_t) i, (uint32_t*) *T0,(uint32_t*) *T1, (uint32_t*) *T2);
    new_index_hash = index_hash = index_hash % TABLE_SIZE;
    while (hash_table[new_index_hash] != (uint32_t) 0 && counter <= 2*TABLE_SIZE) {
      counter ++;
      if (type == linear) {
	new_index_hash  = index_hash + counter;
      } else {
	new_index_hash = index_hash + counter * counter;
      } 
      new_index_hash = new_index_hash % TABLE_SIZE;
      n_collisions ++;
    }
    printf("%u\n", counter);
    hash_table[new_index_hash] = i;
  }
  free(hash_table);
  printf("Short32 type: %d  n of collisions: %d\n", type, n_collisions);
}

void probingChar32(uint32_t** T0,
		   uint32_t** T1,
		   uint32_t** T2,
		   uint32_t** T3,
		   uint32_t** T4,
		   uint32_t** T5,
		   uint32_t** T6,
		   enum ProbingType type)
{
  uint32_t* hash_table;
  int i;
  int n_collisions = 0;
  uint32_t index_hash;
  uint32_t new_index_hash;
  uint32_t counter;
  hash_table = malloc(TABLE_SIZE * 4);
  for (i = 0; i < TABLE_SIZE; i++) {
    hash_table[i] = (uint32_t) 0;
  }

  for(i = 0; i < N_HASHES; i++) {
    counter = 0;
    index_hash = CharTable32((uint32_t) i, (uint32_t*) *T0,(uint32_t*) *T1, (uint32_t*) *T2,
			      (uint32_t*) *T3, (uint32_t*) *T4, (uint32_t*) *T5, (uint32_t*) *T6);
    new_index_hash = index_hash = index_hash % TABLE_SIZE;
    while (hash_table[new_index_hash] != (uint32_t) 0 &&  counter <= 2*TABLE_SIZE) {
      counter ++;
      if (type == linear) {
	new_index_hash  = index_hash + counter;
      } else {
	new_index_hash = index_hash + counter * counter;
      } 
      new_index_hash = new_index_hash % TABLE_SIZE;
      n_collisions ++;
    }
    printf("%u\n", counter);
    hash_table[new_index_hash] = i;
  }
  free(hash_table);
  printf("Char32 type: %d n of collisions: %d\n", type, n_collisions);
}

void probingShort64(uint64_t** T0,
		    uint64_t** T1,
		    uint64_t** T2,
		    uint64_t** T3,
		    uint64_t** T4,
		    uint64_t** T5,
		    uint64_t** T6,
		    enum ProbingType type)
{
  uint64_t* hash_table;
  int i;
  int n_collisions = 0;
  uint64_t index_hash;
  uint64_t new_index_hash;
  uint64_t counter;
  hash_table = malloc(TABLE_SIZE * 8);
  for (i = 0; i < TABLE_SIZE; i++) {
    hash_table[i] = (uint64_t) 0;
  }

  for(i = 0; i < N_HASHES; i++) {
    counter = 0;
    index_hash = ShortTable64((uint64_t) i, (uint64_t*) *T0,(uint64_t*) *T1, (uint64_t*) *T2,
			      (uint64_t*) *T3, (uint64_t*) *T4, (uint64_t*) *T5, (uint64_t*) *T6);
    new_index_hash = index_hash = index_hash % TABLE_SIZE;
    while (hash_table[new_index_hash] != (uint64_t) 0 && counter <= 2*TABLE_SIZE) {
      counter++;
      if (type == linear) {
	new_index_hash  = index_hash + counter;
      } else {
	new_index_hash = index_hash + counter * counter;
      } 
      new_index_hash = new_index_hash % TABLE_SIZE;
      n_collisions++;
    }
    printf("%u\n", counter);
    hash_table[new_index_hash] = i;
  }
  free(hash_table);
  printf("Short64 type: %d n of collisions: %u\n", type, n_collisions);
}

void probingChar64(Entry** T0,Entry** T1,Entry** T2, Entry** T3,
		   Entry** T4, Entry** T5, Entry** T6, Entry** T7,
		   uint64_t** T8, uint64_t** T9, uint64_t** T10, uint64_t** T11,
		   uint64_t** T12, uint64_t** T13, uint64_t** T14, enum ProbingType type)
{
  uint64_t* hash_table;
  int i;
  int n_collisions = 0;
  uint64_t index_hash;
  uint64_t new_index_hash;
  uint64_t counter;
  hash_table = malloc(TABLE_SIZE * 8);
  for (i = 0; i < TABLE_SIZE; i++) {
    hash_table[i] = (uint64_t) 0;
  }

  for(i = 0; i < N_HASHES; i++) {
    counter = 0;
    index_hash = CharTable64((uint64_t) i, 
			     (Entry*) *T0, (Entry*) *T1, (Entry*) *T2, (Entry*) *T3,
			     (Entry*) *T4, (Entry*) *T5, (Entry*) *T6, (Entry*) *T7,
			     (uint64_t*) *T8, (uint64_t*) *T9, (uint64_t*) *T10, (uint64_t*) *T11,
			     (uint64_t*) *T12, (uint64_t*) *T13, (uint64_t*) *T14);
    new_index_hash = index_hash = index_hash % TABLE_SIZE;
    while (hash_table[new_index_hash] != (uint64_t) 0 && counter <= 2*TABLE_SIZE) {
      counter ++;
      if (type == linear) {
	new_index_hash  = index_hash + counter;
      } else {
	new_index_hash = index_hash + counter * counter;
      } 
      new_index_hash = new_index_hash % TABLE_SIZE;
      n_collisions ++;
    }
    printf("%u\n", counter);
    hash_table[new_index_hash] = i;
  }
  free(hash_table);
  printf("Char64 type: %d n of collisions: %d\n", type, n_collisions);
}

void probingTestShort32()
{
  void* T0;
  void* T1;
  void* T2;

  enum ProbingType type = linear;
  enum ProbingType type1 = quadratic;


  // Short 32 linear and quadratic
  makeRandShort32((uint32_t**) &T0, (uint32_t**) &T1, (uint32_t**) &T2);
  //probingShort32((uint32_t**) &T0, (uint32_t**) &T1, (uint32_t**) &T2, type);
  probingShort32((uint32_t**) &T0, (uint32_t**) &T1, (uint32_t**) &T2, type1);
  clearRandShort32((uint32_t**) &T0, (uint32_t**) &T1, (uint32_t**) &T2);

}

void probingTestChar32()
{
  void* T0;
  void* T1;
  void* T2;
  void* T3;
  void* T4;
  void* T5;
  void* T6;
  
  enum ProbingType type = linear;
  enum ProbingType type1 = quadratic;

    // Char 32 linear and quadratic
  makeRandChar32((uint32_t**) &T0, (uint32_t**) &T1, (uint32_t**) &T2,
                 (uint32_t**) &T3, (uint32_t**) &T4, (uint32_t**) &T5,
                 (uint32_t**) &T6);
/*
  probingChar32((uint32_t**) &T0, (uint32_t**) &T1, (uint32_t**) &T2,
		(uint32_t**) &T3, (uint32_t**) &T4, (uint32_t**) &T5, (uint32_t**) &T6,
		type);
*/
  probingChar32((uint32_t**) &T0, (uint32_t**) &T1, (uint32_t**) &T2,
		(uint32_t**) &T3, (uint32_t**) &T4, (uint32_t**) &T5, (uint32_t**) &T6,
		type1);

  clearRandChar32((uint32_t**) &T0, (uint32_t**) &T1, (uint32_t**) &T2,
                 (uint32_t**) &T3, (uint32_t**) &T4, (uint32_t**) &T5,
                 (uint32_t**) &T6);
}

void probingTestShort64()
{
  void* T0;
  void* T1;
  void* T2;
  void* T3;
  void* T4;
  void* T5;
  void* T6;

  enum ProbingType type = linear;
  enum ProbingType type1 = quadratic;
  
  // Short 64 linear and quadratic
  makeRandShort64((uint64_t**) &T0, (uint64_t**) &T1, (uint64_t**) &T2,
		  (uint64_t**) &T3, (uint64_t**) &T4, (uint64_t**) &T5,
		  (uint64_t**) &T6);
/*
  probingShort64((uint64_t**) &T0, (uint64_t**) &T1, (uint64_t**) &T2,
		 (uint64_t**) &T3, (uint64_t**) &T4, (uint64_t**) &T5, (uint64_t**) &T6,
		 type);
*/
  probingShort64((uint64_t**) &T0, (uint64_t**) &T1, (uint64_t**) &T2,
		 (uint64_t**) &T3, (uint64_t**) &T4, (uint64_t**) &T5, (uint64_t**) &T6,
		 type1);

  clearRandShort64((uint64_t**) &T0, (uint64_t**) &T1, (uint64_t**) &T2,
		   (uint64_t**) &T3, (uint64_t**) &T4, (uint64_t**) &T5,
		   (uint64_t**) &T6);

}

void probingTestChar64()
{
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
  
  enum ProbingType type = linear;
  enum ProbingType type1 = quadratic;

  // Char 64 linear and quadratic
  makeRandChar64((Entry**) &T0,(Entry**) &T1,(Entry**) &T2, (Entry**) &T3,
		 (Entry**) &T4, (Entry**) &T5, (Entry**) &T6, (Entry**) &T7,
		 (uint64_t**) &T8, (uint64_t**) &T9, (uint64_t**) &T10, (uint64_t**) &T11,
		 (uint64_t**) &T12, (uint64_t**) &T13, (uint64_t**) &T14);
  /*
  probingChar64((Entry**) &T0,(Entry**) &T1,(Entry**) &T2, (Entry**) &T3,
		(Entry**) &T4, (Entry**) &T5, (Entry**) &T6, (Entry**) &T7,
		(uint64_t**) &T8, (uint64_t**) &T9, (uint64_t**) &T10, (uint64_t**) &T11,
		(uint64_t**) &T12, (uint64_t**) &T13, (uint64_t**) &T14, type);
  */
  probingChar64((Entry**) &T0,(Entry**) &T1,(Entry**) &T2, (Entry**) &T3,
		(Entry**) &T4, (Entry**) &T5, (Entry**) &T6, (Entry**) &T7,
		(uint64_t**) &T8, (uint64_t**) &T9, (uint64_t**) &T10, (uint64_t**) &T11,
		(uint64_t**) &T12, (uint64_t**) &T13, (uint64_t**) &T14, type1);
  clearRandChar64((Entry**) &T0,(Entry**) &T1,(Entry**) &T2, (Entry**) &T3,
		  (Entry**) &T4, (Entry**) &T5, (Entry**) &T6, (Entry**) &T7,
		  (uint64_t**) &T8, (uint64_t**) &T9, (uint64_t**) &T10, (uint64_t**) &T11,
		  (uint64_t**) &T12, (uint64_t**) &T13, (uint64_t**) &T14);

}
/*
 *     QUADRATIC and LINEAR PROBING 
 *     ENDS
 */


/*
 *     CHAINING
 *     BEGINS
 */
struct Link32{
  struct Link32* next;
  uint32_t value;
};

typedef struct Link64{
  struct Link64* next;
  uint64_t value;
}Link64;


uint32_t chaining32(uint32_t table_size, struct Link32* table[], uint32_t hash, uint32_t value){
  uint32_t index = hash%table_size;
  struct Link32* node = table[index];
  if(node == NULL){
    struct Link32* newNode = malloc(sizeof(struct Link32));
    newNode->value = value;
    newNode->next = NULL;
    table[index] = newNode;
    printf("%d\n", 0);
    return 0;
  }

  if(node->value == value){
    printf("%d\n", 0);
    return 0;
  }
  uint32_t cc = 0; //collision count  
  
  while (node->next != NULL){
    node = node->next;
    cc++;
    if(node->value == value){
      printf("%d\n", cc);
      return cc;
    }
  }
  struct Link32* newNode = malloc(sizeof(struct Link32));
  newNode->value = value;
  newNode->next = NULL;
  node->next = newNode;
  printf("%d\n", cc);
  return cc;
}


void clearChainedTable32(struct Link32* table[], uint32_t table_size){
  uint32_t i;
  struct Link32 * node;
  struct Link32 * nextNode;
  for(i = 0; i <table_size;i++){
    if(table[i] != NULL){
      node = table[i];
      while(node != NULL){
        nextNode = node->next;
        free(node);
        node = nextNode;
      }
    }
  }
}

void chainingTestShort32()
{
  void* T0;
  void* T1;
  void* T2;
  struct Link32** hash_table = malloc(sizeof(void*)*TABLE_SIZE);
  int i;
  uint32_t n_collisions = 0;
  uint32_t index_hash;

  for (i = 0; i < TABLE_SIZE; i++) {
    hash_table[i]= NULL;
  }
  makeRandShort32((uint32_t**) &T0, (uint32_t**) &T1, (uint32_t**) &T2);
  for(i = 0; i < N_HASHES; i++) {
    index_hash = ShortTable32((uint32_t) i, (uint32_t*) T0,(uint32_t*) T1, (uint32_t*) T2);
    n_collisions += chaining32(TABLE_SIZE , hash_table , index_hash, i); 
  }
  clearRandShort32((uint32_t**) &T0, (uint32_t**) &T1, (uint32_t**) &T2);
  printf(" Chaining (Short32): Number of collisions: %d\n", n_collisions);
  clearChainedTable32(hash_table, TABLE_SIZE);
}

void chainingTestChar32()
{
  void* T0;
  void* T1;
  void* T2;
  void* T3;
  void* T4;
  void* T5;
  void* T6;
  struct Link32** hash_table = malloc(sizeof(void*)*TABLE_SIZE);
  int i;
  uint32_t n_collisions = 0;
  uint32_t index_hash;

  for (i = 0; i < TABLE_SIZE; i++) {
    hash_table[i]= NULL;
  }
  makeRandChar32((uint32_t**) &T0, (uint32_t**) &T1, (uint32_t**) &T2,
                 (uint32_t**) &T3, (uint32_t**) &T4, (uint32_t**) &T5,
                 (uint32_t**) &T6);
  for(i = 0; i < N_HASHES; i++) {
    index_hash = CharTable32((uint32_t) i, (uint32_t*) T0,(uint32_t*) T1, (uint32_t*) T2,
                             (uint32_t*) T3, (uint32_t*) T4, (uint32_t*) T5, (uint32_t*) T6);
    n_collisions += chaining32(TABLE_SIZE , hash_table , index_hash, i); 
  }
  clearRandChar32((uint32_t**) &T0, (uint32_t**) &T1, (uint32_t**) &T2,
                 (uint32_t**) &T3, (uint32_t**) &T4, (uint32_t**) &T5,
                 (uint32_t**) &T6);
  printf(" Chaining (Char32): Number of collisions: %d\n", n_collisions);
  clearChainedTable32(hash_table, TABLE_SIZE);
}


uint32_t chaining64(uint64_t table_size, struct Link64* table[], uint64_t hash, uint64_t value){
  uint64_t index = hash%table_size;
  struct Link64* node = table[index];
  if(node == NULL){
    struct Link64* newNode = malloc(sizeof(struct Link64));
    newNode->value = value;
    newNode->next = NULL;
    table[index] = newNode;
    printf("0\n");
    return 0;
  }

  if(node->value == value){
    printf("0\n");
    return 0;
  }
  uint32_t cc = 0; //collision count  
  
  while (node->next != NULL){
    node = node->next;
    cc++;
    if(node->value == value){
      printf("%d\n", cc);
      return cc;
    }
  }
  struct Link64* newNode = malloc(sizeof(struct Link64));
  newNode->value = value;
  newNode->next = NULL;
  node->next = newNode;
  printf("%d\n", cc);
  return cc;
}


void clearChainedTable64(struct Link64* table[], uint64_t table_size){
  uint64_t i;
  struct Link64 * node;
  struct Link64 * nextNode;
  for(i = 0; i <table_size;i++){
    if(table[i] != NULL){
      node = table[i];
      while(node != NULL){
        nextNode = node->next;
        free(node);
        node = nextNode;
      }
    }
  }
}

void chainingTestShort64()
{
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

  struct Link64** hash_table = malloc(sizeof(void*)*TABLE_SIZE);
  int i;
  uint32_t n_collisions = 0;
  uint32_t index_hash;

  for (i = 0; i < TABLE_SIZE; i++) {
    hash_table[i]= NULL;
  }
  makeRandShort64((uint64_t**) &T3, (uint64_t**) &T4, (uint64_t**) &T5,
		  (uint64_t**) &T6, (uint64_t**) &T7, (uint64_t**) &T8,
		  (uint64_t**) &T9);
  for(i = 0; i < N_HASHES; i++) {
    index_hash = ShortTable64((uint64_t) i, (uint64_t*) T3, (uint64_t*) T4,
                              (uint64_t*) T5, (uint64_t*) T6, (uint64_t*) T7,
                              (uint64_t*) T8, (uint64_t*) T9 );
    n_collisions += chaining64(TABLE_SIZE , hash_table , index_hash, i); 
  }
  
  clearRandShort64((uint64_t**) &T3, (uint64_t**) &T4, (uint64_t**) &T5,
		  (uint64_t**) &T6, (uint64_t**) &T7, (uint64_t**) &T8,
		  (uint64_t**) &T9);
  printf(" Chaining (Short64): Number of collisions: %d\n", n_collisions);
  clearChainedTable64(hash_table, TABLE_SIZE);
}

void chainingTestChar64()
{
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

  struct Link64** hash_table = malloc(sizeof(void*)*TABLE_SIZE);
  int i;
  uint32_t n_collisions = 0;
  uint32_t index_hash;

  for (i = 0; i < TABLE_SIZE; i++) {
    hash_table[i]= NULL;
  }
  makeRandChar64((Entry**) &T0,(Entry**) &T1,(Entry**) &T2, (Entry**) &T3,
		 (Entry**) &T4, (Entry**) &T5, (Entry**) &T6, (Entry**) &T7,
		 (uint64_t**) &T8, (uint64_t**) &T9, (uint64_t**) &T10, (uint64_t**) &T11,
		 (uint64_t**) &T12, (uint64_t**) &T13, (uint64_t**) &T14);
  for(i = 0; i < N_HASHES; i++) {
    
    index_hash =  CharTable64((uint64_t) i, 
				 (Entry*) T0, (Entry*) T1, (Entry*) T2, (Entry*) T3,
				 (Entry*) T4, (Entry*) T5, (Entry*) T6, (Entry*) T7,
				 (uint64_t*) T8, (uint64_t*) T9, (uint64_t*) T10, (uint64_t*) T11,
				 (uint64_t*) T12, (uint64_t*) T13, (uint64_t*) T14);
    n_collisions += chaining64(TABLE_SIZE , hash_table , index_hash, i); 
  }
  clearRandChar64((Entry**) &T0,(Entry**) &T1,(Entry**) &T2, (Entry**) &T3,
		 (Entry**) &T4, (Entry**) &T5, (Entry**) &T6, (Entry**) &T7,
		 (uint64_t**) &T8, (uint64_t**) &T9, (uint64_t**) &T10, (uint64_t**) &T11,
		 (uint64_t**) &T12, (uint64_t**) &T13, (uint64_t**) &T14);
  printf(" Chaining (Char32): Number of collisions: %d\n", n_collisions);
  clearChainedTable64(hash_table, TABLE_SIZE);
}

/*
 *     CHAINING 
 *     ENDS
 */


int main(int argc, char *argv[])
{
//  printf("hello world! \n");
  srand(time(NULL));
 // chainingTestShort32();
//   chainingTestShort64();
 // chainingTestChar32();
//  chainingTestChar64();

//  probingTestShort32();
  probingTestChar32();
//  probingTestShort64();
//  probingTestChar64();
  
}
