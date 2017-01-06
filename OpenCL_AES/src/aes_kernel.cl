#ifndef uint8
#define uint8  unsigned char        /** ridefinizione del char senza segno */
#endif

#ifndef uint32
#define uint32 unsigned long int     /** ridefinizione di un intero lungo */
#endif

typedef struct
{
    uint32 erk[64];     /** chiave di criptaggio per il round */
    int nr;             /** numero di round*/
}
aes_context;		/** definizione del contesto */

__constant static const uint32 FSb[256] =                             /** S-box per il criptaggio */
{
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
    0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
    0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
    0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A,
    0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
    0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,
    0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85,
    0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
    0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17,
    0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88,
    0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
    0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9,
    0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,
    0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
    0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94,
    0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68,
    0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

								/** tabella T per il criptaggio */

#define FT \
\
V(C6,63,63,A5), V(F8,7C,7C,84), V(EE,77,77,99), V(F6,7B,7B,8D), \
V(FF,F2,F2,0D), V(D6,6B,6B,BD), V(DE,6F,6F,B1), V(91,C5,C5,54), \
V(60,30,30,50), V(02,01,01,03), V(CE,67,67,A9), V(56,2B,2B,7D), \
V(E7,FE,FE,19), V(B5,D7,D7,62), V(4D,AB,AB,E6), V(EC,76,76,9A), \
V(8F,CA,CA,45), V(1F,82,82,9D), V(89,C9,C9,40), V(FA,7D,7D,87), \
V(EF,FA,FA,15), V(B2,59,59,EB), V(8E,47,47,C9), V(FB,F0,F0,0B), \
V(41,AD,AD,EC), V(B3,D4,D4,67), V(5F,A2,A2,FD), V(45,AF,AF,EA), \
V(23,9C,9C,BF), V(53,A4,A4,F7), V(E4,72,72,96), V(9B,C0,C0,5B), \
V(75,B7,B7,C2), V(E1,FD,FD,1C), V(3D,93,93,AE), V(4C,26,26,6A), \
V(6C,36,36,5A), V(7E,3F,3F,41), V(F5,F7,F7,02), V(83,CC,CC,4F), \
V(68,34,34,5C), V(51,A5,A5,F4), V(D1,E5,E5,34), V(F9,F1,F1,08), \
V(E2,71,71,93), V(AB,D8,D8,73), V(62,31,31,53), V(2A,15,15,3F), \
V(08,04,04,0C), V(95,C7,C7,52), V(46,23,23,65), V(9D,C3,C3,5E), \
V(30,18,18,28), V(37,96,96,A1), V(0A,05,05,0F), V(2F,9A,9A,B5), \
V(0E,07,07,09), V(24,12,12,36), V(1B,80,80,9B), V(DF,E2,E2,3D), \
V(CD,EB,EB,26), V(4E,27,27,69), V(7F,B2,B2,CD), V(EA,75,75,9F), \
V(12,09,09,1B), V(1D,83,83,9E), V(58,2C,2C,74), V(34,1A,1A,2E), \
V(36,1B,1B,2D), V(DC,6E,6E,B2), V(B4,5A,5A,EE), V(5B,A0,A0,FB), \
V(A4,52,52,F6), V(76,3B,3B,4D), V(B7,D6,D6,61), V(7D,B3,B3,CE), \
V(52,29,29,7B), V(DD,E3,E3,3E), V(5E,2F,2F,71), V(13,84,84,97), \
V(A6,53,53,F5), V(B9,D1,D1,68), V(00,00,00,00), V(C1,ED,ED,2C), \
V(40,20,20,60), V(E3,FC,FC,1F), V(79,B1,B1,C8), V(B6,5B,5B,ED), \
V(D4,6A,6A,BE), V(8D,CB,CB,46), V(67,BE,BE,D9), V(72,39,39,4B), \
V(94,4A,4A,DE), V(98,4C,4C,D4), V(B0,58,58,E8), V(85,CF,CF,4A), \
V(BB,D0,D0,6B), V(C5,EF,EF,2A), V(4F,AA,AA,E5), V(ED,FB,FB,16), \
V(86,43,43,C5), V(9A,4D,4D,D7), V(66,33,33,55), V(11,85,85,94), \
V(8A,45,45,CF), V(E9,F9,F9,10), V(04,02,02,06), V(FE,7F,7F,81), \
V(A0,50,50,F0), V(78,3C,3C,44), V(25,9F,9F,BA), V(4B,A8,A8,E3), \
V(A2,51,51,F3), V(5D,A3,A3,FE), V(80,40,40,C0), V(05,8F,8F,8A), \
V(3F,92,92,AD), V(21,9D,9D,BC), V(70,38,38,48), V(F1,F5,F5,04), \
V(63,BC,BC,DF), V(77,B6,B6,C1), V(AF,DA,DA,75), V(42,21,21,63), \
V(20,10,10,30), V(E5,FF,FF,1A), V(FD,F3,F3,0E), V(BF,D2,D2,6D), \
V(81,CD,CD,4C), V(18,0C,0C,14), V(26,13,13,35), V(C3,EC,EC,2F), \
V(BE,5F,5F,E1), V(35,97,97,A2), V(88,44,44,CC), V(2E,17,17,39), \
V(93,C4,C4,57), V(55,A7,A7,F2), V(FC,7E,7E,82), V(7A,3D,3D,47), \
V(C8,64,64,AC), V(BA,5D,5D,E7), V(32,19,19,2B), V(E6,73,73,95), \
V(C0,60,60,A0), V(19,81,81,98), V(9E,4F,4F,D1), V(A3,DC,DC,7F), \
V(44,22,22,66), V(54,2A,2A,7E), V(3B,90,90,AB), V(0B,88,88,83), \
V(8C,46,46,CA), V(C7,EE,EE,29), V(6B,B8,B8,D3), V(28,14,14,3C), \
V(A7,DE,DE,79), V(BC,5E,5E,E2), V(16,0B,0B,1D), V(AD,DB,DB,76), \
V(DB,E0,E0,3B), V(64,32,32,56), V(74,3A,3A,4E), V(14,0A,0A,1E), \
V(92,49,49,DB), V(0C,06,06,0A), V(48,24,24,6C), V(B8,5C,5C,E4), \
V(9F,C2,C2,5D), V(BD,D3,D3,6E), V(43,AC,AC,EF), V(C4,62,62,A6), \
V(39,91,91,A8), V(31,95,95,A4), V(D3,E4,E4,37), V(F2,79,79,8B), \
V(D5,E7,E7,32), V(8B,C8,C8,43), V(6E,37,37,59), V(DA,6D,6D,B7), \
V(01,8D,8D,8C), V(B1,D5,D5,64), V(9C,4E,4E,D2), V(49,A9,A9,E0), \
V(D8,6C,6C,B4), V(AC,56,56,FA), V(F3,F4,F4,07), V(CF,EA,EA,25), \
V(CA,65,65,AF), V(F4,7A,7A,8E), V(47,AE,AE,E9), V(10,08,08,18), \
V(6F,BA,BA,D5), V(F0,78,78,88), V(4A,25,25,6F), V(5C,2E,2E,72), \
V(38,1C,1C,24), V(57,A6,A6,F1), V(73,B4,B4,C7), V(97,C6,C6,51), \
V(CB,E8,E8,23), V(A1,DD,DD,7C), V(E8,74,74,9C), V(3E,1F,1F,21), \
V(96,4B,4B,DD), V(61,BD,BD,DC), V(0D,8B,8B,86), V(0F,8A,8A,85), \
V(E0,70,70,90), V(7C,3E,3E,42), V(71,B5,B5,C4), V(CC,66,66,AA), \
V(90,48,48,D8), V(06,03,03,05), V(F7,F6,F6,01), V(1C,0E,0E,12), \
V(C2,61,61,A3), V(6A,35,35,5F), V(AE,57,57,F9), V(69,B9,B9,D0), \
V(17,86,86,91), V(99,C1,C1,58), V(3A,1D,1D,27), V(27,9E,9E,B9), \
V(D9,E1,E1,38), V(EB,F8,F8,13), V(2B,98,98,B3), V(22,11,11,33), \
V(D2,69,69,BB), V(A9,D9,D9,70), V(07,8E,8E,89), V(33,94,94,A7), \
V(2D,9B,9B,B6), V(3C,1E,1E,22), V(15,87,87,92), V(C9,E9,E9,20), \
V(87,CE,CE,49), V(AA,55,55,FF), V(50,28,28,78), V(A5,DF,DF,7A), \
V(03,8C,8C,8F), V(59,A1,A1,F8), V(09,89,89,80), V(1A,0D,0D,17), \
V(65,BF,BF,DA), V(D7,E6,E6,31), V(84,42,42,C6), V(D0,68,68,B8), \
V(82,41,41,C3), V(29,99,99,B0), V(5A,2D,2D,77), V(1E,0F,0F,11), \
V(7B,B0,B0,CB), V(A8,54,54,FC), V(6D,BB,BB,D6), V(2C,16,16,3A)

/** creazione di quattro tabelle per il criptaggio parallelo */
#define V(a,b,c,d) 0x##a##b##c##d    
__constant static const uint32 FT0[256] = { FT };
#undef V

#define V(a,b,c,d) 0x##d##a##b##c
__constant static const uint32 FT1[256] = { FT };
#undef V

#define V(a,b,c,d) 0x##c##d##a##b
__constant static const uint32 FT2[256] = { FT };
#undef V

#define V(a,b,c,d) 0x##b##c##d##a
__constant static const uint32 FT3[256] = { FT };
#undef V

#undef FT

__constant static const uint32 RCON[10] =       /** costante per il round */
{
    0x01000000, 0x02000000, 0x04000000, 0x08000000,
    0x10000000, 0x20000000, 0x40000000, 0x80000000,
    0x1B000000, 0x36000000
};

/** Passaggio da un quarto di dati (4 bit) ai 32 bit per la manipolazione */
#define GET_UINT32(n,b,i) ((n) =                           \
			  ((uint32) (b)[(i)] << 24 ) |     \
			  ((uint32) (b)[(i) + 1] << 16 ) | \
			  ((uint32) (b)[(i) + 2] << 8  ) | \
			  ((uint32) (b)[(i) + 3]))

/** Passaggio da 32 bit a 4 per la ricomposizione del dato criptato */
void put_uint32(uint32 n, uint8 *b, uint8 i)
{
        b[i  ] = (uint8) ( n >> 24 );       \
        b[i+1] = (uint8) ( n >> 16 );       \
        b[i+2] = (uint8) ( n >>  8 );       \
        b[i+3] = (uint8) ( n       );       \
}

/**
*
*	Funzione per l'applicazione di un singolo round dell'algoritmo AES 
* 	/param X0 risultato del round
*	/param Y0, Y1, Y2, Y3 dati in ingresso e risultati del round precedente
*
*/
void aes_fround( uint32 X0, uint32 Y0, uint32 Y1, uint32 Y2, uint32 Y3, uint32 *RK, int idx)
{
	if(idx < 4)
	{
		RK += 4; 
		switch(idx)   /** suddivisione e criptaggio delle paraole eseguite da thread */
		{	      /** paralleli, uno per ogni quarto di dato */
			case 0:
				X0 = RK[0] ^ FT0[ (uint8) ( Y0 >> 24 ) ] ^  
				FT1[ (uint8) ( Y1 >> 16 ) ] ^  
				FT2[ (uint8) ( Y2 >>  8 ) ] ^  
				FT3[ (uint8) ( Y3       ) ]; 
				break;
			case 1:
				X0 = RK[1] ^ FT0[ (uint8) ( Y1 >> 24 ) ] ^  
				FT1[ (uint8) ( Y2 >> 16 ) ] ^  
				FT2[ (uint8) ( Y3 >>  8 ) ] ^  
				FT3[ (uint8) ( Y0       ) ];
				break;
			case 2:
				X0 = RK[2] ^ FT0[ (uint8) ( Y2 >> 24 ) ] ^  
				FT1[ (uint8) ( Y3 >> 16 ) ] ^  
				FT2[ (uint8) ( Y0 >>  8 ) ] ^  
				FT3[ (uint8) ( Y1       ) ];
				break;
			case 3:
				X0 = RK[3] ^ FT0[ (uint8) ( Y3 >> 24 ) ] ^  
				FT1[ (uint8) ( Y0 >> 16 ) ] ^  
				FT2[ (uint8) ( Y1 >>  8 ) ] ^  
				FT3[ (uint8) ( Y2       ) ];
				break;
		}
	}
}

/**
*
*	Settaggio della chiave per il criptaggio
*	/param context contesto
*	/param bey chiave iniziale
*	/param nbits lunghezza chiave
*
*/
int aes_set_key( aes_context *context, uint8 *key, int nbits )
{
    int i;
    uint32 *RK, *SK;
	
    switch( nbits )   /** settaggio del numero di round da effettuare in base alla lunghezza della chiave */
    {
        case 128: context->nr = 10; break;
        case 192: context->nr = 12; break;
        case 256: context->nr = 14; break;
        default : return( 1 );
    }
	
    RK = context->erk;			/** inizializzazione del puntatore alla chiave per ogni round */
	
    for( i = 0; i < (nbits >> 5); i++ )		/** passaggio a 32 bit */
    {
        GET_UINT32( RK[i], key, i * 4 );
    }
	
    switch( nbits )				/** settaggio chiave */
    {
		case 128:
			
			for( i = 0; i < 10; i++, RK += 4 )
			{
				RK[4]  = RK[0] ^ RCON[i] ^
				( FSb[ (uint8) ( RK[3] >> 16 ) ] << 24 ) ^
				( FSb[ (uint8) ( RK[3] >>  8 ) ] << 16 ) ^
				( FSb[ (uint8) ( RK[3]       ) ] <<  8 ) ^
				( FSb[ (uint8) ( RK[3] >> 24 ) ]       );
				
				RK[5]  = RK[1] ^ RK[4];
				RK[6]  = RK[2] ^ RK[5];
				RK[7]  = RK[3] ^ RK[6];
			}
			break;
			
		case 192:
			
			for( i = 0; i < 8; i++, RK += 6 )
			{
				RK[6]  = RK[0] ^ RCON[i] ^
				( FSb[ (uint8) ( RK[5] >> 16 ) ] << 24 ) ^
				( FSb[ (uint8) ( RK[5] >>  8 ) ] << 16 ) ^
				( FSb[ (uint8) ( RK[5]       ) ] <<  8 ) ^
				( FSb[ (uint8) ( RK[5] >> 24 ) ]       );
				
				RK[7]  = RK[1] ^ RK[6];
				RK[8]  = RK[2] ^ RK[7];
				RK[9]  = RK[3] ^ RK[8];
				RK[10] = RK[4] ^ RK[9];
				RK[11] = RK[5] ^ RK[10];
			}
			break;
			
		case 256:
			
			for( i = 0; i < 7; i++, RK += 8 )
			{
				RK[8]  = RK[0] ^ RCON[i] ^
				( FSb[ (uint8) ( RK[7] >> 16 ) ] << 24 ) ^
				( FSb[ (uint8) ( RK[7] >>  8 ) ] << 16 ) ^
				( FSb[ (uint8) ( RK[7]       ) ] <<  8 ) ^
				( FSb[ (uint8) ( RK[7] >> 24 ) ]       );
				
				RK[9]  = RK[1] ^ RK[8];
				RK[10] = RK[2] ^ RK[9];
				RK[11] = RK[3] ^ RK[10];
				
				RK[12] = RK[4] ^
				( FSb[ (uint8) ( RK[11] >> 24 ) ] << 24 ) ^
				( FSb[ (uint8) ( RK[11] >> 16 ) ] << 16 ) ^
				( FSb[ (uint8) ( RK[11] >>  8 ) ] <<  8 ) ^
				( FSb[ (uint8) ( RK[11]       ) ]       );
				
				RK[13] = RK[5] ^ RK[12];
				RK[14] = RK[6] ^ RK[13];
				RK[15] = RK[7] ^ RK[14];
			}
			break;
    }
	
    return( 0 );
	
}


/**
*
*	Funzione dedicata al criptaggio
*	/param context contesto
*	/param input dati iniziali
*	/param output dati criptati
*
*/
void aes_encrypt( aes_context *context, uint8 input[16], uint8 output[16] )
{
	
    __private uint32 *RK;            /** Round key */
    __private int idx;               /** Index of the working item */
    __local uint32 X0, X1, X2, X3;   /** Input blocks (shared in the wg) */
    __local uint32 Y0, Y1, Y2, Y3;   /** Output blocks (shared in the wg) */

    RK = context->erk;
	
	idx = get_global_id(0);

        /** Round Zero */
	if(idx < 4)
	{
		switch(idx)		  /** adattamento dei dati ai 32 bit */
		{
			case 0:
				GET_UINT32( X0, input,  0 );
                                X0 ^= RK[0];
				break;
			case 1:
				GET_UINT32( X1, input,  4 );
                                X1 ^= RK[1];
				break;
			case 2:
				GET_UINT32( X2, input,  8 );
                                X2 ^= RK[2];
				break;
			case 3:
				GET_UINT32( X3, input, 12 );
                                X3 ^= RK[3];
				break;
		}
		
		barrier(CLK_GLOBAL_MEM_FENCE);
	}
	
	for(int i=0; i<context->nr; i++)	  /** N-1 round di criptaggio, in base alla lunghezza della chiave */
	{
		if(idx < 4)
		{
			switch(idx)
			{
				case 0:
					aes_fround(Y0, X0, X1, X2, X3, RK, idx);
					break;
				case 1:
					aes_fround(Y1, X0, X1, X2, X3, RK, idx);
					break;
				case 2:
					aes_fround(Y2, X0, X1, X2, X3, RK, idx);
					break;
				case 3:
					aes_fround(Y3, X0, X1, X2, X3, RK, idx);
					break;
			}
			barrier(CLK_GLOBAL_MEM_FENCE);	  /** sincronizzazione tra i thread */
			X0 = Y0;
			X1 = Y1;
			X2 = Y2;
			X3 = Y3;
		}
	}
							  /** ultimo round */
	RK +=4;
	
	
	if(idx < 4)
	{
		switch(idx)
		{
			case 0:
				X0 = RK[0] ^ ( FSb[ (uint8) ( Y0 >> 24 ) ] << 24 ) ^
				( FSb[ (uint8) ( Y1 >> 16 ) ] << 16 ) ^
				( FSb[ (uint8) ( Y2 >>  8 ) ] <<  8 ) ^
				( FSb[ (uint8) ( Y3       ) ]       );
				put_uint32( X0, output,  0 );
				break;
			case 1:
				X1 = RK[1] ^ ( FSb[ (uint8) ( Y1 >> 24 ) ] << 24 ) ^
				( FSb[ (uint8) ( Y2 >> 16 ) ] << 16 ) ^
				( FSb[ (uint8) ( Y3 >>  8 ) ] <<  8 ) ^
				( FSb[ (uint8) ( Y0       ) ]       );
				put_uint32( X1, output,  4 );
				break;
			case 2:
				X2 = RK[2] ^ ( FSb[ (uint8) ( Y2 >> 24 ) ] << 24 ) ^
				( FSb[ (uint8) ( Y3 >> 16 ) ] << 16 ) ^
				( FSb[ (uint8) ( Y0 >>  8 ) ] <<  8 ) ^
				( FSb[ (uint8) ( Y1       ) ]       );
				put_uint32( X2, output,  8 );
				break;
			case 3:
				X3 = RK[3] ^ ( FSb[ (uint8) ( Y3 >> 24 ) ] << 24 ) ^
				( FSb[ (uint8) ( Y0 >> 16 ) ] << 16 ) ^
				( FSb[ (uint8) ( Y1 >>  8 ) ] <<  8 ) ^
				( FSb[ (uint8) ( Y2       ) ]       );
				put_uint32( X3, output, 12 );
				break;
		}
		
		barrier(CLK_GLOBAL_MEM_FENCE);
	}
}


/**
*
*       Kernel entry point
*	/param ptx_d plaintext
*	/param key_d cipher key
*	/param ctx_d ciphertext
*	/param key_length_d keylength in bit
*	/param ptx_size plaintext size in bytes
*
*/
__kernel void aesEncrypt (__global const uchar* ptx_d,
                          __global const uchar* key_d,
                          __global uchar* ctx_d,
                          const uint key_length_d,
                          const uint ptx_size)
{
        // [TODO] ptx_size parameter is actually never used!
        // We will use it to implement XTS mode of operation
        
        aes_context context;
        unsigned char data[16];
	unsigned char res[16];
        unsigned char key[32];
	
        // Now we are copying just the first block
        // [TODO] Implement at least ECB

	for(int i=0; i<16; i++)
	{
		data[i] = ptx_d[i];
		res[i] = 0;
	}
	
	aes_set_key(&context, key_d, key_length_d);
	aes_encrypt(&context, data, res);
	
	for(int i = 0; i<16 ; i++)
	{
		ctx_d[i] = res[i];
	}
}
