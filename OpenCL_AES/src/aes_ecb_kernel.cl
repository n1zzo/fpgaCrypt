#ifndef uint8
#define uint8  unsigned char        /** ridefinizione del char senza segno */
#endif

#ifndef uint32
#define uint32 unsigned long int     /** ridefinizione di un intero lungo */
#endif

typedef struct
{
    uint32 erk[64];     // Round Key
    int nr;             // Round Number
}
aes_context;

__constant const uint8 SBox[256] =   // Forward S-box
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

__constant const uint32 RCON[10] =
{
    0x01000000, 0x02000000, 0x04000000, 0x08000000,
    0x10000000, 0x20000000, 0x40000000, 0x80000000,
    0x1B000000, 0x36000000
};

// 4 byte to 32 bit for manipulation
#define GET_UINT32(n,b,i) ((n) =                           \
        ((uint32) (b)[(i)] << 24 ) |     \
        ((uint32) (b)[(i) + 1] << 16 ) | \
        ((uint32) (b)[(i) + 2] << 8  ) | \
        ((uint32) (b)[(i) + 3]))

// 32 bit to 4 byte for composing the encrypted data
void put_uint32(uint32 n, __local uint8 *b, uint8 i)
{
    b[i  ] = (uint8) ( n >> 24 );       \
             b[i+1] = (uint8) ( n >> 16 );       \
             b[i+2] = (uint8) ( n >>  8 );       \
             b[i+3] = (uint8) ( n       );       \
}

/**
 *
 *	Setting encryption key
 *	/param context encryption context
 *	/param bey input key
 *	/param nbits key length
 *
 */

int aes_set_key( __local aes_context *context, __constant const uint8 *key, int nbits )
{
    unsigned int i;
    __local uint32 *RK, *SK;

    // Setting the number of round according to the key length

    switch( nbits )
    {
        case 128: context->nr = 10; break;
        case 192: context->nr = 12; break;
        case 256: context->nr = 14; break;
        default : return( 1 );
    }

    /** Initializing pointer to round key */
    RK = context->erk;

#pragma unroll 8
    for( i = 0; i < (nbits >> 5); i++ )	  // Convert data into 32 bits
    {
        GET_UINT32( RK[i], key, i << 2 );
    }

    switch( context->nr )
    {
        case 10:

#pragma unroll
            for( i = 0; i < 10; i++, RK += 4 )
            {
                RK[4]  = RK[0] ^ RCON[i] ^
                    ( SBox[ (uint8) ( RK[3] >> 16 ) ] << 24 ) ^
                    ( SBox[ (uint8) ( RK[3] >>  8 ) ] << 16 ) ^
                    ( SBox[ (uint8) ( RK[3]       ) ] <<  8 ) ^
                    ( SBox[ (uint8) ( RK[3] >> 24 ) ]       );

                RK[5]  = RK[1] ^ RK[4];
                RK[6]  = RK[2] ^ RK[5];
                RK[7]  = RK[3] ^ RK[6];
            }
            break;

        case 12:

#pragma unroll
            for( i = 0; i < 8; i++, RK += 6 )
            {
                RK[6]  = RK[0] ^ RCON[i] ^
                    ( SBox[ (uint8) ( RK[5] >> 16 ) ] << 24 ) ^
                    ( SBox[ (uint8) ( RK[5] >>  8 ) ] << 16 ) ^
                    ( SBox[ (uint8) ( RK[5]       ) ] <<  8 ) ^
                    ( SBox[ (uint8) ( RK[5] >> 24 ) ]       );

                RK[7]  = RK[1] ^ RK[6];
                RK[8]  = RK[2] ^ RK[7];
                RK[9]  = RK[3] ^ RK[8];
                RK[10] = RK[4] ^ RK[9];
                RK[11] = RK[5] ^ RK[10];
            }
            break;

        case 14:

#pragma unroll
            for( i = 0; i < 7; i++, RK += 8 )
            {
                RK[8]  = RK[0] ^ RCON[i] ^
                    ( SBox[ (uint8) ( RK[7] >> 16 ) ] << 24 ) ^
                    ( SBox[ (uint8) ( RK[7] >>  8 ) ] << 16 ) ^
                    ( SBox[ (uint8) ( RK[7]       ) ] <<  8 ) ^
                    ( SBox[ (uint8) ( RK[7] >> 24 ) ]       );

                RK[9]  = RK[1] ^ RK[8];
                RK[10] = RK[2] ^ RK[9];
                RK[11] = RK[3] ^ RK[10];

                RK[12] = RK[4] ^
                    ( SBox[ (uint8) ( RK[11] >> 24 ) ] << 24 ) ^
                    ( SBox[ (uint8) ( RK[11] >> 16 ) ] << 16 ) ^
                    ( SBox[ (uint8) ( RK[11] >>  8 ) ] <<  8 ) ^
                    ( SBox[ (uint8) ( RK[11]       ) ]       );

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
 *       Kernel entry point
 *	/param ptx_d plaintext
 *	/param key_d cipher key
 *	/param ctx_d ciphertext
 *	/param key_length_d keylength in bit
 *	/param ptx_size plaintext size in bytes
 *
 */
    __kernel __attribute__((reqd_work_group_size(16, 1, 1)))
void aesEcbEncrypt (__constant const uint8* restrict ptx_d,
        __constant const uint8* restrict key_d,
        __global uint8* restrict ctx_d,
        const uint key_length_d,
        const uint ptx_size)
{
    __local aes_context context;
    __local uint8 output[16];

    aes_set_key(&context, key_d, key_length_d); // Key expansion

    __local uint8 RK[224];                   // Round key
    __private int idx;                      // Index of the working item
    __local uint8 X[16];                    // Input blocks (shared in the wg)
    __local uint8 Y[16];                    // Working blocks (shared in the wg)
    __local uint8 Z[16];                    // Output blocks (shared in the wg)
    __private size_t g_size = get_global_size(0); // Total number of work-items
    __private size_t l_size = get_local_size(0);  // Work-items in a work-group
    __private size_t id = get_local_id(0);        // Index in the work-group
    __private size_t global_id = get_global_id(0);// Global index
    __private size_t group_id = get_group_id(0);  // Index of the work-group

    // Perform this computation with one work_group per AES block
    // each work group is composed of 16 work_item, one per AES block byte
    if(group_id < (ptx_size / 16)) {
        printf("%x", ptx_d[global_id]);

        // Note that bytes are inserted columns by rows, so the first 4 bytes
        // in the arrays corresponds to the first column on the left

        // Convert 32bit expanded key array into an 8bit array
        // Split work across work-items, every work-item will perform a certain
        // number of rounds and rem other work items will perform a round once more
        int rounds = (context.nr+1)*4/l_size;
        int rem = ((context.nr+1)*4)%l_size;
#pragma unroll 2
        for(int i = 0; i < rounds; i++)
            put_uint32(context.erk[i*16+id], RK, 4*(i*16+id));
        if(id < rem)
            put_uint32(context.erk[rounds*16+id],
                       RK,
                       4*(rounds*16+id));

        barrier(CLK_LOCAL_MEM_FENCE);

        // Copy data and first AddRoundKey operation
        X[id] = ptx_d[global_id] ^ RK[id];

        barrier(CLK_LOCAL_MEM_FENCE);

        // N-1 encryption rounds, according to key length
#pragma unroll 1  // Can't unroll because of data dependencies
        for(int round_num=1; round_num < context.nr; round_num++)
        {

            barrier(CLK_LOCAL_MEM_FENCE);

            // SubBytes
            Y[id] = SBox[X[id]];

            barrier(CLK_LOCAL_MEM_FENCE);

            // ShiftRows
            __private int i = id % 4;
            __private int j = id / 4;
            Z[i+4*((j-i+4)%4)] = Y[i+4*j];

            barrier(CLK_LOCAL_MEM_FENCE);

            // MixColumns
            if(id < 4) { // This has a 4-way parallelism
                uint8 a[4], b[4];
                for (int i=0; i < 4; i++) {
                    a[i] = Z[id * 4 + i];
                    b[i] = (a[i] << 1) ^ ((a[i] & 0x80) ? 0x1b : 0x00);
                }

                // 2*a0 + 3*a1 +   a2 +   a3
                //   a0 * 2*a1 + 3*a2 +   a3
                //   a0 +   a1 + 2*a2 + 3*a3
                // 3*a0 +   a1 +   a2 + 2*a3

                Z[id * 4] = b[0] ^ a[1] ^ b[1] ^ a[2] ^ a[3];
                Z[id * 4 + 1] = a[0] ^ b[1] ^ a[2] ^ b[2] ^ a[3];
                Z[id * 4 + 2] = a[0] ^ a[1] ^ b[2] ^ a[3] ^ b[3];
                Z[id * 4 + 3] = a[0] ^ b[0] ^ a[1] ^ a[2] ^ b[3];
            }

            barrier(CLK_LOCAL_MEM_FENCE);

            // AddRoundKey
            Z[id] ^= RK[(round_num*16)+id];

            barrier(CLK_LOCAL_MEM_FENCE);

            // Output becomes input of the next round
            X[id] = Z[id];
        }

        // Last round

        barrier(CLK_LOCAL_MEM_FENCE);

        // SubBytes
        Y[id] = SBox[X[id]];

        barrier(CLK_LOCAL_MEM_FENCE);

        // ShiftRows
        __private int i = id % 4;
        __private int j = id / 4;
        Z[i+4*((j-i+4)%4)] = Y[i+4*j];

        barrier(CLK_LOCAL_MEM_FENCE);

        // AddRoundKey
        Z[id] ^= RK[(context.nr*16)+id];

        // Copy results back into host memory
        ctx_d[global_id] = Z[id];

        barrier(CLK_GLOBAL_MEM_FENCE);
    }
}
