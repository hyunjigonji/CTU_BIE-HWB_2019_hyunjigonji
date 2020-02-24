#include <stdio.h>
#include <stdint.h>
#include <time.h>
 
/* AES-128 simple implementation template and testing */
 
/*
Author: Hyunji LEE, leehyun1@fit.cvut.cz
Template: Jiri Bucek 2017
AES specification:
http://csrc.nist.gov/publications/fips/fips197/fips-197.pdf
*/
 
/* AES Constants */
 
// forward sbox
const uint8_t SBOX[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};
 
const uint8_t rCon[12] = {
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
};
 
/* AES state type */
typedef uint32_t t_state[4];
 
/* Helper functions */
void hexprint16(uint8_t *p) {
    for (int i = 0; i < 16; i++)
        printf("%02hhx ", p[i]);
    puts("");
}
 
void hexprintw(uint32_t w) {
    for (int i = 0; i < 32; i += 8)
        printf("%02hhx ", (w >> i) & 0xffU);
}
 
void hexprintws(uint32_t * p, int cnt) {
    for (int i = 0; i < cnt; i++)
        hexprintw(p[i]);
    puts("");
}
void printstate(t_state s) {
    hexprintw(s[0]);
    hexprintw(s[1]);
    hexprintw(s[2]);
    hexprintw(s[3]);
    puts("");
}
 
uint32_t word(uint8_t a0, uint8_t a1, uint8_t a2, uint8_t a3) {
    return a0 | (uint32_t)a1 << 8 | (uint32_t)a2 << 16 | (uint32_t)a3 << 24;
}
 
uint8_t wbyte(uint32_t w, int pos) {
    return (w >> (pos * 8)) & 0xff;
}
 
// **************** AES  functions ****************
uint32_t subWord(uint32_t w) {
    return word(SBOX[wbyte(w, 0)], SBOX[wbyte(w, 1)], SBOX[wbyte(w, 2)], SBOX[wbyte(w, 3)]);
}
 
void subBytes(t_state s) { /* here */
    for (int i = 0; i < 4; i++) {
        s[i] = subWord(s[i]);
    }
}
 
void shiftRows(t_state s) { /* here */
    uint8_t state[4][4];
    for(int i = 0 ; i < 4 ; i++){
        for(int j = 0 ; j < 4 ; j++){
            uint8_t temp = wbyte(s[i],j);
            state[i][j] = temp;
            //printf("%02x ",temp);
        }
        //printf("\n");
    }
    
    uint8_t newState[4][4];
    for(int i = 0 ; i < 4 ; i++){
        for(int j = 0 ; j < 4 ; j++){
            newState[j][i] = state[(j+i)%4][i];
            //printf("%02x ",newState[j][i]);
        }
        //printf("\n");
    }
    
    for (int i = 0 ; i < 4 ; i++) {
        s[i] = word(newState[i][0],newState[i][1],newState[i][2],newState[i][3]);
    }
}
 
uint8_t xtime(uint8_t a) {  /* here */
    return ((a << 1) ^ (((a >> 7) & 1) * 0x1b));
}
 
// not mandatory - mix a single column
uint32_t mixColumn(uint32_t c) {  /* here */
    return 0;
}
 
 
void mixColumns(t_state s) {  /* here */
    uint8_t state[4][4];
    for(int i = 0 ; i < 4 ; i++){
        for(int j = 0 ; j < 4 ; j++){
            uint8_t temp = wbyte(s[i],j);
            state[i][j] = temp;
            //printf("%02x ",temp);
        }
        //printf("\n");
    }
    
    uint8_t ax[4][4] = {{02, 03, 01, 01},
                        {01, 02, 03, 01},
                        {01, 01, 02, 03},
                        {03, 01, 01, 02}};
    
    uint8_t newState[4][4];
    for(int i = 0 ; i < 4 ; i++){
        for(int j = 0 ; j < 4 ; j++){
            uint8_t sum = 0;
            for(int k = 0 ; k < 4 ; k++){
                if(ax[i][k] == 01){
                    sum ^= state[j][k];
                }
                else if(ax[i][k] == 02){
                    sum ^= xtime(state[j][k]);
                }
                else if(ax[i][k] == 03){
                    sum ^= (xtime(state[j][k])^state[j][k]);
                }
            }
            newState[i][j] = sum;
            //printf("%02x ", sum);
        }
        //printf("\n");
    }
    
    for (int i = 3 ; i >= 0 ; i--) {
        s[i] = word(newState[0][i],newState[1][i],newState[2][i],newState[3][i]);
    }
}
 
/*
* Key expansion from 128bits (4*32b)
* to 11 round keys (11*4*32b)
* each round key is 4*32b
*/
 
uint32_t RotWord(uint32_t word) {
    uint32_t temp = wbyte(word,0);
 
    return (word >> 8) | ((temp & 0xFF) << 24);
}
 
void expandKey(uint8_t k[16], uint32_t ek[44]) {  /* here */
    uint32_t temp;
 
    int i = 0;
    while (i < 4) {
        ek[i] = word(k[4*i], k[4*i+1], k[4*i+2], k[4*i+3]);
        i++;
    }
 
    i = 4;
 
    while (i < 44) {
        temp = ek[i-1];
        if (i % 4 == 0) {
            temp = subWord(RotWord(temp)) ^ rCon[i/4];
        }
        ek[i] = ek[i-4] ^ temp;
        i++;
    }
}
 
 
/* Adding expanded round key (prepared before) */
void addRoundKey(t_state s, uint32_t ek[], short round) {  /* here */
    uint32_t temp[4];
    for (int i = 0; i < 4; i++) {
        temp[i] = s[i] ^ ek[4*round+i];
    }
    for(int i = 0 ; i < 4 ; i++){
        s[i] = temp[i];
    }
}
 
void aes(uint8_t *in, uint8_t *out, uint8_t *skey)
{
    //... Initialize ...
    unsigned short round = 0;
 
    t_state state;
 
    state[0] = word(in[0], in[1], in[2], in[3]);
    state[1] = word(in[4], in[5], in[6], in[7]);
    state[2] = word(in[8], in[9], in[10], in[11]);
    state[3] = word(in[12], in[13], in[14], in[15]);
 
    printf("IN:  "); printstate(state);
 
    uint32_t expKey[11 * 4];
 
    expandKey(skey, expKey);
 
    for (int i = 0; i < 11; i++) {
        printf("K%02d: ", i);
        hexprintws(expKey + 4 * i, 4);
    }
 
    addRoundKey(state, expKey, 0);
    printf("ARK: "); printstate(state);
 
    for(int i = 1 ; i < 10 ; i++){
        subBytes(state);
        shiftRows(state);
        mixColumns(state);
        addRoundKey(state, expKey, i);
    }
    
    subBytes(state);
    shiftRows(state);
    addRoundKey(state, expKey, 10);
 
    for (int i = 0; i < 16; i++) {
        if (i < 4) out[i] = wbyte(state[0], i % 4);
        else if (i < 8) out[i] = wbyte(state[1], i % 4);
        else if (i < 12) out[i] = wbyte(state[2], i % 4);
        else out[i] = wbyte(state[3], i % 4);
    }
}
 
//****************************
// MAIN function: AES testing
//****************************
int main(int argc, char* argv[])
{
    int test_failed = 0;
    // test subBytes
    printf("Testing subBytes\n");
    {
        t_state state = { 0x01234567, 0x89abcdef, 0xdeadbeef, 0x00112233 };
        t_state res_state = { 0x7c266e85, 0xa762bddf, 0x1d95aedf, 0x638293c3 };
        subBytes(state);
        printf("0x%08x, 0x%08x, 0x%08x, 0x%08x\n", state[0], state[1], state[2], state[3]);
        for (int i = 0; i < 4; i++) {
            if (state[i] != res_state[i]) { printf("Mismatch at state[%d]!\n", i); test_failed = 1; }
        }
    }
    // test shiftRows
    printf("Testing shiftRows\n");
 
    {
        t_state state = { 0x01234567, 0x89abcdef, 0xdeadbeef, 0x00112233 };
        t_state res_state = { 0x00adcd67, 0x0111beef, 0x892322ef, 0xdeab4533 };
        shiftRows(state);
        printf("0x%08x, 0x%08x, 0x%08x, 0x%08x\n", state[0], state[1], state[2], state[3]);
        for (int i = 0; i < 4; i++) {
            if (state[i] != res_state[i]) { printf("Mismatch at state[%d]!\n", i); test_failed = 1; }
        }
    }
    // test mixColumns
    printf("Testing mixColumns\n");
    {
        t_state state = { 0x01234567, 0x89abcdef, 0xdeadbeef, 0x00112233 };
        t_state res_state = { 0xcd678923, 0x45ef01ab, 0x9e69ba6f, 0x66334411 };
        mixColumns(state);
        printf("0x%08x, 0x%08x, 0x%08x, 0x%08x\n", state[0], state[1], state[2], state[3]);
        for (int i = 0; i < 4; i++) {
            if (state[i] != res_state[i]) { printf("Mismatch at state[%d]!\n", i); test_failed = 1; }
        }
    }
    // test xtime
    printf("Testing xtime\n");
    {
        uint8_t res[256] = { 0x00, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0e, 0x10, 0x12,
            0x14, 0x16, 0x18, 0x1a, 0x1c, 0x1e, 0x20, 0x22, 0x24, 0x26,
            0x28, 0x2a, 0x2c, 0x2e, 0x30, 0x32, 0x34, 0x36, 0x38, 0x3a,
            0x3c, 0x3e, 0x40, 0x42, 0x44, 0x46, 0x48, 0x4a, 0x4c, 0x4e,
            0x50, 0x52, 0x54, 0x56, 0x58, 0x5a, 0x5c, 0x5e, 0x60, 0x62,
            0x64, 0x66, 0x68, 0x6a, 0x6c, 0x6e, 0x70, 0x72, 0x74, 0x76,
            0x78, 0x7a, 0x7c, 0x7e, 0x80, 0x82, 0x84, 0x86, 0x88, 0x8a,
            0x8c, 0x8e, 0x90, 0x92, 0x94, 0x96, 0x98, 0x9a, 0x9c, 0x9e,
            0xa0, 0xa2, 0xa4, 0xa6, 0xa8, 0xaa, 0xac, 0xae, 0xb0, 0xb2,
            0xb4, 0xb6, 0xb8, 0xba, 0xbc, 0xbe, 0xc0, 0xc2, 0xc4, 0xc6,
            0xc8, 0xca, 0xcc, 0xce, 0xd0, 0xd2, 0xd4, 0xd6, 0xd8, 0xda,
            0xdc, 0xde, 0xe0, 0xe2, 0xe4, 0xe6, 0xe8, 0xea, 0xec, 0xee,
            0xf0, 0xf2, 0xf4, 0xf6, 0xf8, 0xfa, 0xfc, 0xfe, 0x1b, 0x19,
            0x1f, 0x1d, 0x13, 0x11, 0x17, 0x15, 0x0b, 0x09, 0x0f, 0x0d,
            0x03, 0x01, 0x07, 0x05, 0x3b, 0x39, 0x3f, 0x3d, 0x33, 0x31,
            0x37, 0x35, 0x2b, 0x29, 0x2f, 0x2d, 0x23, 0x21, 0x27, 0x25,
            0x5b, 0x59, 0x5f, 0x5d, 0x53, 0x51, 0x57, 0x55, 0x4b, 0x49,
            0x4f, 0x4d, 0x43, 0x41, 0x47, 0x45, 0x7b, 0x79, 0x7f, 0x7d,
            0x73, 0x71, 0x77, 0x75, 0x6b, 0x69, 0x6f, 0x6d, 0x63, 0x61,
            0x67, 0x65, 0x9b, 0x99, 0x9f, 0x9d, 0x93, 0x91, 0x97, 0x95,
            0x8b, 0x89, 0x8f, 0x8d, 0x83, 0x81, 0x87, 0x85, 0xbb, 0xb9,
            0xbf, 0xbd, 0xb3, 0xb1, 0xb7, 0xb5, 0xab, 0xa9, 0xaf, 0xad,
            0xa3, 0xa1, 0xa7, 0xa5, 0xdb, 0xd9, 0xdf, 0xdd, 0xd3, 0xd1,
            0xd7, 0xd5, 0xcb, 0xc9, 0xcf, 0xcd, 0xc3, 0xc1, 0xc7, 0xc5,
            0xfb, 0xf9, 0xff, 0xfd, 0xf3, 0xf1, 0xf7, 0xf5, 0xeb, 0xe9,
            0xef, 0xed, 0xe3, 0xe1, 0xe7, 0xe5 };
        for (uint16_t i = 0; i < 256; i++) {
            //printf("0x%02hhx,   ", xtime((uint8_t)i));
            if (xtime((uint8_t)i) != res[i]) {
                printf("\nMismatch at xtime(0x%02x)! Comparison interrupted.\n", i);  test_failed = 1;
                break;
            }
        }
        puts("");
    }
 
    // test key expansion
    printf("Testing expandKey\n");
    {
        uint8_t key_b[16] = { 0xef, 0xbe, 0xad, 0xde, 0xbe, 0xba, 0xfe, 0xca, 0x0D, 0xF0, 0xAD, 0xBA, 0x00, 0x11, 0x22, 0x33 };
        uint32_t key_w[44] = { 0 /*, ...*/ };
        uint32_t res_key_w[44] = {
            0xdeadbeef, 0xcafebabe, 0xbaadf00d, 0x33221100,
            0xbd6e2d6c, 0x779097d2, 0xcd3d67df, 0xfe1f76df,
            0x23d5ed56, 0x54457a84, 0x99781d5b, 0x67676b84,
            0x7c50682d, 0x281512a9, 0xb16d0ff2, 0xd60a6476,
            0x44a60f66, 0x6cb31dcf, 0xddde123d, 0x0bd4764b,
            0xf78d474e, 0x9b3e5a81, 0x46e048bc, 0x4d343ef7,
            0x9f6e5fdc, 0x0450055d, 0x42b04de1, 0x0f847316,
            0xd8180013, 0xdc48054e, 0x9ef848af, 0x917c3bb9,
            0x8e991071, 0x52d1153f, 0xcc295d90, 0x5d556629,
            0x2bd5ec59, 0x7904f966, 0xb52da4f6, 0xe878c2df,
            0xb54e504a, 0xcc4aa92c, 0x79670dda, 0x911fcf05,
        };
        expandKey(key_b, key_w);
        for (int i = 0; i < 44; i++) {
            printf("0x%08x, ", key_w[i]);
            if (i % 4 == 3) printf("\n");
        }
 
        for (int i = 0; i < 44; i++) {
            if (key_w[i] != res_key_w[i]) {
                printf("Mismatch at key_w[%d]! Comparison interrupted.\n", i);  test_failed = 1;
                break;
            }
        }
        printf("Testing addRoundKey\n");
        // test  AddRoundKey (last round)
        t_state state = { 0x01234567, 0x89abcdef, 0xdeadbeef, 0x00112233 };
        t_state res_state = { 0xb46d152d, 0x45e164c3, 0xa7cab335, 0x910eed36 };
        addRoundKey(state, key_w, 10);
        printf("0x%08x, 0x%08x, 0x%08x, 0x%08x\n", state[0], state[1], state[2], state[3]);
        for (int i = 0; i < 4; i++) {
            if (state[i] != res_state[i]) { printf("Mismatch at state[%d]!\n", i); }
        }
 
    }
    
    time_t start, end;
    time(&start);
    // test aes encryption
    printf("Testing aes\n");
    {
        uint8_t key[16] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
        uint8_t in[16] = { 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89 };
        uint8_t out[16] = { 0, /*...*/ };
        uint8_t res_out[16] = { 0xa3, 0x3a, 0xca, 0x68, 0x72, 0xa2, 0x27, 0x74, 0xbf, 0x99, 0xf3, 0x71, 0xaa, 0x99, 0xd2, 0x5a };
 
        printf("Key: ");
        hexprint16(key);
        puts("");
        printf("In:  ");
        hexprint16(in);
        puts("");
 
        aes(in, out, key);
 
        printf("Out: ");
        hexprint16(out);
        puts("");
 
        for (int i = 0; i < 16; i++) {
            if (out[i] != res_out[i]) { printf("Mismatch at out[%d]!\n", i); test_failed = 1; }
        }
    }
    time(&end);
    double time_taken = double(end-start);
    
    printf("%f\n",time_taken);
    
    if (test_failed) {
        printf("|*********** SOME TEST(S) FAILED ***********|\n");
        printf("Please fix me!\n");
    }
    else {
        printf("============== All tests OK! ===============\n");
    }
    return  test_failed;
}
 
