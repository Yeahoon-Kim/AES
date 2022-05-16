#ifndef __AES_H__
#define __AES_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

//128-bit block
typedef uint8_t AES_STATE_t[16];

//128-bit masterkey
typedef uint8_t AES128_KEY_t[16];
//192-bit masterkey
typedef uint8_t AES192_KEY_t[24];
//256-bit masterkey
typedef uint8_t AES256_KEY_t[32];


//구현함수 for AES-128
void AES128_enc(AES_STATE_t C, AES_STATE_t P, AES128_KEY_t K128);
void AES128_dec(AES_STATE_t P, AES_STATE_t C, AES128_KEY_t K128);
//구현함수 for AES-192
void AES192_enc(AES_STATE_t C, AES_STATE_t P, AES192_KEY_t K128);
void AES192_dec(AES_STATE_t P, AES_STATE_t C, AES192_KEY_t K128);
//구현함수 for AES-256
void AES256_enc(AES_STATE_t C, AES_STATE_t P, AES256_KEY_t K256);
void AES256_dec(AES_STATE_t P, AES_STATE_t C, AES256_KEY_t K256);

///////////TEST Vectors
typedef struct {
	AES_STATE_t		P;
	AES_STATE_t		C;
	AES128_KEY_t	K128;
}AES128_TV_t;

typedef struct {
	AES_STATE_t		P;
	AES_STATE_t		C;
	AES192_KEY_t	K192;
}AES192_TV_t;

typedef struct {
	AES_STATE_t		P;
	AES_STATE_t		C;
	AES256_KEY_t	K256;
}AES256_TV_t;




static AES128_TV_t aes128_tvs[] = {
	{//0
		{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}, //P
		{0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a}, //C
		{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}, //K128
	},
	{//1
		{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, //P
		{0x66, 0xE9, 0x4B, 0xD4, 0xEF, 0x8A, 0x2C, 0x3B, 0x88, 0x4C, 0xFA, 0x59, 0xCA, 0x34, 0x2B, 0x2E}, //C
		{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, //K128
	},
	{//2
		{0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a}, //P
		{0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97}, //C
		{0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c}, //K128
	},
	{//3
		{0x0f, 0xdc, 0x44, 0xb2, 0x05, 0x43, 0xa0, 0x20, 0xef, 0xcb, 0xf2, 0xde, 0xc5, 0xc8, 0xa0, 0x90}, //P
		{0x39, 0xca, 0xa4, 0x6e, 0x3d, 0x77, 0x57, 0x83, 0x41, 0xa9, 0xb4, 0x68, 0xc3, 0xd8, 0x3c, 0x14}, //C
		{0x0c, 0x99, 0x69, 0xb5, 0x63, 0x62, 0xd4, 0x3b, 0x5c, 0x77, 0xa3, 0x16, 0xe3, 0x2d, 0xe4, 0xc1}, //K128
	},
	{//4
		{0x0f, 0xdc, 0x44, 0xb2, 0x05, 0x43, 0xa0, 0x20, 0xef, 0xcb, 0xf2, 0xde, 0xc5, 0xc8, 0xa0, 0x90}, //P
		{0x39, 0xca, 0xa4, 0x6e, 0x3d, 0x77, 0x57, 0x83, 0x41, 0xa9, 0xb4, 0x68, 0xc3, 0xd8, 0x3c, 0x14}, //C
		{0x0c, 0x99, 0x69, 0xb5, 0x63, 0x62, 0xd4, 0x3b, 0x5c, 0x77, 0xa3, 0x16, 0xe3, 0x2d, 0xe4, 0xc1}, //K128
	},
	{//5
		{0xec, 0xd7, 0xfb, 0x75, 0x2e, 0x21, 0x74, 0xe6, 0x00, 0xd6, 0xfb, 0x0c, 0xf5, 0x5c, 0xfc, 0xb7}, //P
		{0x3e, 0xb2, 0xcb, 0x1b, 0x05, 0xad, 0x6d, 0x13, 0x63, 0x2b, 0xa1, 0x62, 0x02, 0xaa, 0x90, 0x65}, //C
		{0xff, 0x7e, 0x48, 0xb6, 0xf7, 0x2e, 0xb4, 0xaf, 0x93, 0x14, 0x53, 0x37, 0xf2, 0x98, 0x76, 0x0d}, //K128
	},
	{//6
		{0xba, 0x4e, 0x20, 0x6e, 0x6f, 0xa0, 0xd6, 0x8e, 0xa9, 0x5c, 0x69, 0xdd, 0x21, 0x19, 0x73, 0xba}, //P
		{0xf7, 0xf5, 0xf2, 0xe9, 0x01, 0xc7, 0x0b, 0x52, 0xe4, 0x59, 0x40, 0x32, 0xe8, 0xe0, 0xd0, 0x6f}, //C
		{0x7b, 0x14, 0xb3, 0xe9, 0x73, 0x2f, 0x2e, 0xfb, 0xd6, 0x41, 0x20, 0xc8, 0x55, 0x8a, 0x42, 0x6d}, //K128
	},
	{//7
		{0xc0, 0x26, 0xaa, 0x76, 0x95, 0x92, 0x28, 0x46, 0x44, 0x57, 0x72, 0xb7, 0xd7, 0x09, 0x74, 0x53}, //P
		{0x9c, 0xc0, 0xca, 0xd3, 0x9a, 0xce, 0xa7, 0x45, 0x96, 0x85, 0xd5, 0x27, 0x1b, 0xc8, 0xe8, 0x5a}, //C
		{0xeb, 0x3c, 0xd2, 0x91, 0xd0, 0xb0, 0x90, 0x26, 0x65, 0x90, 0xc7, 0x77, 0xb8, 0x28, 0x64, 0x5e}, //K128
	},
	{//8
		{0x6e, 0xcf, 0x11, 0x02, 0xbb, 0xae, 0x31, 0xcb, 0x24, 0x7c, 0x95, 0xe3, 0x68, 0xe4, 0x8d, 0xde}, //P
		{0xce, 0x9c, 0x28, 0xdf, 0x4e, 0x21, 0x16, 0xfc, 0x2c, 0x7a, 0xef, 0x95, 0x18, 0xa4, 0x15, 0x04}, //C
		{0x7f, 0xa5, 0x24, 0xb6, 0xbc, 0xe8, 0xdf, 0x2d, 0x33, 0xde, 0x79, 0xc3, 0x81, 0x3b, 0x88, 0x87}, //K128
	},
	{//9
		{0x55, 0xdf, 0x3e, 0x1f, 0x70, 0x3b, 0x14, 0x64, 0x34, 0x04, 0x20, 0x74, 0xe3, 0x0f, 0x6e, 0xaa}, //P
		{0x47, 0x0f, 0x81, 0x4b, 0x65, 0x27, 0xcf, 0x8d, 0x37, 0x8b, 0x41, 0x82, 0xb2, 0x8c, 0x35, 0xf4}, //C
		{0xa4, 0xf0, 0x72, 0xd2, 0x4f, 0xbf, 0x7d, 0xcc, 0xf7, 0x10, 0xc8, 0xe3, 0xd3, 0x07, 0xbf, 0x33}, //K128
	},
};


static AES192_TV_t aes192_tvs[] = {
	{//0
		{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}, //P
		{0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91}, //C
		{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17}												  //K192
	},
	{//1
		{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, //P
		{0xAA, 0xE0, 0x69, 0x92, 0xAC, 0xBF, 0x52, 0xA3, 0xE8, 0xF4, 0xA9, 0x6E, 0xC9, 0x30, 0x0B, 0xD7}, //C
		{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}												  //K192
	},
	{//2
		{0xbe, 0x1f, 0xa6, 0xeb, 0x5f, 0x18, 0xd1, 0x12, 0xfb, 0x5d, 0xca, 0xe5, 0x89, 0x3b, 0xb8, 0x24}, //P
		{0xe0, 0x8e, 0x9e, 0x17, 0x54, 0x8b, 0x50, 0x30, 0xb7, 0x39, 0x45, 0x7b, 0x0b, 0xa8, 0xad, 0xd2}, //C
		{0x87, 0x78, 0x5a, 0xaf, 0x57, 0x0f, 0x2a, 0x2d, 0xf9, 0x4f, 0xa9, 0xa9, 0xa8, 0x14, 0x95, 0xcc,
		 0x69, 0xa3, 0x6c, 0x8c, 0x50, 0x7b, 0xf5, 0x1d},												  //K192
	},
	{//3
		{0xdb, 0xdf, 0xc5, 0x31, 0x29, 0x7f, 0x2c, 0xea, 0x6b, 0x82, 0x60, 0x91, 0x93, 0x19, 0x0e, 0x30}, //P
		{0xf9, 0xbe, 0x49, 0x01, 0xde, 0x01, 0xb1, 0xaf, 0xe1, 0x44, 0x20, 0x9e, 0x54, 0x7c, 0x92, 0xd7}, //C
		{0xea, 0xc6, 0xf2, 0x96, 0x2a, 0x45, 0xc7, 0x55, 0xea, 0x9a, 0xc7, 0x9f, 0xda, 0xda, 0xd4, 0x3f,
		 0x35, 0x28, 0x39, 0x1d, 0x2f, 0x42, 0xb7, 0xb0},												  //K192
	},
	{//4
		{0x74, 0xac, 0x09, 0x29, 0x53, 0x37, 0xc3, 0x8f, 0x3f, 0x28, 0xa8, 0x59, 0x44, 0xdf, 0xba, 0xc6}, //P
		{0x65, 0x5f, 0x32, 0xb4, 0x2b, 0x84, 0xb2, 0x24, 0xf1, 0x33, 0x7d, 0x7c, 0x46, 0x01, 0x53, 0x9b}, //C
		{0xa7, 0x62, 0x3a, 0x46, 0x4a, 0x39, 0x09, 0x7d, 0xc9, 0xbf, 0x90, 0x95, 0xe8, 0x0f, 0x76, 0x4b,
		 0x3a, 0x30, 0x90, 0xac, 0x1e, 0x5b, 0x63, 0xce},												  //K192
	},
	{//5
		{0xbb, 0x5f, 0xe4, 0xc6, 0xc9, 0x81, 0x22, 0x55, 0x23, 0x80, 0xaa, 0x66, 0x5d, 0x0f, 0xcb, 0x69}, //P
		{0xc4, 0x72, 0x86, 0x1c, 0xa4, 0x27, 0xbc, 0x12, 0x5a, 0x0d, 0xea, 0x52, 0xac, 0xac, 0xef, 0x22}, //C
		{0x41, 0x3d, 0x98, 0xdc, 0xb9, 0x43, 0x82, 0xb2, 0x2e, 0x6c, 0x91, 0x84, 0x8c, 0xa9, 0x01, 0xa8,
		 0xbd, 0x49, 0xbd, 0x6b, 0xb7, 0x30, 0x47, 0xee},												  //K192
	},
	{//6
		{0xae, 0x78, 0x22, 0x1e, 0x1f, 0x9c, 0xa2, 0x93, 0x6a, 0x59, 0xd4, 0x8e, 0xbf, 0x14, 0xb8, 0x82}, //P
		{0x74, 0xb2, 0x12, 0x46, 0x1f, 0x8a, 0x82, 0x68, 0x26, 0x94, 0x71, 0xf6, 0x13, 0x6f, 0xc4, 0x6e}, //C
		{0xeb, 0x61, 0x94, 0x7f, 0x0e, 0x98, 0xad, 0xb7, 0xc5, 0xce, 0xcf, 0xba, 0xb4, 0x29, 0xfd, 0x37,
		 0x53, 0x60, 0xda, 0x95, 0xff, 0xe9, 0xdf, 0x51},												  //K192
	},
	{//7
		{0x2f, 0x49, 0xfa, 0x0a, 0x70, 0x6a, 0x4e, 0x69, 0xa9, 0x1d, 0x65, 0x3c, 0x42, 0x78, 0xe8, 0x18}, //P
		{0x9d, 0xd6, 0x73, 0xa4, 0xa0, 0xf8, 0x90, 0x2f, 0xec, 0x1a, 0x3f, 0xfc, 0x8a, 0x0c, 0x50, 0x6c}, //C
		{0x18, 0xe3, 0x39, 0x7b, 0xf6, 0xb9, 0x1a, 0xac, 0x08, 0xdf, 0x8c, 0x13, 0xbd, 0x2e, 0x16, 0xad,
		 0x2e, 0x12, 0x60, 0x07, 0x94, 0xb3, 0x1c, 0x5f},												  //K192
	},
	{//8
		{0x8a, 0xaa, 0xcf, 0xc2, 0x79, 0xa7, 0xc6, 0xfd, 0xad, 0x69, 0x99, 0x4c, 0xc6, 0x46, 0xdd, 0xad}, //P
		{0xb9, 0x90, 0x90, 0x5b, 0x96, 0xea, 0x98, 0x3e, 0xe9, 0x00, 0xc9, 0xa3, 0x10, 0x3e, 0x67, 0x82}, //C
		{0x43, 0x3e, 0x8a, 0x3a, 0xb9, 0x45, 0x2a, 0x90, 0xef, 0x7c, 0xdb, 0xa6, 0x7e, 0xa0, 0x96, 0x16,
		 0x15, 0x47, 0xb5, 0x1f, 0xf4, 0xfb, 0x75, 0x04},												  //K192
	},
	{//9
		{0x01, 0x3d, 0xe3, 0x39, 0x97, 0x43, 0x6b, 0x24, 0x90, 0x36, 0xa8, 0x4a, 0x82, 0xd4, 0xc3, 0x4f}, //P
		{0x60, 0x32, 0xc3, 0xc7, 0x83, 0x3f, 0x6d, 0x8d, 0xe2, 0x9e, 0xb5, 0xaa, 0x73, 0x55, 0xaa, 0x05}, //C
		{0x7e, 0xf6, 0x46, 0x82, 0x7f, 0x08, 0x3d, 0x0b, 0xd3, 0xa8, 0x16, 0x9a, 0xab, 0xbf, 0x3a, 0x31,
		0x2d, 0xb4, 0xb0, 0x81, 0xbe, 0x5b, 0x0c, 0xc7},												  //K192
	},
};

static AES256_TV_t aes256_tvs[] = {
	{//0
		{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}, //P
		{0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89}, //C
		{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f }  //K256
	},
	{//1
		{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, //P
		{0xDC, 0x95, 0xC0, 0x78, 0xA2, 0x40, 0x89, 0x89, 0xAD, 0x48, 0xA2, 0x14, 0x92, 0x84, 0x20, 0x87}, //C
		{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}  //K256
	},
	{//2
		{0x77, 0xf1, 0x7a, 0xd0, 0xbc, 0x20, 0x34, 0xe7, 0x42, 0xe7, 0xde, 0xdf, 0x45, 0x09, 0x21, 0x66}, //P
		{0x0a, 0x43, 0xd1, 0xcb, 0x74, 0xd7, 0x65, 0xd9, 0xe2, 0xd3, 0xe2, 0xbe, 0xb4, 0x3e, 0xe1, 0x98}, //C
		{0x88, 0xa3, 0x56, 0x41, 0xfe, 0x1c, 0x36, 0x53, 0xe5, 0xa7, 0x68, 0xba, 0x09, 0xb9, 0x2a, 0x05,
		0xe6, 0x15, 0x9c, 0xeb, 0x47, 0x96, 0xbb, 0x7b, 0xb0, 0x34, 0xae, 0x7c, 0xfa, 0x1e, 0xd8, 0x65},  //K256
	},
	{//3
		{0x76, 0x91, 0xf8, 0x8b, 0xf1, 0xb3, 0x6a, 0x16, 0x42, 0xc2, 0x7c, 0xb1, 0xc1, 0x08, 0xee, 0xb3}, //P
		{0x01, 0x1d, 0xc3, 0x4c, 0x58, 0xea, 0x6d, 0x4d, 0x38, 0x04, 0x73, 0xe8, 0xce, 0x96, 0x2f, 0x58}, //C
		{0x0a, 0x1e, 0x13, 0xac, 0xb8, 0x5c, 0x1d, 0x79, 0xc3, 0x22, 0xce, 0xd9, 0x67, 0xa2, 0xc3, 0x00,
		0x71, 0xd9, 0x13, 0x66, 0xe5, 0x45, 0xb9, 0xf2, 0x1b, 0x28, 0x29, 0x73, 0xb5, 0xa6, 0x5e, 0x93},  //K256
	},
	{//4
		{0x0a, 0xd4, 0x77, 0xc9, 0x67, 0x3d, 0x7a, 0x8e, 0x48, 0x12, 0xcd, 0xc3, 0x2f, 0x3a, 0xba, 0x6e}, //P
		{0x57, 0x3f, 0xec, 0xdf, 0x3a, 0x55, 0x2f, 0x43, 0x8e, 0xd0, 0x8d, 0x28, 0xb0, 0x36, 0x66, 0x89}, //C
		{0xd5, 0x41, 0xdf, 0x94, 0x41, 0x3e, 0xb8, 0x81, 0xaa, 0x39, 0x6e, 0x20, 0xb6, 0xda, 0x16, 0x2b,
		0x2f, 0xb7, 0xab, 0x5e, 0xce, 0xc7, 0xd5, 0x43, 0xbb, 0xec, 0x68, 0xf5, 0x94, 0x50, 0xf1, 0x73},  //K256
	},
	{//5
		{0xf5, 0x89, 0x63, 0x9c, 0x57, 0xa8, 0x22, 0xce, 0xf6, 0x8a, 0xd5, 0xae, 0x1f, 0x60, 0x21, 0xd3}, //P
		{0x41, 0x69, 0x3d, 0x66, 0xf8, 0xb4, 0xe6, 0x62, 0x62, 0x7f, 0x4c, 0x46, 0xc5, 0xe2, 0xa4, 0xf7}, //C
		{0x89, 0x89, 0x90, 0x43, 0x12, 0xf9, 0xbd, 0xfc, 0xb6, 0x47, 0x8b, 0xeb, 0x2b, 0xec, 0x56, 0x13,
		0xb0, 0x4b, 0xc4, 0xbc, 0x3d, 0x3b, 0x65, 0x10, 0xf0, 0xe3, 0x3a, 0xf6, 0x36, 0x47, 0x67, 0x82},  //K256
	},
	{//6
		{0x99, 0xb1, 0xc9, 0x23, 0x0f, 0x00, 0x57, 0x26, 0xa8, 0x80, 0x3b, 0x70, 0x8d, 0xeb, 0x59, 0x87}, //P
		{0xf7, 0x62, 0x5b, 0xfb, 0xfb, 0x76, 0xee, 0xa6, 0xdd, 0xc5, 0x64, 0x38, 0x76, 0x88, 0x25, 0xe4}, //C
		{0xce, 0xeb, 0xa0, 0x6c, 0xee, 0xbc, 0x09, 0xf2, 0x8a, 0x36, 0x93, 0x6e, 0x39, 0xaf, 0x2a, 0x2a,
		0x16, 0xc2, 0x3c, 0x5d, 0xa7, 0x3a, 0xfb, 0x5c, 0x37, 0x33, 0xb6, 0x13, 0x44, 0x89, 0xe5, 0x23},  //K256
	},
	{//7
		{0xd3, 0x29, 0x12, 0x6a, 0xde, 0x92, 0xbe, 0x25, 0x38, 0x2a, 0xfd, 0x56, 0xa6, 0x47, 0x54, 0x2f}, //P
		{0x9c, 0xe9, 0x9e, 0x5f, 0x0d, 0x9a, 0x4b, 0x82, 0xbe, 0xb7, 0x07, 0x9f, 0xd4, 0x0e, 0x70, 0xa6}, //C
		{0x81, 0x5e, 0x52, 0x4d, 0x81, 0x52, 0x85, 0xdd, 0xda, 0x98, 0x93, 0xab, 0x03, 0xdb, 0x78, 0x96,
		0x77, 0xfb, 0x97, 0x2c, 0x33, 0x03, 0x63, 0x17, 0x61, 0x56, 0x70, 0x9c, 0xf2, 0xa3, 0x12, 0x03},  //K256
	},
	{//8
		{0x1e, 0xa2, 0xe3, 0xa3, 0x57, 0xbb, 0x91, 0x30, 0x84, 0x70, 0x11, 0x62, 0x7c, 0x54, 0x93, 0xe6}, //P
		{0x97, 0x78, 0x6f, 0x1c, 0xd6, 0x9e, 0xd6, 0x5c, 0x07, 0xc7, 0x2d, 0x23, 0x63, 0x7b, 0x89, 0x1d}, //C
		{0x71, 0x14, 0xfd, 0x06, 0x17, 0x98, 0x11, 0x68, 0xea, 0x71, 0x27, 0xbd, 0xaf, 0x26, 0x0d, 0xc1,
		0x1c, 0xc4, 0x1a, 0x4c, 0x66, 0x29, 0x0a, 0x7b, 0xbf, 0x6e, 0x7a, 0xeb, 0x93, 0x48, 0x18, 0x11},  //K256
	},
	{//9
		{0x58, 0x38, 0x90, 0x96, 0x90, 0x66, 0xbb, 0x61, 0x58, 0x0a, 0xe4, 0xca, 0x1e, 0x54, 0x58, 0xbd},
		{0xe4, 0x48, 0x04, 0xba, 0x79, 0x45, 0x34, 0x23, 0x69, 0x9a, 0xfc, 0xb4, 0x4c, 0x42, 0x8c, 0x07},
		{0xed, 0x57, 0xdb, 0x47, 0x23, 0x09, 0xc8, 0x09, 0xab, 0xbd, 0xe9, 0xab, 0xe3, 0x90, 0xf0, 0x0e, 
		0xb1, 0xf4, 0x50, 0xb7, 0x03, 0xbd, 0xfd, 0x40, 0xa8, 0x77, 0x63, 0x09, 0x3e, 0x69, 0xbc, 0xff},
	},
};

#define NUM_AES128_TVS (sizeof(aes128_tvs)/sizeof(AES128_TV_t))
#define NUM_AES192_TVS (sizeof(aes192_tvs)/sizeof(AES192_TV_t))
#define NUM_AES256_TVS (sizeof(aes256_tvs)/sizeof(AES256_TV_t))




#ifdef __cplusplus
}
#endif /*extern "C"*/
#endif /*__AES_H__*/