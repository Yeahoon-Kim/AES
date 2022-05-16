#include "aes.h"

//학번_이름
char SUBMISSION_INFO[256] = "0000000000_000";


//관련 데이터 타입 정의 내역
//128-bit block
//typedef uint8_t AES_STATE_t[16];
//128-bit masterkey
//typedef uint8_t AES128_KEY_t[16];

AES128_KEY_t roundedKey[15];

typedef uint8_t AES_KEY_WORD[4];

// Substitution Box
const uint8_t SBox[16][16] = {
	{0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
	{0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
	{0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
	{0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
	{0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
	{0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
	{0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
	{0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
	{0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
	{0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
	{0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
	{0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
	{0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
	{0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
	{0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
	{0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}
};

// Substitution Inverse Box
const uint8_t InvSBox[16][16] = {
	{0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb},
	{0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb},
	{0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e},
	{0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25},
	{0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92},
	{0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84},
	{0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06},
	{0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b},
	{0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73},
	{0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e},
	{0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b},
	{0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4},
	{0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f},
	{0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef},
	{0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61},
	{0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d}
};

// mixColumn Box
const uint8_t mixColumnBox[4][4] = {
	{0x02, 0x03, 0x01, 0x01},
	{0x01, 0x02, 0x03, 0x01},
	{0x01, 0x01, 0x02, 0x03},
	{0x03, 0x01, 0x01, 0x02}
};

// mixColumn Inverse Box
const uint8_t InvMixColumnBox[4][4] = {
	{0x0e, 0x0b, 0x0d, 0x09},
	{0x09, 0x0e, 0x0b, 0x0d},
	{0x0d, 0x09, 0x0e, 0x0b},
	{0x0b, 0x0d, 0x09, 0x0e}
};

// R-Constant
const uint32_t RConstant[14] = {
	0x01000000, 0x02000000, 0x04000000, 0x08000000,
	0x10000000, 0x20000000, 0x40000000, 0x80000000,
	0x1b000000, 0x36000000, 0x6c000000, 0xd8000000,
	0xab000000, 0x4d000000
};

// RotWord
uint32_t RotWord(uint32_t Key)
{
	uint32_t temp = (Key >> 24) & 0xff;
	temp |= Key << 8;
	return temp;
}

// RotWord Inverse
uint32_t InvRotWord(uint32_t Key)
{
	uint32_t temp = (Key & 0xff) << 24;
	temp |= (Key >> 8) & 0x00ffffff;
	return temp;
}

// SubWord
uint32_t SubWord(uint32_t Key)
{
	AES_KEY_WORD block;
	int i;
	uint32_t temp = 0;

	for (i = 0; i < 4; i++)
	{
		block[3 - i] = Key & 0xff;
		Key >>= 8;
	}

	for (i = 0; i < 4; i++)
	{
		temp |= SBox[(block[i] >> 4) & 0x0f][block[i] & 0x0f];
		if (i == 3) break;
		temp <<= 8;
	}

	return temp;
}

// SubWord Inverse
uint32_t InvSubWord(uint32_t Key)
{
	AES_KEY_WORD block;
	int i;
	uint32_t temp = 0;

	for (i = 0; i < 4; i++)
	{
		block[3 - i] = Key & 0xff;
		Key >>= 8;
	}

	for (i = 0; i < 4; i++)
	{
		temp |= InvSBox[(block[i] >> 4) & 0x0f][block[i] & 0x0f];
		if (i == 3) break;
		temp <<= 8;
	}

	return temp;
}

/*
* SubBytes 함수
* 입력값 : char[16] 배열(평문)의 주소 -> 조작 가능
* 출력값 : 입력값의 직접 조작
*/
void SubBytes(AES_STATE_t P)
{
	for (char i = 0; i < 16; i++)
	{
		P[i] = SBox[(P[i] >> 4) & 0x0f][P[i] & 0x0f];
	}
}

/*
* InvSubBytes 함수
* 입력값 : char[16] 배열(평문)의 주소 -> 조작 가능
* 출력값 : 입력값의 직접 조작
*/
void InvSubBytes(AES_STATE_t P)
{
	for (char i = 0; i < 16; i++)
	{
		P[i] = InvSBox[(P[i] >> 4) & 0x0f][P[i] & 0x0f];
	}
}

/*
* ShiftRows 함수
* 입력값 : char[16] 배열(평문)의 주소 -> 조작 가능
* 출력값 : 입력값의 직접 조작
*/
void ShiftRows(AES_STATE_t P)
{
	AES_STATE_t temp;
	char i;

	for (i = 0; i < 16; i++)
	{
		temp[i] = P[i];
	}

	for (i = 0; i < 4; i++)
	{
		P[(1 + 4 * i) % 16] = temp[(1 + 4 * (i + 1)) % 16];
		P[(2 + 4 * i) % 16] = temp[(2 + 4 * (i + 2)) % 16];
		P[(3 + 4 * i) % 16] = temp[(3 + 4 * (i + 3)) % 16];
	}
}

/*
* InvShiftRows 함수
* 입력값 : char[16] 배열(평문)의 주소 -> 조작 가능
* 출력값 : 입력값의 직접 조작
*/
void InvShiftRows(AES_STATE_t P)
{
	AES_STATE_t temp;
	char i;

	for (i = 0; i < 16; i++)
	{
		temp[i] = P[i];
	}

	for (i = 0; i < 4; i++)
	{
		P[(1 + 4 * i) % 16] = temp[(1 + 4 * (i + 3)) % 16];
		P[(2 + 4 * i) % 16] = temp[(2 + 4 * (i + 2)) % 16];
		P[(3 + 4 * i) % 16] = temp[(3 + 4 * (i + 1)) % 16];
	}
}

/*
* AddRoundKey 함수
* 입력값 : char[16] 배열(평문, 라운드키)의 주소 -> 조작 가능
* 출력값 : 입력값의 직접 조작
*/
void AddRoundKey(AES_STATE_t P, AES_STATE_t roundKey)
{
	for (int i = 0; i < 16; i++)
	{
		P[i] ^= roundKey[i];
	}
}

uint8_t multiplication(uint8_t B, uint8_t mix)
{
	// temp : 결과값
	uint8_t temp = 0, temp2, flag;
	// B * 0x01
	if (mix & 0x01)
		temp ^= B;
	flag = B & 0x80;
	temp2 = B;

	// B * 0x02
	temp2 <<= 1;
	if (flag)	
		temp2 ^= 0x1b;
	if(mix & 0x02)
		temp ^= temp2;
	flag = temp2 & 0x80;

	// MixColumn이 빨리 끝나도록 하는 용도
	if (!(mix & 0x0c)) return temp;

	// B * 0x04
	temp2 <<= 1;
	if (flag)
		temp2 ^= 0x1b;
	if (mix & 0x04)
		temp ^= temp2;
	flag = temp2 & 0x80;

	// B * 0x08
	temp2 <<= 1;
	if (flag)
		temp2 ^= 0x1b;
	if (mix & 0x08)
		temp ^= temp2;

	return temp;
}

/*
* MixColumn 함수
* 입력값 : char[16] 배열(평문)의 주소 -> 조작 가능
* 출력값 : 입력값의 직접 조작
*/
void MixColumns(AES_STATE_t P)
{
	AES_STATE_t temp;
	uint8_t tmp;
	char i, j, k;

	for (i = 0; i < 16; i++)
	{
		temp[i] = P[i];
	}

	for (i = 0; i < 4; i++)
	{
		for (j = 0; j < 4; j++)
		{
			tmp = 0;

			for (k = 0; k < 4; k++)
			{
				tmp ^= multiplication(temp[4 * i + k], mixColumnBox[j][k]);
			}

			P[4 * i + j] = tmp;
		}
	}
}

/*
* InvMixColumn 함수
* 입력값 : char[16] 배열(평문)의 주소 -> 조작 가능
* 출력값 : 입력값의 직접 조작
*/
void InvMixColumns(AES_STATE_t P)
{
	AES_STATE_t temp;
	uint8_t tmp;
	char i, j, k;

	for (i = 0; i < 16; i++)
	{
		temp[i] = P[i];
	}

	for (i = 0; i < 4; i++)
	{
		for (j = 0; j < 4; j++)
		{
			tmp = 0;

			for (k = 0; k < 4; k++)
			{
				tmp ^= multiplication(temp[4 * i + k], InvMixColumnBox[j][k]);
			}

			P[4 * i + j] = tmp;
		}
	}
}

/* 키 확장 함수
* 입력값 : char[16] 배열
* 중간값 : uint[11][4] 배열, 한 행이 한 라운드를 의미
* 결과값 : 전역변수 char[15][16]에 저장 -> 완성된 라운드 키
*/
void keyRounder128(AES128_KEY_t K128)
{
	char i, j, k;
	uint32_t tempKey[11][4] = { 0 };

	// w0, w1, w2, w3
	for (i = 0; i < 4; i++)
	{
		for (j = 0; j < 4; j++)
		{
			tempKey[0][i] |= K128[i * 4 + j];
			if (j == 3) break;
			tempKey[0][i] <<= 8;
		}
	}

	for (i = 0; i < 10; i++)
	{
		tempKey[i + 1][0] = tempKey[i][3];
		tempKey[i + 1][0] = RotWord(tempKey[i + 1][0]);
		tempKey[i + 1][0] = SubWord(tempKey[i + 1][0]);
		tempKey[i + 1][0] ^= RConstant[i];
		tempKey[i + 1][0] ^= tempKey[i][0];

		tempKey[i + 1][1] = tempKey[i + 1][0] ^ tempKey[i][1];
		tempKey[i + 1][2] = tempKey[i + 1][1] ^ tempKey[i][2];
		tempKey[i + 1][3] = tempKey[i + 1][2] ^ tempKey[i][3];
	}

	for (i = 0; i < 11; i++)
	{
		for (j = 0; j < 4; j++)
		{
			for (k = 0; k < 4; k++)
			{
				roundedKey[i][j * 4 + (3 - k)] = tempKey[i][j] & 0xff;
				tempKey[i][j] >>= 8;
			}
		}
	}
}

void AES128_enc(AES_STATE_t C, AES_STATE_t P, AES128_KEY_t K128)
{
	AES_STATE_t temp;
	int i;

	for (i = 0; i < 16; i++)
	{
		temp[i] = P[i];
	}

	keyRounder128(K128);

	AddRoundKey(temp, roundedKey[0]);
	for (i = 0; i < 10; i++)
	{
		SubBytes(temp);
		ShiftRows(temp);
		if (i == 9) break;
		MixColumns(temp);
		AddRoundKey(temp, roundedKey[i + 1]);
	}
	AddRoundKey(temp, roundedKey[10]);

	for (i = 0; i < 16; i++)
	{
		C[i] = temp[i];
	}
}

void AES128_dec(AES_STATE_t P, AES_STATE_t C, AES128_KEY_t K128)
{
	AES_STATE_t temp;
	int i;

	for (i = 0; i < 16; i++)
	{
		temp[i] = C[i];
	}

	AddRoundKey(temp, roundedKey[10]);
	for (i = 0; i < 10; i++)
	{
		InvShiftRows(temp);
		InvSubBytes(temp);
		AddRoundKey(temp, roundedKey[9 - i]);
		if (i == 9) break;
		InvMixColumns(temp);
	}

	for (i = 0; i < 16; i++)
	{
		P[i] = temp[i];
	}
}

//관련 데이터 타입 정의 내역
//128-bit block
//typedef uint8_t AES_STATE_t[16];
//192-bit masterkey
//typedef uint8_t AES192_KEY_t[24];


/* 키 확장 함수
* 입력값 : char[24] 배열
* 중간값 : uint[9][6] 배열, 한 행이 한 라운드를 의미
* 결과값 : 전역변수 char[15][16]에 저장 -> 완성된 라운드 키
*/
void keyRounder192(AES192_KEY_t K192)
{
	char i, j;
	uint32_t tempKey[9][6] = { 0 };

	// w0, w1, w2, w3, w4, w5
	for (i = 0; i < 6; i++)
	{
		for (j = 0; j < 4; j++)
		{
			tempKey[0][i] |= K192[i * 4 + j];
			if (j == 3) break;
			tempKey[0][i] <<= 8;
		}
	}

	for (i = 0; i < 8; i++)
	{
		tempKey[i + 1][0] = tempKey[i][5];
		tempKey[i + 1][0] = RotWord(tempKey[i + 1][0]);
		tempKey[i + 1][0] = SubWord(tempKey[i + 1][0]);
		tempKey[i + 1][0] ^= RConstant[i];
		tempKey[i + 1][0] ^= tempKey[i][0];

		tempKey[i + 1][1] = tempKey[i + 1][0] ^ tempKey[i][1];
		tempKey[i + 1][2] = tempKey[i + 1][1] ^ tempKey[i][2];
		tempKey[i + 1][3] = tempKey[i + 1][2] ^ tempKey[i][3];
		if (i == 7) break;
		tempKey[i + 1][4] = tempKey[i + 1][3] ^ tempKey[i][4];
		tempKey[i + 1][5] = tempKey[i + 1][4] ^ tempKey[i][5];
	}

	for (i = 0; i < 5; i++)
	{
		for (j = 0; j < 16; j++)
		{
			roundedKey[i * 3][3 + (int)(j / 4) * 4 - (j % 4)] = tempKey[i * 2][j / 4] & 0xff;
			tempKey[i * 2][j / 4] >>= 8;

			
			if (i == 4) continue;
			roundedKey[i * 3 + 2][3 + (int)(j / 4) * 4 - (j % 4)] = tempKey[i * 2 + 1][(j / 4) + 2] & 0xff;
			tempKey[i * 2 + 1][(j / 4) + 2] >>= 8;
			
		}

		if (i == 4) break;
		for (j = 0; j < 8; j++)
		{
			roundedKey[i * 3 + 1][3 + (int)(j / 4) * 4 - (j % 4)] = tempKey[i * 2][(j / 4) + 4] & 0xff;
			tempKey[i * 2][(j / 4) + 4] >>= 8;

			roundedKey[i * 3 + 1][11 + (int)(j / 4) * 4 - (j % 4)] = tempKey[i * 2 + 1][j / 4] & 0xff;
			tempKey[i * 2 + 1][j / 4] >>= 8;
		}
	}
}

void AES192_enc(AES_STATE_t C, AES_STATE_t P, AES192_KEY_t K192)
{
	AES_STATE_t temp;
	int i;

	for (i = 0; i < 16; i++)
	{
		temp[i] = P[i];
	}

	keyRounder192(K192);

	AddRoundKey(temp, roundedKey[0]);
	for (i = 0; i < 12; i++)
	{
		SubBytes(temp);
		ShiftRows(temp);
		if (i == 11) break;
		MixColumns(temp);
		AddRoundKey(temp, roundedKey[i + 1]);
	}
	AddRoundKey(temp, roundedKey[12]);

	for (i = 0; i < 16; i++)
	{
		C[i] = temp[i];
	}
}

void AES192_dec(AES_STATE_t P, AES_STATE_t C, AES192_KEY_t K192)
{
	AES_STATE_t temp;
	int i;

	for (i = 0; i < 16; i++)
	{
		temp[i] = C[i];
	}

	AddRoundKey(temp, roundedKey[12]);
	for (i = 0; i < 12; i++)
	{
		InvShiftRows(temp);
		InvSubBytes(temp);
		AddRoundKey(temp, roundedKey[11 - i]);
		if (i == 11) break;
		InvMixColumns(temp);
	}

	for (i = 0; i < 16; i++)
	{
		P[i] = temp[i];
	}
}

//관련 데이터 타입 정의 내역
//128-bit block
//typedef uint8_t AES_STATE_t[16];
//256-bit masterkey
//typedef uint8_t AES256_KEY_t[32];

void keyRounder256(AES256_KEY_t K256)
{
	char i, j, k;
	uint32_t tempKey[8][8] = { 0 };

	// w0, w1, w2, w3, w4, w5, w6, w7
	for (i = 0; i < 8; i++)
	{
		for (j = 0; j < 4; j++)
		{
			tempKey[0][i] |= K256[i * 4 + j];
			if (j == 3) break;
			tempKey[0][i] <<= 8;
		}
	}

	for (i = 0; i < 7; i++)
	{
		tempKey[i + 1][0] = tempKey[i][7];
		tempKey[i + 1][0] = RotWord(tempKey[i + 1][0]);
		tempKey[i + 1][0] = SubWord(tempKey[i + 1][0]);
		tempKey[i + 1][0] ^= RConstant[i];
		tempKey[i + 1][0] ^= tempKey[i][0];

		tempKey[i + 1][1] = tempKey[i + 1][0] ^ tempKey[i][1];
		tempKey[i + 1][2] = tempKey[i + 1][1] ^ tempKey[i][2];
		tempKey[i + 1][3] = tempKey[i + 1][2] ^ tempKey[i][3];

		if (i == 7) break;
		tempKey[i + 1][4] = SubWord(tempKey[i + 1][3]) ^ tempKey[i][4];
		tempKey[i + 1][5] = tempKey[i + 1][4] ^ tempKey[i][5];
		tempKey[i + 1][6] = tempKey[i + 1][5] ^ tempKey[i][6];
		tempKey[i + 1][7] = tempKey[i + 1][6] ^ tempKey[i][7];
	}

	for (i = 0; i < 7; i++)
	{
		for (j = 0; j < 8; j++)
		{
			for (k = 0; k < 4; k++)
			{
				roundedKey[2 * i + (j / 4)][(j % 4) * 4 + (3 - k)] = tempKey[i][j] & 0xff;
				tempKey[i][j] >>= 8;
			}
		}
	}

	for (i = 0; i < 4; i++)
	{
		for (j = 0; j < 4; j++)
		{
			roundedKey[14][i * 4 + (3 - j)] = tempKey[7][i] & 0xff;
			tempKey[7][i] >>= 8;
		}
	}
}

void AES256_enc(AES_STATE_t C, AES_STATE_t P, AES256_KEY_t K256)
{
	AES_STATE_t temp;
	int i;

	for (i = 0; i < 16; i++)
	{
		temp[i] = P[i];
	}

	keyRounder256(K256);

	AddRoundKey(temp, roundedKey[0]);
	for (i = 0; i < 14; i++)
	{
		SubBytes(temp);
		ShiftRows(temp);
		if (i == 13) break;
		MixColumns(temp);
		AddRoundKey(temp, roundedKey[i + 1]);
	}
	AddRoundKey(temp, roundedKey[14]);

	for (i = 0; i < 16; i++)
	{
		C[i] = temp[i];
	}
}

void AES256_dec(AES_STATE_t P, AES_STATE_t C, AES256_KEY_t K256)
{
	AES_STATE_t temp;
	int i;

	for (i = 0; i < 16; i++)
	{
		temp[i] = C[i];
	}

	AddRoundKey(temp, roundedKey[14]);
	for (i = 0; i < 14; i++)
	{
		InvShiftRows(temp);
		InvSubBytes(temp);
		AddRoundKey(temp, roundedKey[13 - i]);
		if (i == 13) break;
		InvMixColumns(temp);
	}

	for (i = 0; i < 16; i++)
	{
		P[i] = temp[i];
	}
}
