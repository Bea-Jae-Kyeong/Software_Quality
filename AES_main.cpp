/**
 *  @file main.cpp
 *  @brief An AES encryption and decryption program for Computer Security
 *
 *  By putting plain text and key text, we can get an encrypted cipher text, and also get an decrypted text compared with the plain text
 */
#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <fstream>
#include <windows.h>
using namespace std;

#define xtime(x) ((x << 1) ^ (((x >> 7) & 1) * 0x169))		/// Declaring xtime
#define Multiply(x,y) (((y & 1) * x) ^ ((y>>1 & 1) * xtime(x)) ^ ((y>>2 & 1) * xtime(xtime(x))) ^ ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^ ((y>>4 & 1) * xtime(xtime(xtime(xtime(x))))))
/// Declaring the Multiply for Mix column
#define Nb 4	/// Length of the Block
#define Nk 4	/// Length of the key
#define Nr 10	/// Number of Round
int state[4][4] = { 0, };			/// Array storing instant state
int RoundKey[240] = { 0, };			/// Array storing Round Key
int c[8] = { 1,0,1,0,1,0,0,0 };		/// Array used for Sbox XOR operation
int c1[8] = { 1,1,1,0,0,0,1,1 };	/// Array used for Inverse Sbox XOR operation
int b[8] = { 0, };
int b1[8] = { 0, };
int m, w;							/// By defining m and w here, we can stop m, w from shadowing outer variables
unsigned char a, b_, c_, d;		/// By defining a,b,c,d here, we can stop them from shadowing outer variables
unsigned char sbox[256];
unsigned char invsbox[256];			/// Inverse of the Sbox
unsigned char GF[256] = { 0, };		/// Array of Galua Field(2^8) for calculation inverse element
unsigned char InvGF[256];			/// Array of Inverse Galua Field(2^8) for calculation inverse element
/**
 *
 * @param [in] num The index of Sbox array
 * @brief Function for making 8-bit Sbox for encryption
 * @return The value of Sbox is returned, by the num, which is the index of Sbox array
 */
int Sbox(size_t num) {		/// preventing index out-of-bound
	a = 1;
	for (int e = 0; e < 256; e++) {	/// Function Generating Galua Field
		InvGF[e] = a;
		w = a & 0x80;
		a <<= 1;
		if (w == 0x80)
			a ^= 0x69;
		a ^= InvGF[e];
		GF[InvGF[e]] = e;
	}
	InvGF[255] = 0;

	for (int i = 1; i < 256; i++) {
		m = InvGF[(255 - GF[i])];		/// Inverse element
		for (int j = 7; j >= 0; j--) {
			b[j] = m / (1 << j);		/// Generating inverse element into binary b[0] to b[7]
			m %= (1 << j);
		}
		for (int k = 0; k < 8; k++) {
			b1[k] = b[k] ^ b[(k + 4) % 8] ^ b[(k + 5) % 8] ^ b[(k + 6) % 8] ^ b[(k + 7) % 8] ^ c[k];	// ��� ���� �� XOR
			m += b1[k] * (1 << k);		/// Restore from binary
		}
		sbox[i] = m;
	}
	sbox[0] = 0x15;						/// 0 doesn't have inverse
	return sbox[num];
}

/**
 *
 * @param [in] n The index of Inversed Sbox array
 * @brief Function generating 8-bit Inverse Sbox used for decryption
 * @return Inverse Sbox's value is returned, followed by n, which is the Inverse Sbox array's index
 */
int InvSbox(size_t n) {				/// preventing index out-of-bound
	int i, j, k;

	for (i = 1; i < 256; i++) {
		m = i;
		for (j = 7; j >= 0; j--) {
			b[j] = m / (1 << j);		/// Making 1 to 255 into binary and store b[0] to b[7]
			m %= (1 << j);
		}
		for (k = 0; k < 8; k++) {
			b1[k] = b[(k + 2) % 8] ^ b[(k + 5) % 8] ^ b[(k + 7) % 8] ^ c1[k];	/// XOR after matrix operation
			m = m + b1[k] * (1 << k);		/// Restore from binary
		}
		invsbox[i] = InvGF[(255 - GF[m])];	/// Inverse
	}
	sbox[0] = 0xf3;							/// 0 doesn't have inverse
	return invsbox[n];
}

/**
 *
 * @param [in] num The index of Rcon array
 * @brief Function generating Rcon
 * @return The value of Rcon array is returned, by num which is the index of Rcon array.
 */
int RCon(size_t num) {					/// preventing index out-of-bound
	int Rcon[11];
	for (int i = 0; i < 10; i++) {
		Rcon[i] = (1 << i) % 0x169;
		if (Rcon[i] > 128)
			Rcon[i] = 0x169 - Rcon[i];
	}
	return Rcon[num];
}

/**
 *
 * @param [in] key The array which stores the key
 * @brief Key expanding function to add each round key
 */
void KeyExpansion(int *key)
{
	int i, j;
	unsigned char temp[4], k;
	cout << "ROUND 0: ";
	for (i = 0; i < Nk; i++)	/// Storing key value in Round key
	{
		RoundKey[4 * i] = key[4 * i];
		RoundKey[4 * i + 1] = key[4 * i + 1];
		RoundKey[4 * i + 2] = key[4 * i + 2];
		RoundKey[4 * i + 3] = key[4 * i + 3];
	}
	for (k = 0; k < 16; k++) {
		cout << RoundKey[k] << " ";
	}
	cout << endl;

	while (i < (Nb * (Nr + 1)))
	{
		for (j = 0; j < 4; j++)
		{
			temp[j] = RoundKey[(i - 1) * 4 + j];
		}

		if (i % Nk == 0)
		{
			{	/// Rotating word by Word
				k = temp[0];
				temp[0] = temp[1];
				temp[1] = temp[2];
				temp[2] = temp[3];
				temp[3] = k;
			}
			{	/// Substitute by Sbox
				temp[0] = Sbox(temp[0]);
				temp[1] = Sbox(temp[1]);
				temp[2] = Sbox(temp[2]);
				temp[3] = Sbox(temp[3]);
			}
			temp[0] = temp[0] ^ RCon(i / Nk - 4);		// We changed this line by adding -4 to prevent it from hardcoding
		}
		RoundKey[4 * i + 0] = RoundKey[(i - Nk) * 4 + 0] ^ temp[0];
		RoundKey[4 * i + 1] = RoundKey[(i - Nk) * 4 + 1] ^ temp[1];
		RoundKey[4 * i + 2] = RoundKey[(i - Nk) * 4 + 2] ^ temp[2];
		RoundKey[4 * i + 3] = RoundKey[(i - Nk) * 4 + 3] ^ temp[3];
		i++;
	}
	for (i = 1; i <= Nr; i++)
	{
		cout << dec << "ROUND " << i << ": ";
		for (j = 0; j < 16; j++)
		{
			cout << hex << RoundKey[i * 16 + j] << " ";
		}
		cout << endl;
	}
}

/**
 *
 * @param [in] round the round number
 * @brief Function adding round key value by XORing state array and round key
 */
void AddRoundKey(int round)
{
	cout << "AR: ";
	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < 4; j++)
		{
			state[j][i] ^= RoundKey[round * Nb * 4 + i * Nb + j];
			cout << state[j][i] << " ";
		}
	}
	cout << endl;
}
/**
 *
 * @brief Substitute each Byte value of state array by Sbox
 */
void SubBytes()
{
	cout << "SB: ";
	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < 4; j++)
		{
			state[j][i] = Sbox(state[j][i]);		/// assigned Sbox as an unsigned char before converted into state array
			cout << state[j][i] << " ";
		}
	}
	cout << endl;
}
/**
 *
 * @brief Function decrypting SubBytes. Substitute each Byte value of state array by Inverse Sbox
 */
void InvSubBytes()
{
	cout << "SB: ";
	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < 4; j++)
		{
			state[j][i] = InvSbox(state[j][i]);
			cout << state[j][i] << " ";
		}
	}
	cout << endl;
}

/**
 *
 * @brief Function rotating rows of substituted Byte value by bit
 */
void ShiftRows()
{
	unsigned char temp = 0;

	/// Rotating left from first row
	temp = state[1][0];
	state[1][0] = state[1][1];
	state[1][1] = state[1][2];
	state[1][2] = state[1][3];
	state[1][3] = temp;

	/// Rotating left from second row
	temp = state[2][0];
	state[2][0] = state[2][2];
	state[2][2] = temp;

	temp = state[2][1];
	state[2][1] = state[2][3];
	state[2][3] = temp;

	/// Rotating left from third row
	temp = state[3][0];
	state[3][0] = state[3][3];
	state[3][3] = state[3][2];
	state[3][2] = state[3][1];
	state[3][1] = temp;

	cout << "SR: ";
	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < 4; j++)
		{
			cout << state[j][i] << " ";
		}
	}
	cout << endl;
}

/**
 *
 * @brief Function decrypting ShiftRows
 */
void InvShiftRows()
{
	unsigned char temp;

	/// Rotating right from first row
	temp = state[1][3];
	state[1][3] = state[1][2];
	state[1][2] = state[1][1];
	state[1][1] = state[1][0];
	state[1][0] = temp;

	/// Rotating right from second row
	temp = state[2][0];
	state[2][0] = state[2][2];
	state[2][2] = temp;

	temp = state[2][1];
	state[2][1] = state[2][3];
	state[2][3] = temp;

	/// Rotating right from third row
	temp = state[3][0];
	state[3][0] = state[3][1];
	state[3][1] = state[3][2];
	state[3][2] = state[3][3];
	state[3][3] = temp;

	cout << "SR: ";
	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < 4; j++)
		{
			cout << state[j][i] << " ";
		}
	}
	cout << endl;
}

/**
 *
 * @brief Function mixing columns by operating in 4-bit
 */
void MixColumns()
{

	for (int i = 0; i < 4; i++)
	{
		unsigned char Tmp, Tm, t;			/// putting inside the loop solves warnings
		t = state[0][i];

		Tmp = state[0][i] ^ state[1][i] ^ state[2][i] ^ state[3][i];
		/// execute matrix multiply operation and store in Tm
		Tm = state[0][i] ^ state[1][i];
		Tm = xtime(Tm);
		state[0][i] ^= Tm ^ Tmp;
		Tm = state[1][i] ^ state[2][i];
		Tm = xtime(Tm);
		state[1][i] ^= Tm ^ Tmp;
		Tm = state[2][i] ^ state[3][i];
		Tm = xtime(Tm);
		state[2][i] ^= Tm ^ Tmp;
		Tm = state[3][i] ^ t;
		Tm = xtime(Tm);
		state[3][i] ^= Tm ^ Tmp;
	}
	cout << "MC: ";
	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < 4; j++)
		{
			cout << state[j][i] << " ";
		}
	}
	cout << endl;
}

/**
 *
 * @brief MixColumns function for decryption
 */
void InvMixColumns()
{
	for (int i = 0; i < 4; i++)
	{
		a = state[0][i];
		b_ = state[1][i];
		c_ = state[2][i];
		d = state[3][i];

		/// Operating multiply with fixed polynomial expression by Multiply and XOR operation
		state[0][i] = Multiply(a, 0x0e) ^ Multiply(b_, 0x0b) ^ Multiply(c_, 0x0d) ^ Multiply(d, 0x09);
		state[1][i] = Multiply(a, 0x09) ^ Multiply(b_, 0x0e) ^ Multiply(c_, 0x0b) ^ Multiply(d, 0x0d);
		state[2][i] = Multiply(a, 0x0d) ^ Multiply(b_, 0x09) ^ Multiply(c_, 0x0e) ^ Multiply(d, 0x0b);
		state[3][i] = Multiply(a, 0x0b) ^ Multiply(b_, 0x0d) ^ Multiply(c_, 0x09) ^ Multiply(d, 0x0e);
	}

	cout << "MC: ";
	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < 4; j++)
		{
			cout << state[j][i] << " ";
		}
	}
	cout << endl;
}

/**
 *
 * @param [in] plain The array which stores plain text
 * @param [out] cipher The array which stores ciphered text
 * @brief Encryption function
 */
void Cipher(int * plain, int * cipher)
{
	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < Nb; j++)
		{
			state[j][i] = plain[4 * i + j];
		}
	}
	cout << endl;

	cout << "Round 0" << endl;
	AddRoundKey(0);			/// Add first Round Key
	cout << endl;
	for (int round = 1; round < Nr; round++)
	{
		cout << "Round " << round << endl;
		SubBytes();		/// Substitute by Byte
		ShiftRows();	/// Rotate rows
		MixColumns();	/// Mixing columns
		AddRoundKey(round);	/// XORing extended key and current block
		cout << endl;
	}
	cout << "Round 10" << endl;
	SubBytes();
	ShiftRows();
	AddRoundKey(Nr);	/// XORing last key and current block

	/// Storing final encrypted state array in cipher array
	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < Nb; j++)
		{
			cipher[4 * i + j] = state[j][i];
		}
	}
}
/**
 *
 * @param [in] cipher The array which stores ciphered text
 * @param [out] decrypted The array which stores decrypted text
 * @brief Decryption function
 */
void InvCipher(int * cipher, int * decrypted) {
	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < Nb; j++)
		{
			state[j][i] = cipher[4 * i + j];
		}
	}

	cout << "Round 0" << endl;
	AddRoundKey(Nr);
	cout << endl;
	for (int round = Nr - 1; round > 0; round--)
	{
		cout << "Round " << 10 - round << endl;
		InvShiftRows();		/// Rotating inverse row
		InvSubBytes();		/// Substitute inverse byte
		AddRoundKey(round);		/// Adding round key
		InvMixColumns();		/// Mixing inverse columns
		cout << endl;
	}
	cout << "Round 10" << endl;
	InvShiftRows();
	InvSubBytes();
	AddRoundKey(0);		/// XORing first key and current block
	cout << endl;
	/// Storing final decrypted state block in plain array
	for (int i = 0; i < 4; i++)
	{
		for (int j = 0; j < Nb; j++)
		{
			decrypted[4 * i + j] = state[j][i];
		}
	}

}

/**
 * @brief Opening cipher and decrypted binary file and writing the output
 */

void Decrypt() {
	int i;
	unsigned char buf1[16];
	int decrypted[20] = { 0, };	/// Array storing decrypted text
	int cipher[128] = { 0, };	/// Array storing cipher text

	FILE *fp2, *fp3;
	/// Writing cipher text and decrypted text in binary file
	fp2 = fopen("cipher.bin", "wx");
	fp3 = fopen("decrypted.bin", "wx");
	if (!fp2) {
		perror("cipher.bin");
		exit(1);
	}
	if (!fp3) {
		perror("decrypted.bin");
		exit(1);
	}
	/// Writing cipher file
	for (i = 0; i < 16; i++) {
		buf1[i] = cipher[i];
	}
	fwrite(&buf1, 1, sizeof(buf1), fp2);

	/// Writing decrypted file
	for (i = 0; i < 16; i++) {
		buf1[i] = decrypted[i];
	}
	fwrite(&buf1, 1, sizeof(buf1), fp3);

	fclose(fp2);
	fclose(fp3);

	fputs("stdout successfully closed.", stderr);
}
/**
 *
 * @brief Opening binary files and writing a new one
 */
int main(void)
{
	int i = 0;
	int key[32];		/// Array storing key
	int plain[20];		/// Array storing plain text
	int decrypted[20];	/// Array storing decrypted text
	int cipher[128] = { 0, };	/// Array storing cipher text
	unsigned char buf[16];
	FILE *fp, *fp1;

	cout << hex;

	cout << "RC : ";
	for (i = 0; i < 10; i++)
		cout << RCon(i) << " ";
	cout << endl;

	/// Reading binary file
	fp = fopen("key.bin", "rb");
	fp1 = fopen("plain.bin", "rb");
	if (fp == NULL) {		/// fopen returns NULL when error occurs
		perror("key.txt");
		exit(1);
	}
	if (fp1 == NULL) {	/// fopen returns NULL when error occurs
		perror("plain.txt");
		exit(1);
	}
	/// Printing plain text array
	while (fread((void*)buf, 1, sizeof(buf), fp1)) {
		cout << "PLAIN : ";
		for (i = 0; i < 16; i++) {
			plain[i] = buf[i];
			cout << plain[i] << " ";
		}
		cout << endl;
	}
	/// Printing key array
	while (fread((void*)buf, 1, sizeof(buf), fp)) {
		cout << "KEY : ";
		for (i = 0; i < 16; i++) {
			key[i] = buf[i];
			cout << hex << key[i] << " ";
		}
		cout << endl;
	}
	fclose(fp);
	fclose(fp1);

	cout << endl << endl << "<------ENCRYPTION-------->" << endl << endl << "KEY EXPANSION" << endl;
	KeyExpansion(key);
	Cipher(plain, cipher);		/// Encryption
	cout << endl << "CIPHER : ";
	for (i = 0; i < 16; i++)
		cout << cipher[i] << " ";
	cout << endl << endl << "<------DECRYPTION-------->" << endl << endl;

	InvCipher(cipher, decrypted);	/// Decryption
	cout << "DECRYPTED : ";
	for (i = 0; i < 16; i++)
		cout << decrypted[i] << " ";
	cout << endl;
	Decrypt();

	return 0;
}
