/**
 *        @file: simplified_des.cc
 *      @author: Parker Corbitt
 *        @date: October 8, 2023
 *       @brief: The purpose of this program is to perform encryption/decryption 
 *              based on the simplified DES algorithm. All operations (permutations, 
 *              keygen, feistel) are done in accordance with this algorithm.
 * 
 * 
 *        @todo:    *Verify that the p10 permutations functions as expected
 *                  *Take the key as a command line argument
 */

#include <iostream>
#include <iomanip>
#include <cstdlib>
#include <bitset>
using namespace std;

/// function prototypes

/**
 * @brief Performs operations on the input variable to either encyrpt/decrypt
 *          the input character. 
 * 
 * @param input - The character to be encrypted
 * @param k1 - The key to be used first within the feistel function
 * @param k2 - the key to be used second within the feistel function
 * @return char - The encrypted/decrypted char
 */
char feistel(char &input, bitset<8> &k1, bitset<8> &k2);

/**
 * @brief Generates a key based on a 10 bit input supplied by a command line argument
 * 
 * @param input_key - The command line integer converted to a bitset
 * @param k1 - The first key generated
 * @param k2 - The second key generated
 */
void keygen(bitset<10> input_key, bitset<8> &k1, bitset<8> &k2);

/**
 * @brief Permutes the input bitset in accordance with the ip permutation
 * 
 * @param input - The character to be enc/dec, converted to a bitset
 */
void ip(bitset<8> &input);

/**
 * @brief Permutes the input bitset in accordance with th ip inverse permutation
 * 
 * @param input - The bitset to be converted to the output char
 */
void ip_inv(bitset<8> &input);

/**
 * @brief Performs the expansion permutation
 * 
 * @param input - 
 * @return bitset<8> 
 */
bitset<8> ep(bitset<4> &input);
bitset<4> p4(bitset<2> upper, bitset<2> lower);
bitset<8> p8(bitset<5> upper, bitset<5> lower);
void p10(bitset<10> &input_key);
bitset<2> s0(bitset<4> input);
bitset<2> s1(bitset<4> input);
void wrapping_shift(bitset<5> &bits, int shift_amount);

int main(int argc, char const *argv[])
{

    int key = 642;
    string starting = "bro";
    string ciphertext;
    string plaintext;

    bitset<8> k1;
    bitset<8> k2;
    bitset<10> key_bits = bitset<10>(key);

    keygen(key_bits, k1, k2);
    cout << "This is k1: " << k1 << endl;
    cout << "This is k2: " << k2 << endl;
    cout << "This is the entered text: " << starting << endl;
    for (int i = 0; i < starting.size(); i++)
    {
        ciphertext += feistel(starting.at(i), k1, k2);
    }
    cout << "This is the encrypted text: " << ciphertext << endl;

    for (int i = 0; i < starting.size(); i++)
    {
        plaintext += feistel(ciphertext.at(i), k2, k1);
    }
    cout << "This is the decrypted text: " << plaintext << endl;

    return 0;
} // main

char feistel(char &input, bitset<8> &k1, bitset<8> &k2)
{
    // convert input char to bits
    bitset<8> input_bits = bitset<8>(input);

    // IP permutation
    ip(input_bits);

    // Split the ip bits into two ordered halves
    bitset<4> upper;
    bitset<4> lower;

    for (int i = 7; i >= 4; i--)
    {
        upper[i- 4] = input_bits[i];
        lower[i - 4] = input_bits[i - 4];
    }
    bitset<8> lower_expanded = ep(lower);
    bitset<8> expanded_xor = lower_expanded ^ k1;

    bitset<4> post_xor_upper;
    bitset<4> post_xor_lower;
    for (int i = 7; i >= 4; i--)
    {
        post_xor_upper[i - 4] = expanded_xor[i];
        post_xor_lower[i - 4] = expanded_xor[i - 4];
    }
    bitset<2> post_s0 = s0(post_xor_upper);
    bitset<2> post_s1 = s1(post_xor_lower);
    bitset<4> p4_output = p4(post_s0, post_s1);
    bitset<4> last_xor = upper ^ p4_output;
    upper = lower;
    lower = last_xor;

    lower_expanded = ep(lower);
    expanded_xor = lower_expanded ^ k2;

    for (int i = 7; i >= 4; i--)
    {
        post_xor_upper[i - 4] = expanded_xor[i];
        post_xor_lower[i - 4] = expanded_xor[i - 4];
    }
    post_s0 = s0(post_xor_upper);
    post_s1 = s1(post_xor_lower);
    p4_output = p4(post_s0, post_s1);
    last_xor = upper ^ p4_output;

    bitset<8> final;
    for (int i = 7; i >= 4; i--)
    {
        final[i] = last_xor[i - 4];
        final[i - 4] = lower[i - 4];
    }

    ip_inv(final);

    // cout << final << endl;
    char x = final.to_ulong();
    return x;
}

void keygen(bitset<10> input_key, bitset<8> &k1, bitset<8> &k2)
{
    // cout << input_key << endl;
    p10(input_key);
    bitset<5> upper;
    bitset<5> lower;

    for (int i = 9; i >= 5; i--)
    {
        upper[i - 5] = input_key[i];
        lower[i - 5] = input_key[i - 5];
    }
    // cout << upper << lower << endl;
    wrapping_shift(upper, 1);
    wrapping_shift(lower, 1);
    // cout << upper << lower << endl;
    k1 = p8(upper, lower);
    // cout << k1 << endl;
    wrapping_shift(upper, 2);
    wrapping_shift(lower, 2);
    k2 = p8(upper, lower);
    // cout << k2 << endl;

    return;
}

void ip(bitset<8> &input)
{
    bitset<8> tmp;
    int permutation[8] = {1, 3, 0, 4, 7, 5, 2, 6};

    tmp = input;

    for (int i = 7; i >= 0; i--)
    {
        input[i] = tmp[permutation[i]];
    }
}

void ip_inv(bitset<8> &input)
{
    bitset<8> tmp;
    int permutation[8] = {2, 0, 6, 1, 3, 5, 7, 4};

    tmp = input;

    for (int i = 7; i >= 0; i--)
    {
        input[i] = tmp[permutation[i]];
    }
}

bitset<8> ep(bitset<4> &input)
{
    bitset<8> expanded;
    int permutation[8] = {3, 0, 1, 2, 1, 2, 3, 0};

    for (int i = 7; i >= 0; i--)
    {
        expanded[i] = input[permutation[i]];
    }

    return expanded;
}

bitset<4> p4(bitset<2> upper, bitset<2> lower)
{
    bitset<4> tmp;
    bitset<4> output;
    int permutation[4] = {3, 1, 0, 2};

    for (int i = 3; i >= 2; i--)
    {
        tmp[i] = upper[i - 2];
        tmp[i - 2] = lower[i - 2];
    }

    for (int i = 3; i >= 0; i--)
    {
        output[i] = tmp[permutation[i]];
    }

    return output;
}

bitset<8> p8(bitset<5> upper, bitset<5> lower)
{
    bitset<10> tmp;
    bitset<8> p8_bits;
    int permutation[8] = {1, 0, 5, 2, 6, 3, 7, 4};

    for (int i = 9; i >= 5; i--)
    {
        tmp[i] = upper[i - 5];
        tmp[i - 5] = lower[i - 5];
    }
    for (int i = 7; i >= 0; i--)
    {
        p8_bits[i] = tmp[permutation[i]];
    }
    return p8_bits;
}

void p10(bitset<10> &input_key)
{
    int permutation[10] = {4, 2, 1, 9, 0, 6, 3, 8, 5, 7};
    bitset<10> tmp = input_key;
    for (int i = 9; i >= 0; i--)
    {
        input_key[i] = tmp[permutation[i]];
    }
}

bitset<2> s0(bitset<4> input)
{
    int matrix[4][4] = {
        {1, 0, 3, 2},
        {3, 2, 1, 0},
        {0, 2, 1, 3},
        {3, 1, 3, 2}};

    bitset<2> row;
    bitset<2> column;

    row[1] = input[3];
    row[0] = input[0];
    column[1] = input[2];
    column[0] = input[1];

    int c = column.to_ulong();
    int r = row.to_ulong();

    int result = matrix[r][c];

    return bitset<2>(result);
}

bitset<2> s1(bitset<4> input)
{
    int matrix[4][4] = {
        {0, 1, 2, 3},
        {2, 0, 1, 3},
        {3, 0, 1, 0},
        {2, 1, 0, 3}};

    bitset<2> row;
    bitset<2> column;

    row[1] = input[3];
    row[0] = input[0];
    column[1] = input[2];
    column[0] = input[1];

    int c = column.to_ulong();
    int r = row.to_ulong();

    int result = matrix[r][c];

    return bitset<2>(result);
}

void wrapping_shift(bitset<5> &bits, int shift_amount)
{
    int tmp = 0;
    for (int i = shift_amount; i > 0; i--)
    {
        tmp = bits[4];
        bits = bits << 1;
        bits[0] = tmp;
    }
}