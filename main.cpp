/*
Maksim Shishkov
913401117
SFSU
Project 1
*/

#include<iostream>
#include<string>
#include<math.h>
#include<cctype>
#include<windows.h>
#include "des.h"

using namespace std;

string toBinary(string message, int length);
string cbc(string message, string key, string iv);
string cfb(string message, string key, string iv);
string ofb(string message, string key, string iv);
string cbcRe(string message, string key);
string cbcEnRe(string message, string key, string iv);

string conv_table[23]={
   		"0000",
        "0001",
   		"0010",
   		"0011",
   		"0100",
   		"0101",
   		"0110",
   		"0111",
   		"1000",
   		"1001",
   		"pad",
   		"pad",
   		"pad",
   		"pad",
   		"pad",
   		"pad",
   		"pad",
        "1010",
   		"1011",
   		"1100",
   		"1101",
   		"1110",
   		"1111"
   };

   string hex_table[23]={
   		"0",
   		"1",
   		"2",
   		"3",
   		"4",
   		"5",
   		"6",
   		"7",
   		"8",
   		"9",
   		"pad",
   		"pad",
   		"pad",
   		"pad",
   		"pad",
   		"pad",
   		"pad",
   		"A",
   		"B",
   		"C",
   		"D",
   		"E",
   		"F"
   };



int main()
{


    string input="0123456789ABCDEFFEDCBA9876543210",key="133457799BBCDFF1", iv = "2819F59C1D58D750", result;

    cout << "input: \t" << input << endl;
    cout << "key: \t" << key << endl;
    cout << "iv: \t" << iv << endl;
    cout << endl;

    result = cbc(input, key, iv);
    cout << "cbc: \t" << result << endl;
    cout << endl;

    result = cfb(input, key, iv);
    cout << "cfb: \t" << result << endl;
    cout << endl;

    result = ofb(input, key, iv);
    cout << "ofb: \t" << result << endl;
    cout << endl;

    result = cbcRe(input, key);
    cout << "cbcRe: \t" << result << endl;
    cout << endl;

    result = cbcEnRe(input, key, iv);
    cout << "cbcEnRe:   " << result << endl;
    cout << endl;
    return 0;
}

string toBinary(string message, int length)
{
    string input;
    for(int i=0;i<length;i++)
        {
            int a=message[i]-'0';
            input=input+conv_table[a];

        }
        return input;
}

string cbc(string message, string key, string iv)
{
    string block;
    string encrypted_block;
    string hex_encrypted_msg;
	message = toBinary(message, message.length());
	iv = toBinary(iv, iv.length());
	int length = message.length();

    int rounds = static_cast<int>(ceil(message.length() / 64.0));
	int pad_num = 64 - (message.length() % 64);
	string pad;
	for(int i =  0; i < pad_num; i++)
        pad.append("0");
    if(!pad.empty())
        message = message.append(pad);


    for( int i = 0; i < rounds; i++)
    {
        block = message.substr(i*64,64);
        block = xored_msg(block, iv);
        encrypted_block=des_process(block,key,true);
        iv = encrypted_block;
        string hex_conv=hex_conversion(encrypted_block,conv_table,hex_table);
        hex_encrypted_msg.append(hex_conv);

    }



	return 	hex_encrypted_msg;
}

string cfb(string message, string key, string iv)
{
    string block;
    string hex_encrypted_msg;
    string encrypted_block;
	message = toBinary(message, message.length());
	iv = toBinary(iv, iv.length());
	int length = message.length();
	int iv_length = iv.length();

    int rounds = static_cast<int>(ceil(message.length() / static_cast<double>(iv_length)));
	int pad_num = iv_length - (message.length() % iv_length);
	string pad;
	for(int i =  0; i < pad_num; i++)
        pad.append("0");
    if(!pad.empty())
        message = message.append(pad);

    for( int i = 0; i < rounds; i++)
    {
        encrypted_block=des_process(iv,key,true);
        block = message.substr(i*iv_length,iv_length);
        encrypted_block = xored_msg(block, encrypted_block);
        iv = encrypted_block;
        string hex_conv=hex_conversion(encrypted_block,conv_table,hex_table);
        hex_encrypted_msg.append(hex_conv);
    }



    return hex_encrypted_msg;
}


string ofb(string message, string key, string iv)
{
    string block;
    string encrypted_msg;
    string encrypted_block;
    string hex_encrypted_msg;
	message = toBinary(message, message.length());
	iv = toBinary(iv, iv.length());
	int length = message.length();
	int iv_length = iv.length();

    int rounds = static_cast<int>(ceil(message.length() / static_cast<double>(iv_length)));
	int pad_num = iv_length - (message.length() % iv_length);
	string pad;
	for(int i =  0; i < pad_num; i++)
        pad.append("0");
    if(!pad.empty())
        message = message.append(pad);

    for( int i = 0; i < rounds; i++)
    {
        encrypted_block=des_process(iv,key,true);
        block = message.substr(i*iv_length,iv_length);
        iv = encrypted_block;
        encrypted_msg = xored_msg(block, encrypted_block);
        string hex_conv=hex_conversion(encrypted_msg,conv_table,hex_table);
        hex_encrypted_msg.append(hex_conv);

    }



    return hex_encrypted_msg;
}


string cbcRe(string message, string key)
{
    string block;
    string encrypted_block;
    string iv = "0000000000000000";
	message = toBinary(message, message.length());
	iv = toBinary(iv, iv.length());
	int length = message.length();

    int rounds = static_cast<int>(ceil(message.length() / 64.0));
	int pad_num = 64 - (message.length() % 64);
	string pad;
	for(int i =  0; i < pad_num; i++)
        pad.append("0");
    if(!pad.empty())
        message = message.append(pad);


    for( int i = 0; i < rounds; i++)
    {
        block = message.substr(i*64,64);
        block = xored_msg(block, iv);
        encrypted_block=des_process(block,key,true);
        iv = encrypted_block;
    }

    string hex_resadue=hex_conversion(encrypted_block,conv_table,hex_table);


	return 	hex_resadue;
}


string cbcEnRe(string message, string key, string iv)
{
    string resadue = cbcRe(message,key);
    message.append(resadue);
    string encrypted_message = cbc(message,key,iv);

    return encrypted_message;
}


