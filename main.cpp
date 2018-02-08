/*
 * Encrypt any file usnig strong 256 CBC Encryption 
 * Requires openssl 
 * Tested on ubuntu/Linux flavors
 */

/* 
 * File:   main.cpp
 * Author: alsabawi
 *
 * Created on January 26, 2017, 3:36 PM
 */


using namespace std;
#include <iostream>
#include <cstdlib>
#include <cstring>
#include <fstream> 
#include <stdlib.h>
#include <stdio.h>
#include <string>
#include <memory>
#include <limits>
#include <stdexcept>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <iosfwd>
/*
 * 
 */
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

#include <openssl/rand.h>

static const char* VERSION = "1.1";
static const unsigned int KEY_SIZE = 32;
static const unsigned int BLOCK_SIZE = 16;
static const unsigned int RANDOMPW_SIZE = 16;

int password2key(std::string password, const EVP_CIPHER *cipher, unsigned char *retkey, unsigned char *retiv) {

    const EVP_MD *dgst = NULL;
    unsigned char ranpw[RANDOMPW_SIZE];
    const unsigned char *salt = NULL;
    int ranpw_len = RANDOMPW_SIZE;
    
    OpenSSL_add_all_digests();
    dgst = EVP_get_digestbyname("md5");
    if (!dgst) {
        fprintf(stderr, "no such digest\n");
        return 1;
    }
    if(password.compare("randomrandom") == 0)
    {
        RAND_bytes(ranpw, ranpw_len);
        password.assign((const char *)ranpw);
        printf("Random password generated : %s\n", ranpw);
        fflush(stdout);
    }
    if (!EVP_BytesToKey(cipher, dgst, salt,
            (unsigned char *) password.c_str(),
            password.length(), 1, retkey, retiv)) {
        fprintf(stderr, "EVP_BytesToKey failed\n");
        return 1;
    }

    return 0;
}

void handleErrors(void) {
    fflush(stdout);

    printf("\n***ERROR***\n");
    //ERR_print_errors_fp(stderr);
    fprintf(stderr,"Encryption/Decryption failed");
    printf("\n");
    exit(-1);
}

void getRandom(unsigned char *buf, int size) {
    unsigned char buf2[size];
    int rc = RAND_bytes(buf2, size);

    unsigned long err = ERR_get_error();

    if (rc != 1) {
        perror("Random");
        printf("Error : %lu\n", err);
    } else {
        memcpy(buf, buf2, sizeof (buf2));
    }
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
        unsigned char *iv, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    /* Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits */
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /* Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /* Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
        unsigned char *iv, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    /* Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits */
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /* Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    /* Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

char *read_textfile(char *file_name, long *size) {
    char *source = NULL;
    FILE *fp = fopen(file_name, "r");
    if (fp != NULL) {
        /* Go to the end of the file. */
        if (fseek(fp, 0L, SEEK_END) == 0) {
            /* Get the size of the file. */
            long bufsize = ftell(fp);
            if (bufsize == -1) {
                /* Error */
            }

            /* Allocate our buffer to that size. */
            source = (char *) malloc(sizeof (char) * (bufsize + 1));
	    if(source != NULL)
	    {
		/* Go back to the start of the file. */
		if (fseek(fp, 0L, SEEK_SET) != 0) {
		    /* Error */
                }

	        /* Read the entire file into memory. */
	        long newLen = fread(source, sizeof (char), bufsize, fp);
		if (ferror(fp) != 0) 
		{
		    fputs("Error reading file", stderr);
		} else 
		{
		    source[newLen++] = '\0'; /* Just to be safe. */
		}
		*size = newLen;
	    }
	    else
	    {
		cout << "Failed to allocate " <<  bufsize << " bytes of memory! " << endl;
		fclose(fp);
		exit(-1);
	    }
        }
        fclose(fp);
    }
    return source;
}

void outputhelp()
{
    printf("Usage : \n\t-enc|-dec <filename> : Encrypt or Decrypt file\n\t-v : Show program version \n");
}

int main(int argc, char* argv[]) {

    std::string password, password2;
    if (argc > 1)
    {
	if (strcmp(argv[1], "-h") == 0 || (strcmp(argv[1], "--help") == 0))
	{
	    outputhelp();
	    exit(0);	
	}
	else if (strcmp(argv[1], "-v") == 0) {
	    cout  << VERSION << endl;
	    exit(0);
	}    
	else if ((argc == 3) && (strcmp(argv[1], "-enc") == 0 || strcmp(argv[1], "-dec") == 0) ) 
	{
	    bool quit = false;
	    
	    if(std::ifstream(argv[2]))
	    {
		while (!quit) 
		{
		    password = getpass("Password:");
		    if (password.length() > 8 && password.length() <= 25) 
		    {
			if (strcmp(argv[1], "-enc") == 0) 
			{
			    // validate password
			    password2 = getpass("Confirm Password:");
			    if (password2.compare(password) == 0) {
				quit = true;
			    } 
			    else 
			    {
				printf("Confirmation of passwords failed. Retry! or ctrl-c to exit\n");
			    }
			} 
			else 
			{
			    quit = true;
			}
		    } 
		    else 
		    {
			printf("Password must be 8 to 25 charecters long\n");
		    }
		}
	    }
	    else
	    {
		cout << "File '" << argv[2] << "' does not exist" << endl;
		exit(0);
	    }
	}
	else 
	{
	    outputhelp();
	    exit(0);
	}
	
	long bufsize = 0;
	std::string file_name;
	file_name.assign(argv[2]);

	// Load the necessary cipher
	EVP_add_cipher(EVP_aes_256_cbc());

	unsigned char key[KEY_SIZE], iv[BLOCK_SIZE];
	const EVP_CIPHER *cipher = EVP_get_cipherbyname("aes-256-cbc");

	password2key(password, cipher, key, iv);

	/* Initialise the library */
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	OPENSSL_config(NULL);

	if (strcmp(argv[1], "-enc") == 0) 
	{
	    int ciphertext_len;
	    long textsize = 0;

	    /* Message to be encrypted */
	    unsigned char *plaintext = (unsigned char *) read_textfile((char *) file_name.c_str(), &textsize);
            if (plaintext == NULL) {
	        cout << "File " << file_name << " Not found!" << endl;
	        exit(-1);
	    }

	    /* Buffer for ciphertext. Ensure the buffer is long enough for the
	    * ciphertext which may be longer than the plaintext, dependant on the
	    * algorithm and mode
	    */
	    unsigned char ciphertext[textsize];
	    try 
	    {
		/* Do something useful with the ciphertext here */
		cout << "Encrypting file ....";
		//BIO_dump_fp(stdout, (const char *) ciphertext, ciphertext_len);

		/* Encrypt the plaintext */
		ciphertext_len = encrypt(plaintext, textsize, key, iv,
                    ciphertext);

		string outfile_name;
		outfile_name.assign(file_name);
		outfile_name.append(".encrypted");
		// write to outfile
		fstream encrypted_file(outfile_name.c_str(), ios::out | ios::binary);
		encrypted_file.write((char *) ciphertext, ciphertext_len);
		cout << "File encrypted into '" << outfile_name << "'\n" << "Done!" << endl;
	    } catch (exception e) {
		std::cerr << "Error occurred: " << e.what() << std::endl;
	    }

	    free(plaintext);
	}
	else if (strcmp(argv[1], "-dec") == 0) 
	{
	    long decryptedtext_len;
	    long encryptedtext_len;
	    cout << "Decrypting file '" << file_name << "'" << " ....";

	    fstream encrypted_file(file_name.c_str(), ios::in | ios::binary);
	    // get size of file
	    encrypted_file.seekg(0, encrypted_file.end);
	    encryptedtext_len = encrypted_file.tellg();
	    encrypted_file.seekg(0);

	    /* Buffer for the decrypted text */
	    unsigned char * encrypted_data = new unsigned char[encryptedtext_len];
	    unsigned char * decryptedtext = new unsigned char[encryptedtext_len];

	    try {
		encrypted_file.read((char*) encrypted_data, encryptedtext_len);
		/* Decrypt the ciphertext */
		decryptedtext_len = decrypt(encrypted_data, encryptedtext_len, key, iv,
                    decryptedtext);

		/* create output file name from the input file name */
		size_t fnlen = file_name.length();
		size_t lastindex = file_name.find_last_of(".");

		string file_name2;
		file_name2.assign(file_name);
		file_name2.replace(fnlen - (fnlen - lastindex), (fnlen - lastindex), ".decrypted");

		fstream decrypted_file(file_name2.c_str(), ios::out | ios::binary);
		decrypted_file.write((char *) decryptedtext, decryptedtext_len);
		cout << endl << decryptedtext_len << " bytes writen to file '" << file_name2 << "'" << endl;
		cout << "Done!\n";

	    } catch (exception e) {
		std::cerr << "Error occurred: " << e.what() << std::endl;
	    }

	    delete encrypted_data;
	    delete decryptedtext;
	}
    }
    else
    {
	outputhelp();
	exit(0);
    }
    /* Clean up */
    EVP_cleanup();
    ERR_free_strings();

    return 0;
}
