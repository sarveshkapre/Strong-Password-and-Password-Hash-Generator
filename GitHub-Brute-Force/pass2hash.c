#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(__APPLE__)
#define COMMON_DIGEST_FOR_OPENSSL
#include <CommonCrypto/CommonDigest.h>
#define SHA1 CC_SHA1
#else
#include <openssl/md5.h>
#endif

char *hashStr(const char *str, int length) 
{
    int n;
    MD5_CTX c;
    unsigned char digest[16];
    char *hash = (char*)malloc(33);

    MD5_Init(&c);

    while (length > 0) 
    {
        if (length > 512) 
	{
            MD5_Update(&c, str, 512);
        }
	else 
	{
            MD5_Update(&c, str, length);
        }
	
        length -= 512;
        str += 512;
    }

    MD5_Final(digest, &c);

    for (n = 0; n < 16; ++n) 
    {
        snprintf(&(hash[n*2]), 16*2, "%02x", (unsigned int)digest[n]);
    }

    return hash;
}


int main()
{
   FILE *fp1,*fp2;
   char str[60];

   /* opening file for reading */
   fp1 = fopen("passwordfile.txt" , "r"); //Instead of passwordfile.txt...replace it with a name of file which contains the passwords

   
while (!feof(fp1))
 {
   if(fp1 == NULL) 
   {
      perror("Error opening file");
      return(-1);
   }
   if( fgets (str, 60, fp1)!=NULL ) 
   {
      /* writing content to stdout */
      
      char *output = hashStr(str, strlen(str));
        printf("Password: %s Hash: %s\n",str, output);
        float entropy;
        //password using alphanumeric and uppercase characters would be represented as log2(62) ≈ 5.95419631039 bits of entropy per character
 	//entropy of password = 5.95419631039 x strlen(str)
        entropy= 5.95419631039*strlen(str);
	printf("Entropy of this password is : %f\n\n",entropy);
	fp2 = fopen("HashofPassword.txt","a+");

   	fprintf(fp2,"Password :  %s  ------------>  Hash Values :  %s -----------> Entropy : %f",str,output,entropy);
        fprintf(fp2,"\n");

        
   }
 }
   fclose(fp1);
   
   return(0);
}
