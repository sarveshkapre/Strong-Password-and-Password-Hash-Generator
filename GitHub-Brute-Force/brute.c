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

char *hashString(const char *str, int length) 
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


void permute(char *str,int l,int pos,int r);
void swap(char *a,char *b);
void print_string(char *str,int r);
int main()
{
  char str[]="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
  printf("The Following Permuations are possible :");
  permute(str,62,1,16);
  return 0;
}
 
void permute(char *str,int l,int pos,int r)
{
  if(pos==r+1)
  {
      print_string(str,r); 
      printf("\n");
      return; 
  }
  int i;
  for(i=pos-1;i<=l-1;i++)
  {
      str[pos-1]=str[pos-1]+str[i]-(str[i]=str[pos-1]);
      permute(str,l,pos+1,r);
      str[pos-1]=str[pos-1]+str[i]-(str[i]=str[pos-1]);
  }
}
 
void print_string(char *str,int r)
{
  FILE *fp = fopen("log.txt","a+");
  char temp[16]="";
  int i;
  for(i=0;i<r;i++)
   {
      temp[i]=str[i];
   }
     
    char *output = hashString(temp, strlen(temp));
        printf("Alphanumeric Password: %s, Hash Values: %s\n",temp, output);
        
    fprintf(fp,"Alphanumeric Password :  %s  ------------>  Hash Values :  %s",temp,output);
    fprintf(fp,"\n");
    free(output);
    fflush(fp);
    fclose(fp);
  
}
