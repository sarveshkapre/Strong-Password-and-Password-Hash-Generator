#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto.h"


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
  char temp[17];
  memset(temp, 0, sizeof(temp));
  int i;
  for(i=0;i<r && i<16;i++)
  {
    temp[i]=str[i];
  }
     
    char hash_hex[64 * 2 + 1];
    if (crypto_digest_hex(CRYPTO_ALGO_SHA256, (const uint8_t *)temp, strlen(temp),
                          hash_hex, sizeof(hash_hex)) != 0) {
      fprintf(stderr, "Hashing failed.\n");
      if (fp)
        fclose(fp);
      return;
    }
    printf("Alphanumeric Password: %s, Hash Values: %s\n",temp, hash_hex);
        
    if (fp) {
      fprintf(fp,"Alphanumeric Password :  %s  ------------>  Hash Values :  %s\n",temp,hash_hex);
      fflush(fp);
      fclose(fp);
    }
  
}
