/* uuide_hash.c
 *
 * Standalone UUID-E generation utility that returns the uuid_gen_mac_addr
 * UUID-E for a MAC provided on the command line.
 *
 *
 * Requires libopenssl-dev[el]
 *
 * Compile with 
 *
 * gcc uuide_hash.c -lssl -lcrypto -o uuide_hash
 *
 * For single MAC hash, invoke like: 
 * 
 * ./uuide_hash -m 00:11:22:33:44:55
 *
 * Prints MAC\tUUID-E to stdout
 *
 * For bulk MAC hashes, invoke like:
 *
 * ./uuide_hash -b mac_file
 *
 * where mac_file is a file of newline-delimited MAC addresses
 *
 * Prints MAC\tUUID-E pairs to stdout
 *
 * To generate all MACs and hashes for a particular OUI, 
 *
 * ./uuide_hash -O 00:11:23 
 *
 * Prints MAC\tUUID-E pairs for all MACs in the OUI to stdout
 *
 */
#include <stdio.h>
#include <linux/types.h>
#include <openssl/sha.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <ctype.h>
#include <unistd.h>

#define SHA1_MAC_LEN 20
#define UUID_LEN 16
#define ETH_ALEN 6

int sha1_vector(size_t num_elem, const uint8_t *addr[], const size_t *len, uint8_t *mac)
{
    SHA_CTX ctx;
    size_t i;

    SHA1_Init(&ctx);
    for (i = 0; i < num_elem; i++)
        SHA1_Update(&ctx, addr[i], len[i]);
    SHA1_Final(mac, &ctx);
    return 0;
}

void uuid_gen_mac_addr(const uint8_t *mac_addr, uint8_t *uuid)
{
  const uint8_t *addr[2];
  size_t len[2];
  uint8_t hash[SHA1_MAC_LEN];
  uint8_t nsid[16] = {
  0x52, 0x64, 0x80, 0xf8,
  0xc9, 0x9b,
  0x4b, 0xe5,
  0xa6, 0x55,
  0x58, 0xed, 0x5f, 0x5d, 0x60, 0x84
  };

  addr[0] = nsid;
  len[0] = sizeof(nsid);
  addr[1] = mac_addr;
  len[1] = 6;
  sha1_vector(2, addr, len, hash);
  memcpy(uuid, hash, 16);

  /* Version: 5 = named-based version using SHA-1 */
  uuid[6] = (5 << 4) | (uuid[6] & 0x0f);

  /* Variant specified in RFC 4122 */
  uuid[8] = 0x80 | (uuid[8] & 0x3f);
}

static int hex2num(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}


int hex2byte(const char *hex)
{
    int a, b;
    a = hex2num(*hex++);
    if (a < 0) 
        return -1;
    b = hex2num(*hex++);
    if (b < 0) 
        return -1;
    return (a << 4) | b;
}

static const char * hwaddr_parse(const char *txt, uint8_t *addr)
{
    size_t i;
    for (i = 0; i < ETH_ALEN; i++) {
        int a;

        a = hex2byte(txt);
        if (a < 0)
            return NULL;
        txt += 2;
        addr[i] = a;
        if (i < ETH_ALEN - 1 && *txt++ != ':')
            return NULL;
    }
    return txt;
}

static const char * oui_parse(const char *txt, uint8_t *oui)
{
    size_t i;
    for (i = 0; i < ETH_ALEN/2; i++) {
        int a;

        a = hex2byte(txt);
        if (a < 0)
            return NULL;
        txt += 2;
        oui[i] = a;
        if (i < ETH_ALEN/2 - 1 && *txt++ != ':')
            return NULL;
    }
    return txt;
}

void * usage(void) 
{
  printf("uuide_hash -- a MAC to UUID-E conversion utility\n\n"
         "Usage: ./uuide_hash [-h] ([-m MAC_ADDRESS] | [-b MAC_FILE]"
         " | [-O OUI])\n\n                                          \n"
         "-h                       prints this help message\n" 
         "-m                       (m)AC address. Single MAC mode accepts\n" 
         "                         one MAC address as an argument. Prints\n"
         "                         MAC address - UUID-E pait to stdout\n"
         "-b                       (b)ulk mode. Reads a file of newline-\n" 
         "                         delimited MAC addresses, and prints the\n"
         "                         MAC address - UUID-E pairs one per line\n" 
         "-O                       (O)UI mode. Accepts an OUI as a command-\n"
         "                         line argument, and prints all MAC address\n"
         "                         UUID-E pairs for every MAC in the OUI\n"
         "-B                       (B)inary mode. Prints raw binary rather\n"
         "                         than ASCII\n"
      );

}

int main(int argc, char * argv[])
{

  int n;
  int bin = 0;
  char *strmac = NULL;
  char *macfile = NULL;
  char *oui = NULL;

  if (argc < 2) {
    usage();
    exit(1);
  }

  while ((n = getopt (argc, argv, "Bhm:b:O:")) != -1)
    switch (n)
      {
      case 'h':
        usage();
        break;
      case 'm':
        strmac = optarg;
        break;
      case 'b':
        macfile = optarg;
        break;
      case 'O':
        oui = optarg;
        break;
      case 'B':
        bin = 1;
        break;
      case '?':
        if (isprint (optopt))
          fprintf (stderr, "Unknown option `-%c'.\n", optopt);
          
        else
          fprintf (stderr,
                   "Unknown option character `\\x%x'.\n",
                   optopt);
        usage();
        
        return 1;
      default:
        usage();
      }

  if ((NULL != strmac) && (NULL != macfile) || ((NULL != strmac) && 
        (NULL != oui)) || ((NULL != macfile) && (NULL != oui))){
    fprintf(stderr, "Error: Only one of -m, -b, and -O may be specified.\n");
    usage();
    exit(1);
  }

  if (strmac) {  
    uint8_t mac[ETH_ALEN];
    int ret;

    ret = hwaddr_parse(strmac, mac) ? 0 : 1;
    if (ret) {
      fprintf(stderr, "Error: %s is not a valid MAC address.\n", strmac);
      exit(1);
    }
    uint8_t uuid[16];

    uuid_gen_mac_addr(mac, uuid);
    if (bin)
      fwrite(mac, 1, ETH_ALEN, stdout);
    else
      printf("%s\t", strmac);

    if (bin){
      fwrite(uuid, 1, UUID_LEN, stdout);
    }
    else {
      for (int i = 0; i < UUID_LEN; i++){
        printf("%02x", uuid[i]);
      }
        printf("\n");
    }

  }
  else if (macfile) {
    size_t len = 0;
    ssize_t read;
    FILE * f = NULL;
    char *line = NULL;
    uint8_t mac[ETH_ALEN];

    if (NULL == (f = fopen(macfile, "r"))) {
      perror("fopen");
    }

    while ((read = getline(&line, &len, f)) != -1) {
      int ret;
      line[strcspn(line, "\n")] = 0;
      ret = hwaddr_parse(line, mac) ? 0 : 1;
      if (ret) {
        fprintf(stderr, "Error: %s is not a valid MAC address.\n", line);
        exit(1);
      }
      uint8_t uuid[16];

      uuid_gen_mac_addr(mac, uuid);
      if (bin)
        fwrite(mac, 1, ETH_ALEN, stdout);
      else
        printf("%s\t", line);


      if (bin){
        fwrite(uuid, 1, UUID_LEN, stdout);
      }
      else {
        for (int i = 0; i < UUID_LEN; i++){
          printf("%02x", uuid[i]);
        }
          printf("\n");
      }
    }
    fclose(f);
  }

  else if (oui) {
    int8_t ret;
    uint8_t ouibuf[ETH_ALEN];

    ret  = oui_parse(oui, ouibuf) ? 0 : 1;

    if (ret) {
      fprintf(stderr, "OUI %s is invalid\n", oui);
      exit(1);
    }

    ouibuf[3] = 0;
    for (int i = 0; i < 256; i++){
      ouibuf[4] = 0;
      for (int j = 0; j < 256; j++){
        ouibuf[5] = 0;
        for (int k = 0; k < 256; k++){
            char strmac[30];
            uint8_t mac[ETH_ALEN];
            uint8_t uuid[16];

            snprintf(strmac, 30, "%02x:%02x:%02x:%02x:%02x:%02x", 
                ouibuf[0],ouibuf[1],ouibuf[2],ouibuf[3],ouibuf[4],ouibuf[5]);
            //for (int a = 0; a < 6; a++)
            //  printf("%02x ", ouibuf[a]);
            
            ret = hwaddr_parse(strmac, mac) ? 0 : 1;
            if (ret) {
              fprintf(stderr, "Error: %s is not a valid MAC address.\n", strmac);
              exit(1);
            }
             
            if (bin)
              fwrite(mac, 1, ETH_ALEN, stdout);
            else
              printf("%s\t", strmac);
            uuid_gen_mac_addr(mac, uuid);

            if (bin){
              fwrite(uuid, 1, UUID_LEN, stdout);
            }
            else {
              for (int i = 0; i < UUID_LEN; i++){
                printf("%02x", uuid[i]);
              }
                printf("\n");
            }

            ouibuf[5]++;
        }
        ouibuf[4]++;
      }
      ouibuf[3]++;
    }


  }

  return 0;
}
