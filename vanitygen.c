/* vanitygen.c - Super Vanitygen - Vanity Bitcoin address generator */

// Copyright (C) 2016 Byron Stanoszek  <gandalf@winds.org>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to
// deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// IN THE SOFTWARE.

#include "externs.h"

/* Number of secp256k1 operations per batch */
#define STEP 3072

//#include <locale.h>
#include "src/libsecp256k1-config.h"
#include "src/secp256k1.c"
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <time.h>
#include <sys/stat.h>

#define MY_VERSION "0.3"

/* List of public key byte patterns to match */
static struct {
  align8 u8 low[20];   // Low limit
  align8 u8 high[20];  // High limit
} *patterns;

static int num_patterns;
static char fname;
/* Global command-line settings */
static int  max_count=1;
//static bool anycase;
//static bool keep_going;
static bool cntflag=0;
static bool quiet;
static bool verbose;

/* Difficulty (1 in x) */
static double difficulty;

/* Per-thread hash counter */
static u64 *thread_count;
static u64 gen_count;
/* Socket pair for sending up results */
static int sock[2];

/* Static Functions */
static void manager_loop(int threads);
static void announce_result(u64 found, u8 result[168]);
static void search(u64 found, char fname, u8 result[168]);
static unsigned char * read_whole_file (const char * file_name);
static unsigned get_file_size (const char * file_name);
//static bool add_prefix(const char *prefix);
//static bool add_anycase_prefix(const char *prefix);
static double get_difficulty(void);
static void engine(int thread);
//static bool verify_key(const u8 result[82]);
static unsigned char * file_contents;
static unsigned get_file_size (const char * file_name);
static unsigned char * read_whole_file (const char * file_name);
static void tohex(unsigned char * in, size_t insz, char * out, size_t outsz);
/**** Main Program ***********************************************************/

#define parse_arg()     \
  if(argv[i][j+1])      \
    arg=&argv[i][j+1];  \
  else if(i+1 < argc)   \
    arg=argv[++i];      \
  else                  \
    goto no_arg

// Main program entry.
//
int main(int argc, char *argv[])
{
  char *arg;
  int i, j, digits, parent_pid, ncpus=get_num_cpus(), threads=ncpus;
  //setlocale(LC_NUMERIC, "");

  /* Process command-line arguments */
  for(i=1;i < argc;i++) {
    if(argv[i][0] != '-')
      break;
    for(j=1;argv[i][j];j++) {
      switch(argv[i][j]) {
      case 'c':  /* Count */
        parse_arg();
        max_count=max(atoi(arg), 1);
        cntflag=1;
        goto end_arg;
      case 'f':
        parse_arg();
        fname=arg; 
        fprintf(stderr, "%s", fname);
        goto end_arg;
      //case 'i':  /* Case-insensitive matches */
      //  anycase=1;
      //  break;
      //case 'k':  /* Keep going */
      //  keep_going=1;
      //  break;
      case 'q':  /* Quiet */
        quiet=1;
        verbose=0;
        break;
      case 't':  /* #Threads */
        parse_arg();
        threads=RANGE(atoi(arg), 1, ncpus*2);
        goto end_arg;
      case 'v':  /* Verbose */
        quiet=0;
        verbose=1;
        break;
      no_arg:
        fprintf(stderr, "%s: option requires an argument -- '%c'\n", *argv,
                argv[i][j]);
        goto error;
      default:
        fprintf(stderr, "%s: invalid option -- '%c'\n", *argv, argv[i][j]);
      case '?':
      error:
        fprintf(stderr,
                "Usage: %s [options] ...\n"
                "Options:\n"
                "  -c count  Stop after 'count' solutions; default=%d\n"
                "  -q        Be quiet (report solutions in CSV format)\n"
                "  -t num    Run 'num' threads; default=%d\n"
                "  -v        Be verbose\n\n",
                *argv, max_count, threads);
        fprintf(stderr, "Super Collider v" MY_VERSION "\n");
        return 1;
      }
    }
    end_arg:;
  }

  /* Auto-detect fastest SHA-256 function to use */
  sha256_register(verbose);

  // Convert specified prefixes into a global list of public key byte patterns.
  /*
  for(;i < argc;i++)
    if((!anycase && !add_prefix(argv[i])) ||
       (anycase && !add_anycase_prefix(argv[i])))
      return 1;
  if(!num_patterns)
    goto error;
    */

  /* List patterns to match */
 /*
  if(verbose) {
    digits=(num_patterns > 999)?4:(num_patterns > 99)?3:(num_patterns > 9)?2:1;
    for(i=0;i < num_patterns;i++) {
      printf("P%0*d High limit: ", digits, i+1);
      for(j=0;j < 20;j++)
        printf("%02x", patterns[i].high[j]);
      printf("\nP%0*d Low limit:  ", digits, i+1);
      for(j=0;j < 20;j++)
        printf("%02x", patterns[i].low[j]);
      printf("\n");
    }
    printf("---\n");
  }
*/
/*  difficulty=get_difficulty();
  if(difficulty < 1)
    difficulty=1;
  if(!quiet)
    fprintf(stderr, "Difficulty: %.0f\n", difficulty);
*/  
//    file_contents = read_whole_file ("/media/root/EVOSSD1TB/addresses3");

   // free (file_contents);
  // Create memory-mapped area shared between all threads for reporting hash
  // counts.
  thread_count=mmap(NULL, threads*sizeof(u64), PROT_READ|PROT_WRITE,
                    MAP_SHARED|MAP_ANONYMOUS|MAP_LOCKED, -1, 0);
  if(thread_count == MAP_FAILED) {
    perror("mmap");
    return 1;
  }

  /* Create anonymous socket pair for children to send up solutions */
  if(socketpair(AF_UNIX, SOCK_DGRAM, 0, sock)) {
    perror("socketpair");
    return 1;
  }

  /* Ignore signals */
  signal(SIGPIPE, SIG_IGN);
  signal(SIGCHLD, SIG_IGN);

  /* Fork off the child processes */
  parent_pid=getpid();
  for(i=0;i < threads;i++) {
    if(!fork()) {
      /* In the child... */

      /* Close the read end of the socketpair */
      close(sock[0]);

      /* Kill child process whenever parent process dies */
      prctl(PR_SET_PDEATHSIG, SIGTERM);
      if(getppid() != parent_pid)
        return 0;  /* Parent process already died */

      /* Run hashing engine */
      engine(i);
      return 0;
    }
  }

  /* Close the write end of the socketpair */
  close(sock[1]);

  manager_loop(threads);
  return 1;
}

// Parent process loop, which tracks hash counts and announces new results to
// standard output.
//
static void manager_loop(int threads)
{
  //static const int targets[]={50, 75, 80, 90, 95};
  //static const int units[]={31536000, 86400, 3600, 60, 1};
  //static const char units_str[]="ydhms";

  fd_set readset;
  struct timeval tv={1, 0};
  time_t t; 
    t = time(NULL);
  char msg[256];
  u8 result[168];
  u64 prev=0, last_result=0, count, avg=0, count_avg[8], found=0;
  int i, j, ret, len, count_index=0, count_max=0;
  double prob, secs, secperMkey;
    FD_ZERO(&readset);

  while(1) {
  
    /* Wait up to 1 second for hashes to be reported */
    FD_SET(sock[0], &readset);
    if((ret=select(sock[0]+1, &readset, NULL, NULL, quiet?NULL:&tv)) == -1) {
      perror("select");
      return;
    }

    if(ret) {
      /* Read the (PubKey,PubKey,PrivKey) tuple from the socket */
      if((len=read(sock[0], result, 168)) != 168) {
        /* Datagram read wasn't 168 bytes; ignore message */
        if(len != -1)
          continue;

        /* Something went very wrong if this happens; exit */
        perror("read");
        return;
      }

      announce_result(++found, result);

      /* Reset hash count */
      for(i=0,count=0;i < threads;i++)
        count += thread_count[i];
      last_result=count;
      continue;
    }

    /* Reset the select() timer */
    tv.tv_sec=2, tv.tv_usec=0;
if (!quiet){
    avg = found - avg;
    sprintf(msg, "[%'llu key/s]", (avg)); //multiplied as we announce 2 key
    avg = found;

    /* Display match count */
    //if(found) {

    // if(!keep_going && max_count > 1)
    //   sprintf(msg+strlen(msg), "[Found %d of %d]", found, max_count);
    // else
        sprintf(msg+strlen(msg), "[Generated %'llu Mkey]", (found*2/1000000));
    //}

    fprintf(stderr, "\r%-78.78s", msg);
    fflush(stderr);
    }
  }
}

static void announce_result(u64 found, u8 result[168])
{
    char str[64];
    
    tohex(result+72, 32, str, 64);
    printf("%s %s\n", result, str);
    printf("%s %s\n", result+35, str);
  
  if(cntflag && found >= max_count)
    exit(0);
   
}

// Calculate the difficulty of finding a match from the pattern list, where
// difficulty = 1/{valid pattern space}.
//
static double get_difficulty()
{
  u32 total[5]={}, *low, *high;
  u64 temp;
  double freq;
  int i, j;

  /* Loop for each pattern */
  for(i=0;i < num_patterns;i++) {
    low=(u32 *)patterns[i].low;
    high=(u32 *)patterns[i].high;

    /* total += high-low */
    for(j=4,temp=0;j >= 0;j--) {
      temp += (u64)total[j]+be32(high[j])+(~be32(low[j])+(j == 4));
      total[j]=temp;
      temp >>= 32;
    }
  }

  /* Add up fractions, from least significant to most significant */
  freq  = total[4] / 1461501637330902918203684832716283019655932542976.0;
  freq += total[3] / 340282366920938463463374607431768211456.0;
  freq += total[2] / 79228162514264337593543950336.0;
  freq += total[1] / 18446744073709551616.0;
  freq += total[0] / 4294967296.0;

  return 1/freq;
}

/**** Hash Engine ************************************************************/

// Per-thread entry point.
//
static void engine(int thread)
{

  secp256k1_context *sec_ctx;
  
  u8 seckey[32];  /*DC 8A 0D 54 E4 B5 54 1B 0E F4 E3 F2 92 49 56 DC 36 49 1C E5 0B 1A 41 98 BD D6 EB 42 D4 3D 88 93*/
  align8 u8 public_key64[65];
  align8 u8 public_key32[33];
  u8 hash1[65], hash2[33];
  size_t pk_len = 65;
  size_t pk_len2 = 33;
  align8 u8 sha_block[64], rmd_block[64], result[168];
  align8 u8 cksum_block[64], checksum[32], wif[68], wif2[68];
  u64 *pkey=(u64 *)seckey; /*DC8A0D54E4B5541B 0EF4E3F2924956DC 36491CE50B1A4198 BDD6EB42D43D8893*/
  int i;
  align8 u8 rmd[5 + RIPEMD160_DIGEST_LENGTH];
  align8 u8 rmd2[5 + RIPEMD160_DIGEST_LENGTH];
  /* Set CPU affinity for this thread# (ignore any failures) */
  set_working_cpu(thread);
  /* Set context*/
  sec_ctx=secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
  secp256k1_pubkey pubkey;

/* Azzera priv key*/
 /*
  for (i = 0; i < 32; i++) {
	  seckey[i]=0x0;
	  seckey[24]=0xFF;
	  seckey[25]=0xFF;
	  seckey[26]=0xFF;
	  seckey[27]=0xFF;
	  seckey[28]=0xFF;
	  seckey[29]=0xFF;
	  seckey[30]=0xFF;
	  seckey[31]=0xFE;
    }
 */
  
  /* Load private key (seckey) from random bytes */
  FILE *frand = fopen("/dev/urandom", "r");
    fread(seckey, 32, 1, frand);
    fclose(frand);
    if (frand == NULL) {
        fprintf(stderr, "Failed to read /dev/urandom\n");
        return 0;
    }

  rekey:

    pkey[0]=be64(pkey[0]);
    pkey[1]=be64(pkey[1]);
    pkey[2]=be64(pkey[2]);
    pkey[3]=be64(pkey[3]);
    if (pkey[3] == 0xFFFFFFFFFFFFFFFF) pkey[2]++;
    ++pkey[3];
    if (pkey[3] == 0xFFFFFFFFFFFFFFFF && pkey[2] == 0xFFFFFFFFFFFFFFFF) ++pkey[1];
    if (pkey[3] == 0xFFFFFFFFFFFFFFFF && pkey[2] == 0xFFFFFFFFFFFFFFFF && pkey[1] == 0xFFFFFFFFFFFFFFFF) ++pkey[0];
    if (pkey[2] == 0xFFFFFFFFFFFFFFFF) ++pkey[1];
    pkey[3]=be64(pkey[3]);
    pkey[2]=be64(pkey[2]);
    pkey[1]=be64(pkey[1]);
    pkey[0]=be64(pkey[0]);

  /* Main Loop */

  printf("\r");  // This magically makes the loop faster by a smidge
    
  while(1) {
    thread_count[thread]++;
    /* Verify secret key is valid */
    if (!secp256k1_ec_seckey_verify(sec_ctx, seckey)) {
        fprintf(stderr, "Invalid secret key. ");
    }

    /* Create Public Key */
    if (!secp256k1_ec_pubkey_create(sec_ctx, &pubkey, seckey)) {
        fprintf(stderr, "Failed to create public key\n");
        goto rekey;
    }

    secp256k1_ec_pubkey_serialize(
      sec_ctx,
      public_key64,
      &pk_len,
      &pubkey,
      SECP256K1_EC_UNCOMPRESSED
    );
  
  RIPEMD160(SHA256(public_key64, 65, 0), SHA256_DIGEST_LENGTH, rmd + 1);
  memcpy(rmd + 21, SHA256(SHA256(rmd, 21, 0), SHA256_DIGEST_LENGTH, 0), 4);

    secp256k1_ec_pubkey_serialize(
        sec_ctx,
        public_key32,
        &pk_len2,
        &pubkey,
        SECP256K1_EC_COMPRESSED
    );

  RIPEMD160(SHA256(public_key32, 33, 0), SHA256_DIGEST_LENGTH, rmd2 + 1);
  memcpy(rmd2 + 21, SHA256(SHA256(rmd2, 21, 0), SHA256_DIGEST_LENGTH, 0), 4);

  b58enc(wif, rmd, 25);
  b58enc(wif2, rmd2, 25);

/*----------------    
    if((strstr(file_contents, wif)) != NULL) {
			//printf("A match found on line: %d\n", line_num);
    memcpy(result, wif, 68);
    memcpy(result+68, wif2, 68);
    memcpy(result+136, seckey, 32);
    if(write(sock[1], result, 168) != 168)
      return;
			//find_result++;
		}
	if((strstr(file_contents, wif2)) != NULL) {
			//printf("A match found on line: %d\n", line_num);
    memcpy(result, wif, 68);
    memcpy(result+68, wif2, 68);
    memcpy(result+136, seckey, 32);
    if(write(sock[1], result, 168) != 168)
      return;
			//find_result++;
		}
-----------------*/		

    memcpy(result, wif, 35);
    memcpy(result+35, wif2, 35);
    memcpy(result+72, seckey, 32);
    //memcpy(result+102, "\0", 1);
    if(write(sock[1], result, 168) != 168)
      return;

    /* Pick a new random starting private key */
      goto rekey;
  }
}

/*
static unsigned get_file_size (const char * file_name)
{
    struct stat sb;
    if (stat (file_name, & sb) != 0) {
        fprintf (stderr, "'stat' failed for '%s': %s.\n",
                 file_name, strerror (errno));
        exit (EXIT_FAILURE);
    }
    return sb.st_size;
}

/* This routine reads the entire file into memory. */
/*
static unsigned char * read_whole_file (const char * file_name)
{
    unsigned s;
    unsigned char * contents;
    FILE * f;
    size_t bytes_read;
    int status;

    s = get_file_size (file_name);
    contents = malloc (s + 1);
    if (! contents) {
        fprintf (stderr, "Not enough memory.\n");
        exit (EXIT_FAILURE);
    }

    f = fopen (file_name, "r");
    if (! f) {
        fprintf (stderr, "Could not open '%s': %s.\n", file_name,
                 strerror (errno));
        exit (EXIT_FAILURE);
    }
    bytes_read = fread (contents, sizeof (unsigned char), s, f);
    if (bytes_read != s) {
        fprintf (stderr, "Short read of '%s': expected %d bytes "
                 "but got %d: %s.\n", file_name, s, bytes_read,
                 strerror (errno));
        exit (EXIT_FAILURE);
    }
    status = fclose (f);
    if (status != 0) {
        fprintf (stderr, "Error closing '%s': %s.\n", file_name,
                 strerror (errno));
        exit (EXIT_FAILURE);
    }
    return contents;
}
*/
void tohex(unsigned char * in, size_t insz, char * out, size_t outsz)
{
    unsigned char * pin = in;
    const char * hex = "0123456789ABCDEF";
    char * pout = out;
    for(; pin < in+insz; pout +=2, pin++){
        pout[0] = hex[(*pin>>4) & 0xF];
        pout[1] = hex[ *pin     & 0xF];
        if (pout + 2 - out > outsz){
            /* Better to truncate output string than overflow buffer */
            /* it would be still better to either return a status */
            /* or ensure the target buffer is large enough and it never happen */
            break;
        }
    }
    //pout[outsz+1] = 0;
}


