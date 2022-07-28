#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h> 
#include <sys/select.h>
#include <sys/time.h>
#include <errno.h>
#include <stdarg.h>

/* buffer for reading from tun/tap interface, must be >= 1500 */
#define BUFSIZE 2000   
#define CLIENT 0
#define SERVER 1
#define PORT 55555

int debug;
char *progname;

/**************************************************************************
 * tun_alloc: allocates or reconnects to a tun/tap device. The caller     *
 *            must reserve enough space in *dev.                          *
 **************************************************************************/
int tun_alloc(char *dev, int flags) {

  struct ifreq ifr;
  int fd, err;
  char *clonedev = "/dev/net/tun";

  if( (fd = open(clonedev , O_RDWR)) < 0 ) {
    perror("Opening /dev/net/tun");
    return fd;
  }

  memset(&ifr, 0, sizeof(ifr));

  ifr.ifr_flags = flags;

  if (*dev) {
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
  }

  if( (err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0 ) {
    perror("ioctl(TUNSETIFF)");
    close(fd);
    return err;
  }

  strcpy(dev, ifr.ifr_name);

  return fd;
}

/**************************************************************************
 * cread: read routine that checks for errors and exits if an error is    *
 *        returned.                                                       *
 **************************************************************************/
int cread(int fd, char *buf, int n){
  
  int nread;

  if((nread=read(fd, buf, n)) < 0){
    perror("Reading data");
    exit(1);
  }
  return nread;
}

/**************************************************************************
 * cwrite: write routine that checks for errors and exits if an error is  *
 *         returned.                                                      *
 **************************************************************************/
int cwrite(int fd, char *buf, int n){
  
  int nwrite;

  if((nwrite=write(fd, buf, n)) < 0){
    perror("Writing data");
    exit(1);
  }
  return nwrite;
}

/**************************************************************************
 * read_n: ensures we read exactly n bytes, and puts them into "buf".     *
 *         (unless EOF, of course)                                        *
 **************************************************************************/
int read_n(int fd, char *buf, int n) {

  int nread, left = n;

  while(left > 0) {
    if ((nread = cread(fd, buf, left)) == 0){
      return 0 ;      
    }else {
      left -= nread;
      buf += nread;
    }
  }
  return n;  
}

/**************************************************************************
 * do_debug: prints debugging stuff (doh!)                                *
 **************************************************************************/
void do_debug(char *msg, ...){
  
  va_list argp;
  
  if(debug) {
	va_start(argp, msg);
	vfprintf(stderr, msg, argp);
	va_end(argp);
  }
}

/**************************************************************************
 * my_err: prints custom error messages on stderr.                        *
 **************************************************************************/
void my_err(char *msg, ...) {

  va_list argp;
  
  va_start(argp, msg);
  vfprintf(stderr, msg, argp);
  va_end(argp);
}

/**************************************************************************
 * usage: prints usage and exits.                                         *
 **************************************************************************/
void usage(void) {
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "%s -i <ifacename> [-s|-c <serverIP>] [-p <port>] [-u|-a] [-d]\n", progname);
  fprintf(stderr, "%s -h\n", progname);
  fprintf(stderr, "\n");
  fprintf(stderr, "-i <ifacename>: Name of interface to use (mandatory)\n");
  fprintf(stderr, "-s|-c <serverIP>: run in server mode (-s), or specify server address (-c <serverIP>) (mandatory)\n");
  fprintf(stderr, "-p <port>: port to listen on (if run in server mode) or to connect to (in client mode), default 55555\n");
  fprintf(stderr, "-u|-a: use TUN (-u, default) or TAP (-a)\n");
  fprintf(stderr, "-d: outputs debug information while running\n");
  fprintf(stderr, "-h: prints this help text\n");
  fprintf(stderr, "Auth Status: \n");
  fprintf(stderr, "R00: Both Username and Password incorrect\n");
  fprintf(stderr, "R01: Username incorrect\n");
  fprintf(stderr, "R10: Password incorrect\n");
  fprintf(stderr, "R11: All correct\n");
  exit(1);
}

int main(int argc, char *argv[]) {
  
  int tap_fd, option;
  int flags = IFF_TUN;
  char if_name[IFNAMSIZ] = "";
  int maxfd;
  uint16_t nread, nwrite, plength;
  char buffer[BUFSIZE];
  struct sockaddr_in local, remote;
  char remote_ip[16] = "";            /* dotted quad IP string */
  unsigned short int port = PORT;
  int sock_fd, net_fd, optval = 1;
  socklen_t remotelen;
  int cliserv = -1;    /* must be specified on cmd line */
  unsigned long int tap2net = 0, net2tap = 0;
   
  /*Use for username/password authentication*/ 
  int Verification_State = -1;
  char C_Username[256], C_Password[256];
  char S_Username[256], S_Password[256]; 
  char C_Response[256], S_Response[256];
  FILE *ConfigFile = NULL;
  int CheckUsername_flg = 0, CheckPassword_flg = 0;
  char AuthResult_00[10] = "R00";
  char AuthResult_01[10] = "R01";
  char AuthResult_02[10] = "R02";
  char AuthResult_03[10] = "R03";

  progname = argv[0];
  
  /* Check command line options */
  while((option = getopt(argc, argv, "i:sc:p:uahdw:")) > 0) {
    switch(option) {
      case 'd':
        debug = 1;
        break;
      case 'h':
        usage();
        break;
      case 'i':
        strncpy(if_name,optarg, IFNAMSIZ-1);
        break;
      case 's':
        cliserv = SERVER;
        break;
      case 'c':
        cliserv = CLIENT;
        strncpy(remote_ip,optarg,15);
        break;
      case 'p':
        port = atoi(optarg);
        break;
      case 'u':
        flags = IFF_TUN;
        break;
      case 'a':
        flags = IFF_TAP;
        break;
      default:
        my_err("Unknown option %c\n", option);
        usage();
    }
  }

  argv += optind;
  argc -= optind;

  if(argc > 0) {
    my_err("Too many options!\n");
    usage();
  }

  if(*if_name == '\0') {
    my_err("Must specify interface name!\n");
    usage();
  } else if(cliserv < 0) {
    my_err("Must specify client or server mode!\n");
    usage();
  } else if((cliserv == CLIENT)&&(*remote_ip == '\0')) {
    my_err("Must specify server address!\n");
    usage();
  }

  /* initialize tun/tap interface */
  if ( (tap_fd = tun_alloc(if_name, flags | IFF_NO_PI)) < 0 ) {
    my_err("Error connecting to tun/tap interface %s!\n", if_name);
    exit(1);
  }

  do_debug("Successfully connected to interface %s\n", if_name);

  if ( (sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    perror("socket()");
    exit(1);
  }

  if(cliserv == CLIENT) {
    /* Client, try to connect to server */

    /* assign the destination address */
    memset(&remote, 0, sizeof(remote));
    remote.sin_family = AF_INET;
    remote.sin_addr.s_addr = inet_addr(remote_ip);
    remote.sin_port = htons(port);

    /* connection request */
    if (connect(sock_fd, (struct sockaddr*) &remote, sizeof(remote)) < 0) {
      perror("connect()");
      exit(1);
    }

    net_fd = sock_fd;
    do_debug("CLIENT: Connected to server %s\n", inet_ntoa(remote.sin_addr));

    Verification_State = 1;

    if(Verification_State == 1){
      /*Client ask user to enter username & password*/
      printf("Please enter the Username : ");
      scanf("%s", C_Username);
      printf("Please enter the Password : ");
      scanf("%s", C_Password);


      /*Client send user Username to Server*/
      if (send(net_fd, C_Username, strlen(C_Username), 0) < 0) {
        perror("send()");
        exit(1);
      }
      /*Client wait Server response*/
      while (recv(net_fd, S_Response, sizeof(S_Response), 0) < 0){
      }
      if(strcmp("Finished", S_Response) == 1){
        perror("Unknown Error");
        exit(1);
      }
     
      memset(C_Response, 0, sizeof(C_Response));
      memset(S_Response, 0, sizeof(S_Response));

      /*Client send user Username to Server*/
      if (send(net_fd, C_Password, strlen(C_Password), 0) < 0) {
        perror("send()");
        exit(1);
      }
      /*Client wait Server response*/
      while (recv(net_fd, S_Response, sizeof(S_Response), 0) < 0){
      }
      if(strcmp("Finished", S_Response) == 1){
        perror("Unknown Error");
        exit(1);
      }

      memset(C_Response, 0, sizeof(C_Response));
      memset(S_Response, 0, sizeof(S_Response));

      /*Client ask verification result*/
      snprintf(C_Response, sizeof(C_Response), "%s", "Finish");
      if (send(net_fd, C_Response, strlen(C_Response), 0) < 0) {
        perror("send()");
        exit(1);
      }

      /*Client receive verification result*/
      while (recv(net_fd, S_Response, sizeof(S_Response), 0) < 0){
      }
      if(strcmp(AuthResult_03, S_Response) == 0){
        printf("Pass Verification!\n");
      }
      else {
        printf("Connection failed! Didn't pass authentication process!(Status: %s)\n", S_Response);
        exit(1);
      }

    }

  } else {
    /* Server read config file*/
    ConfigFile = fopen("ServerConfig.txt", "r");

    int counter = 0;
    while (counter < 2) {
      if(counter == 0) {
        if(fscanf(ConfigFile, "Username=%s\n", S_Username) == 1)
        {
          printf("Found Username in config file: %s\n", S_Username);
        }
      }
      else if (counter == 1) {
        if(fscanf(ConfigFile, "Password=%s\n", S_Password) == 1)
        {
          printf("Found Password in config file: %s\n", S_Password);
        }
      }
      counter++;
    }

    fclose(ConfigFile);


    /* Server, wait for connections */

    /* avoid EADDRINUSE error on bind() */
    if(setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&optval, sizeof(optval)) < 0) {
      perror("setsockopt()");
      exit(1);
    }
    
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_ANY);
    local.sin_port = htons(port);
    if (bind(sock_fd, (struct sockaddr*) &local, sizeof(local)) < 0) {
      perror("bind()");
      exit(1);
    }
    
    if (listen(sock_fd, 5) < 0) {
      perror("listen()");
      exit(1);
    }
    
    /* wait for connection request */
    remotelen = sizeof(remote);
    memset(&remote, 0, remotelen);
    if ((net_fd = accept(sock_fd, (struct sockaddr*)&remote, &remotelen)) < 0) {
      perror("accept()");
      exit(1);
    }

    do_debug("SERVER: Client connected from %s\n", inet_ntoa(remote.sin_addr));

    Verification_State = 1;

    if(Verification_State == 1){
      /*Server wait client send Username*/
      while (recv(net_fd, C_Response, sizeof(C_Response), 0) < 0){
      }
    
      /*Server compare client's Username.*/
      if(strcmp(S_Username, C_Response) == 0){
        //snprintf(S_Response, sizeof(S_Response), "%s", "Success");
        printf("UserName Correct!\n");
        CheckUsername_flg = 1;
      }
      else{
        printf("UserName Incorrect!\n");
        printf("Incorrect detailed: [%s] vs [%s]\n", S_Username, C_Response);
      }
      /*Server send result to client*/
      snprintf(S_Response, sizeof(S_Response), "%s", "Finished");
      if (send(net_fd, S_Response, strlen(S_Response), 0) < 0) {
        perror("send()");
        exit(1);
      }
      memset(C_Response, 0, sizeof(C_Response));
      memset(S_Response, 0, sizeof(S_Response));

      /*Server wait client send Password*/
      while (recv(net_fd, C_Response, sizeof(C_Response), 0) < 0){
      }
      /*Server compare client's Password*/
      if(strcmp(S_Password, C_Response) == 0){
        printf("Password Correct!\n");
        CheckPassword_flg = 1;
      }
      else{
        printf("Password Incorrect!\n");
        printf("Incorrect detailed: [%s] vs [%s]\n", S_Password, C_Response);
      }
      /*Server send result to client*/
      snprintf(S_Response, sizeof(S_Response), "%s", "Finished");
      if (send(net_fd, S_Response, strlen(S_Response), 0) < 0) {
        perror("send()");
        exit(1);
      }
      memset(C_Response, 0, sizeof(C_Response));
      memset(S_Response, 0, sizeof(S_Response));

      /*Server wait client send Password*/
      int finish_flg = 0;
      while (recv(net_fd, C_Response, sizeof(C_Response), 0) < 0 && finish_flg == 0){
        if(strcmp("Finish", C_Response) == 0){
          finish_flg = 1;
        }
      }

      /*Server send verification result to client */
      if(CheckUsername_flg == 0 && CheckPassword_flg == 0){
        snprintf(S_Response, sizeof(S_Response), "%s", AuthResult_00);
      }
      else if(CheckUsername_flg == 0 && CheckPassword_flg == 1){
        snprintf(S_Response, sizeof(S_Response), "%s", AuthResult_01);
      }
      else if(CheckUsername_flg == 1 && CheckPassword_flg == 0){
        snprintf(S_Response, sizeof(S_Response), "%s", AuthResult_02);
      }
      else{
        snprintf(S_Response, sizeof(S_Response), "%s", AuthResult_03);
      }

      printf("%s\n", S_Response);

      if (send(net_fd, S_Response, strlen(S_Response), 0) < 0) {
        perror("send()");
        exit(1);
      }



    }


  }
  
  /* use select() to handle two descriptors at once */
  maxfd = (tap_fd > net_fd)?tap_fd:net_fd;

  while(1) {
    int ret;
    fd_set rd_set;

    FD_ZERO(&rd_set);
    FD_SET(tap_fd, &rd_set); FD_SET(net_fd, &rd_set);

    ret = select(maxfd + 1, &rd_set, NULL, NULL, NULL);

    if (ret < 0 && errno == EINTR){
      continue;
    }

    if (ret < 0) {
      perror("select()");
      exit(1);
    }

    if(FD_ISSET(tap_fd, &rd_set)) {
      /* data from tun/tap: just read it and write it to the network */
      
      nread = cread(tap_fd, buffer, BUFSIZE);

      tap2net++;
      do_debug("TAP2NET %lu: Read %d bytes from the tap interface\n", tap2net, nread);

      /* write length + packet */
      plength = htons(nread);
      nwrite = cwrite(net_fd, (char *)&plength, sizeof(plength));
      nwrite = cwrite(net_fd, buffer, nread);
      
      do_debug("TAP2NET %lu: Written %d bytes to the network\n", tap2net, nwrite);
    }

    if(FD_ISSET(net_fd, &rd_set)) {
      /* data from the network: read it, and write it to the tun/tap interface. 
       * We need to read the length first, and then the packet */

      /* Read length */      
      nread = read_n(net_fd, (char *)&plength, sizeof(plength));
      if(nread == 0) {
        /* ctrl-c at the other end */
        break;
      }

      net2tap++;

      /* read packet */
      nread = read_n(net_fd, buffer, ntohs(plength));
      do_debug("NET2TAP %lu: Read %d bytes from the network\n", net2tap, nread);

      /* now buffer[] contains a full packet or frame, write it into the tun/tap interface */ 
      nwrite = cwrite(tap_fd, buffer, nread);
      do_debug("NET2TAP %lu: Written %d bytes to the tap interface\n", net2tap, nwrite);
    }
  }
  
  return(0);
}
