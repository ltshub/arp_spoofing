//sender target
#include "arp_spoofing.h"
#include "packet.c"



int main(int argc, char* argv[]) {
  if (argc < 4) {
    usage();
    return -1;
  }


  unsigned char *tmp;
  dev = argv[1];

  tmp = macMac(dev);
  memcpy(My_MAC, tmp, 6);


  pthread_t *thread_id = (pthread_t *)malloc((argc-2)/2 * sizeof(pthread_t));
  struct session *Session = (struct session *)malloc((argc-2)/2 *sizeof(struct session));



  for(int i = 0; i < (argc-2)/2; i++){
      struct session Session2;
      Session2.sender = argv[i * 2 + 2];
      Session2.target = argv[i * 2 + 3];
      Session[i] = Session2;
   }


  for(int i = 0; i < (argc-2)/2; i++){
     pthread_create(&thread_id[i], NULL, &t_fun, (void *)&Session[i]);

   }

  for(int i = 0; i < (argc-2)/2; i++){
    pthread_join(thread_id[i], NULL);
  }

  free(thread_id);

  return 0;
}



