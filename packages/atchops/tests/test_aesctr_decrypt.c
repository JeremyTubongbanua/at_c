#include "atchops/aes_ctr.h"
#include "atchops/base64.h"
#include "atchops/iv.h"
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CIPHERTEXTBASE64                                                                                               \
  "yY9vOA8bbzyADNGOxFPdT6bGxySKmNd6usP5/"                                                                              \
  "LBufYo4oBJt4ntFCecxESIjZuCqX5ALV8YNujt9V7s5f5QdfEuLAX7pa8apJp23BwDP7j7e3qz5NVbGocGpChdQBX8ni2aoMOrKZyMjtls8G4cCG0b" \
  "7QIDSSEk1sv6fH50lToBZ/4fNSKonHZ0JvsbkE/1vg7VrcQ8tqwZJNfSfZaoP6zQpROknfjgRyYGJfy/Rao/"                               \
  "vJRoSicH5sOcXKg+41BUa0Uc8Iqz4wJrzkI+uz7sJUIBZ3b5ZLdHXmk5z5cee3Suh58+"                                               \
  "yE2p29hcF2Dzpygx2KdT8ValH2PdB9u4B4DzTikQBKDqP9mDPPR4K/"                                                             \
  "TGBvI90vsX2vZo2LSRpx2NC7aZxvx5RXdjjfFNffYCAwX2n0SKvyUBhXmYu2zdgx99MDsfwp/7LG7Noy5q/InfDb/"                          \
  "dQdvJAGdWcsnqdHIANVen1+"                                                                                            \
  "cQFKPk79MMcSsBQI6WAYYZAI2ctWju6y2SN5MhSOAdWehWRS8P3fv4j30KqAHKnXiNzqfTb8135u2hsDCCP6H6fdf3IKQmqVasFUs2AgUcdIVEQxOf" \
  "RNu5URemIk7imJ0pGP/P47gCb2TwThObE7XCPcNfgyY51cRgKQc5vQXyqJw4gKE49QmuDIsMyoSdroYhnn/"                                \
  "1nhfO7AxG74+3y76CHvhcqsNT5LK1Nr9ecdAeKTEqp4SvVcxxA7CJcjbjv6GuSAQovv04uxiOGjMFoWeU+CaVi0jNAYa+bE/"                   \
  "TBpdL7Meg8EStK8p3Sb2AQc46LHVHEW7OMDT9JG2jgtL3wjjYbhm+o7W+yEkGZL5p274749LFMCeHafW5qKougjUuR3g1AUzW9TeL84J52/"        \
  "ZaqHPOpk0+7uhVzUhnNvKofVypyV3bGnGyqUeAx5uRbBjrFJdor+cZ6NmsnOHyVlzXHOsFItmB5STth+zSTyZ/"                             \
  "53SZkTP9NoTiZMl3iuJAffzRXjmvouA6JstxdXYbAfGNVRz+VIvHPlqYbrS/SopijypqEZ1Hnju3y0HexsUc4xilDXvy+XaTUibAbi6hHy8QfRd1/"  \
  "KU6DgOVNjlOsvELjsa3f+hLE9Zu+QOrC42vpzR3BVC+rh2X5RXEn+"                                                              \
  "aY5i4oejYH2HiRQo00gUfrffL79NCpfvn10NMawlWQxRiVLbJ0qi6TN4hsKr2HAzTmuh1lN+tC4VciexHfy87Bs2l8/"                        \
  "oXCFzAT6TdpTXBaTWXzmXBy8YaQwXxMb3xNV+LaEaYy1AlDTypPZdkkIkpJkG9Tkbw4JXt7RKQ0oS/"                                     \
  "sFp2MkHKjkbJjHaFm+Fi55uMKMht3200PWwTQSHS/GupZhTIlXm86HbQHUUAbxe/"                                                   \
  "Dgpup6NQ96TMgYOi3t+FG78TY7QXJMejkAHNpS57deB0EmeFhbJRCgSEc0amwjEk7AIKYbg0J+j7lYcJvB/"                                \
  "uiUj2GSfBBU75iudTrvMJ60VnbQF055piUwlRlYc9TUf/43Oa7wszCq+oPI/Kjaho/GO4cO2mnc92sgw7wR/+hv/8Bd8/"                      \
  "j2gSssraQgepEkjVL1HKvrxil+OuJo5hy+bM88CjB8Q04to0gkLApPbirL6w2ZlOCn2LRrGuSkajl0QgviL95GEM8zNqZscPkBiV2yVUw403G+T5+"  \
  "3ERtbZ1kJrgKuTSnjPTt8bFMYEdJVQ1+Z1mtnWX4AxR/"                                                                       \
  "j6vC2H+DSuGfOyaH1vociT+nNeDtq3axck5sf8h443Yw9jSbMVjyE+HkZWvxzyD4MjSvnEVp1Sso0/eDKFyTVRPn4dsw09+ltOm0F8CGeH/"        \
  "FAoXLF8CGrEoFe//"                                                                                                   \
  "Tlk8b+PbW1FVIph42cnQXpwHLrlsSAGjHmg4mWK8QXcRLjykdYpH4sX+Wd1wxHvlKAWEDBlZB1NSHkTgrprovr7xxqUCA3vRkRRD1RzG+Q6ikb0/"   \
  "1PmBPlOW3v8Dwr1BGuu9a7fruisMrl88LuPVXgxBpjANa4aq3nVmcZ2WMduDEgH1bWWqaciT3IkYm/"                                     \
  "97QMIQRyFTfQ5tWY9ZcsP9DKluqM222whKBsLz3sL4F9gL5L2HECz3y5EGX4J5QSrU4y4Y8HE5KNz9SqwlTdYSj87dm/"                       \
  "e5l8mVNVR8gMFtzbd9MqNaCoNPm8GfWvx+QIctKNR3zEjxqWrMkiyezZU0PxC98eeHIkef0s1OPcDLMRiwIl"

#define AESKEYBASE64 "su16AzIiiGZULJYFsxDWyyy8yAJQNJvEsmVNkr2/0Vo="

int main() {

  int ret = 1;

  const size_t plaintextsize = 8192;
  unsigned char *plaintext = malloc(sizeof(unsigned char) * plaintextsize);
  memset(plaintext, 0, plaintextsize);
  size_t plaintextlen = 0;

  const size_t ciphertextsize = 8192;
  unsigned char ciphertext[ciphertextsize];
  memset(ciphertext, 0, sizeof(unsigned char) * ciphertextsize);
  size_t ciphertextlen = 0;

  unsigned char key[32];
  memset(key, 0, sizeof(unsigned char) * 32);
  size_t keylen = 0;

  unsigned char *iv = malloc(sizeof(unsigned char) * ATCHOPS_IV_BUFFER_SIZE);
  if (iv == NULL) {
    printf("malloc (failed): %d\n", ret);
    goto exit;
  }
  memset(iv, 0, ATCHOPS_IV_BUFFER_SIZE); // keys in the atKeys file are encrypted with AES with IV {0} * 16

  ret = atchops_base64_decode((unsigned char *)CIPHERTEXTBASE64, strlen(CIPHERTEXTBASE64), ciphertext, ciphertextsize,
                              &ciphertextlen);
  if (ret != 0) {
    printf("atchops_base64_decode (failed): %d\n", ret);
    goto exit;
  }

  ret = atchops_base64_decode((unsigned char *)AESKEYBASE64, strlen(AESKEYBASE64), key, 32, &keylen);
  if (ret != 0) {
    printf("atchops_base64_decode (failed): %d\n", ret);
    goto exit;
  }

  ret = atchops_aes_ctr_decrypt(key, ATCHOPS_AES_256, iv, ciphertext, ciphertextlen, plaintext, plaintextsize,
                                &plaintextlen);
  if (ret != 0) {
    printf("atchops_aes_ctr_decrypt (failed): %d\n", ret);
    goto exit;
  }
  printf("atchops_aes_ctr_decrypt (success): %d\n", ret);

  if (plaintextlen <= 0) {
    printf("atchops_aes_ctr_decrypt (failed): %d\n", ret);
    goto exit;
  }
  printf("decrypted text: %.*s\n", (int)plaintextlen, plaintext);

  printf("decrypted bytes:\n");
  for (size_t i = 0; i < plaintextlen && i < plaintextsize; i++) {
    printf("%02x ", *(plaintext + i));
  }
  printf("\n");

  goto exit;

exit: {
  free(iv);
  free(plaintext);
  return ret;
}
}
