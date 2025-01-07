#include <atclient/atclient.h>
#include <atclient/atkeys.h>
#include <atclient/atkeys_file.h>
#include <atlogger/atlogger.h>
#include <string.h>
#include <functional_tests/config.h>

#define TAG "test_atkeys_write"

#define ATSIGN "@alice🛠"
#define ATKEYS_FILE_PATH_COPY "temp_key.atKeys"

#define ATKEYS_STRING_ALICE                                                                                            \
  "{\"aesPkamPublicKey\":\"yYYhLRFIfqlz/"                                                                              \
  "sGEiswbGO+MRdAWUZSJJeMyGqRVqxneJa3oaJrUtFQWkG17f3Hi6fDKDXB1iLNEmLDWBMxtE101U97rRaNo0wjG8qyazI/"                     \
  "L2X5WVdBI6Qait7hFoPkjv7ea0zm5KDh+Y+17X5c7ipEpCxHLUMFbSRDSyOJmoE9Hz1DsYualY3fjxwBaXje9YzmOm3dYqM5ySxOVMA/Rt14sx9t/"  \
  "7JFvfP8gcPFhIXti0cI1/suwvPaK7eG8Kf9tqtYy7vGjnZlgC3J9yLAsoDzyq2tMv4hflvINmkBOtCK71bu1R9rZ0Y9jiqs/wN1WX3WLQ/"         \
  "dsg0fsRep/amtGjTrHmV0BT79Qn2vVFb8mvAdCy8PVSYhT6A3anLipsyTSxcH1fdsmPMEup/"                                           \
  "OWI8dkrcBaalA15B2xp0l5ASiqCE7vvrulzmqL+thl5R755v53tWV5SBUOJw5DIGFhG2gU356PCv2brVGLvFS+Cu1VP3Y1VOUJtdWEQqE+mlB/"     \
  "IjA3jwGwqVelvrTcuSOI4dCO+Q==\",\"aesPkamPrivateKey\":\"yYYhKi5FdqVw3eu7oMAZLr6QHNVud+"                              \
  "GNJfM4H6RFwBvRJ4PdTJrMnFQgkG1dIWzo2sPkDFZgoINplJfZDo9kNUBla8DKLoEx6xP5nLmav4XCxjcJYNEA916fqp965t4StZe42ySIJBNDZIJY" \
  "KJZT6PwRQQSjfJNDCgjKnp16s1Iytx74IdmYQiOG9W1qJDqPEz/vhDR8mfMSa3LYeyTSyn4by+0xm5t3Rt0OFfVqL2hM/"                      \
  "Nhow8OR2dilvZKBFORI8ZMg7/SntJ1oI2lZyIkV2Q3qrnp7tZZdjO02yV09wTaFm6SPB/"                                              \
  "jA4ZVCvaRKhcE3a06COORlt02tWsENTnhUnhXRzUh6dvNzjQ/"                                                                  \
  "XLqIh0S5o1eH6Q4JNhDPXqcCapzbz0NjFY61REckOlNajev8slI9mXG49mxi39gFhFAOME2Pbqp6w2kuG5N8X9gK+wvZ332RlUSIMJAYRDDYeShQU/" \
  "bmHYODEgXyQ+kuOBtlMFHYyVuMRzdifNcAHi21zES14nzSUpHGn1LCV1mbCqJnDskYAl30EswA/a/r5/"                                   \
  "DeFGwXMhvQyhwnCspd3Npx4zuosRMU+czbS/aS+p8DUBQ9OOZp6/iQZ4dPHKhmZqYp7iMsnpjuFGAEe8mIr2/"                              \
  "S4SFZtTBK4R+uhUbhVePE8XbujQ2Z21F2UbUkZZK6PJMce0T2eLvAkDU/"                                                          \
  "uM66H4asFPtgmp0eDxK9AkvhfqNOb9hFrfr4LQoXCEk2EOL39Gon42KZgPO8fbULxcrdt/"                                             \
  "A2HS1Mf78s5rwcAZ9u2Jtj4F8ab4JsjoM23HdrKqvUfiNotSR6hyyCYTzUb1VyIubzJnVRCE+Xz5vdKREw6KaFEfHP95DbQ+"                   \
  "jw4XfvObeLd4O4MbIRfb6a4TQfNsEDxQUHIczk+dqLGSTdR1k+O/"                                                               \
  "AoXyMDSIaJsWuXKvYbY19e0RWlg7xsigx9shTcFvW0NPZZpDTxue+R2BgVT2nBlhzBVSvd9qyi8RUy2tvkh2m/"                             \
  "K4+dYBw6W3Tgx+L1qwYMCHWI+lvgdCbN0Eojbj8izcil4zOWQ8LB+j0fd3g7mhQQMvzbtpi+"                                           \
  "mrF7SpSGdZ3qyKdsV5by5em6ieUoEQm5K2OBDFhcIYqmjhJ2HliVUo3hwf66gF1bezDaPXCJKE9UfHoBOk1DfBJ/"                           \
  "6+moMSIadhXY1dVX1LSpvKOBnppptVRunQf1EvMGTuOlS4wtExDbMT9hlnBdMIWdc9CT0O5R/3lBCowBCrfaWcl5Zrdx3cVZ45mDKjxjoiOyO/"     \
  "bWXCMnAzq5W02LgKPSjPuGBxUQdc+hHCSbsyhQjQALEJgjx3uyxrgnNcE/P0LDHgnEJloyOdSsSSIr62pkyy0EPL1yxobUGnEKDcnsQN/"          \
  "lVChqTfeFbY471HRRNfcT2bmQlFsOvwAlzYxY63hsvIw/RlHoxJv8OO8QvDgX59sDqlhYUcH6W/5Aonv0ySOs/"                             \
  "ZTIiFqO0hblquxDYXkQJk4cCjp04K3wnX/YDENqJ4zQdShvlhGQ9jG+0iNm7xkNAQ09MqfODyZ92fuHa2EosakOnYArfNzp/"                   \
  "fNHssbKtQchij5mlM0/XU4OqzWbsb3UJiVxTvAnGXFJkKVLSqjslsJC8EiRPWOMD6UR/cxQkswLVemE6VbcTS1UNW/"                         \
  "ib6AQ34Y9i9Bo8cWA2JxBHHCz+fgJdbxYkECvs+J14yG3FYKq5lyP0lRjCJ8NaODFhKWWZnUd6bDzKjZeY0JGYxDC9GMyIkm4e+"                \
  "XHj0XU27hIC0TM7ypXursRfPjJ2StaA89NJc3iQ5CaJ9dY40lfeACHfhje4mEzk4LShw0RonVSigpM7ia95hhNOFVJMIICp70frTio88B1oMY8IUXU" \
  "ISxkiDDNrv1a91xAbDxViOw5epbPmYCO24OR9XvqVa6+79/bgnSSMc/lQKBIJNO8dshrsIY2Zizm9HD/IrttnLY5J5/"                        \
  "TpPb2ZZa5rB3ji0wK2P0H34+LYlyVZRHbDAqhsy43u26eeJB5Y5tOAWBRrhDeIsWk4oFmfjZEgWmCgthaW1zSJsyYe5Q+"                      \
  "ohGfI5Fr2buyT3c6tJp6j9HfMP68E5tBk6idke+mVz6T74oWTN5dybCgWq67+"                                                      \
  "36mqeV4F43SGStLwR6zO6bgqBuVGCQ0IxSJ6tXMMgpv01jrOgmnd0wS62ljZHJ96Wx9MT6jX9LxA\",\"aesEncryptPublicKey\":"            \
  "\"yYYhLRFIfqlz/sGEiswbGO+MRdAWUZSJJeMyGqRVqxneJa3oaJrUtFQWkG0sPXzAzOaRHFRErpZ2lPf9B45OHyAnfL77EvdPrziE8Pe+u63/"     \
  "xjdRa/Rq5CCLuudipflMgZm8/"                                                                                          \
  "TzqBQZTKdpnJ65b2el0ACywToZEUzSxlPxNlTcyrRf4UOmcbSOdgBhVYSSSRT3Ko09UhPBPT3XZdxTKtlFG5a4Rzq91L8MnYNhBb0NB56ES1+GGvM+" \
  "q3pejCv5Hw81Cj/eMmOdUaFEOuq9M/"                                                                                     \
  "iDD3nRlgNRU1PA1n0EgtR+"                                                                                             \
  "uwYvRXfq766Jsvu1vls9aQHXxZ7VolXerGugqVkdbpRnPnltFecRojxvvEJlQ3hZistXSVJtR3Dr8qIqknjSh3PP0WN0mHPoggvG7He1v9Ml1UXNCj" \
  "SO7jUFtcz7QHnDChaCz/VHp+skz8yGbwehovkdESyMRIipuHmMiWlsB6qWxAMGdi2uutz27JuIXGlQCbP8vnfW/"                            \
  "N8E4jExUJQwH1yewqVelvrTcuSOI4dCO+Q==\",\"aesEncryptPrivateKey\":\"yYYhKi5zdqVw3eu7oMAZLr6QHNVud+"                   \
  "GNJfM4H6RFwBvRJ4fdTJrMnVQgkG1dIWzo2sPjG3hEi5YvvYr6JqpbH3k3d8OUR/dl/"                                                \
  "Tfmku+6zunk7CwSbf1N2UKXhY0E3aUch4SL1zCGQ09CGMx9ALlB9OIlNxG5Zp5cEzfTrP5qpy8R/"                                       \
  "V7NJciJQCz6wRhSKAqWdSDJuG8Mx4ZIC0aUEjHQiTBG5vUA+odIPP4yf6NpNEBEvNtltLGYudX1zdKQFOJC0/"                              \
  "8vz9apuexXPXkI7ssA1FbNs21bq9hps6kKzEYb7Hyfh46RVvqQ/Mw7oZdx2bdmanCRRvdtjUmgWMknZTRxnSPfkWhhT+1VqymSM69V2itH1fP/"     \
  "Z6ND2gLPo7iergX4ptX7bOdGAv4gmaereN8oqJJaSUY6pliWqxwLIDuMMnP+v7+mrmiUy+4A7mmg/"                                      \
  "PV9tTR8DRhgHh1mXQEjTk400eScTcPlpnaMs2uWNv1NO0lfTPssjt6lRdsk93tTCDh002CsqCW9p6KV1mbCqJnDskYAl30ni10IFfmgxXSgAFOOgfI" \
  "e5XX8tJFUQpZ76eNBENUWSBW3/"                                                                                         \
  "5KdxMPgHwRAXZ5RxhUg2ZfzVDuCh4orrfozmS6CF3Ms7R4Axd+QUyM1VTK8T5PeSNJCcd0tFpy7XT1bxnyxMlUxN56hX5oIjSfMF/"              \
  "9UFFn6dI3m89I6QME5v16r04gTuIddgcGZ3EZQJbU0QJDmLGqhdZ2GSI7W1bsrAulpaDiHMId8tTOwbHJB8vcM71gjfvTAXuDcNrWq1bt7jMbnI5LE" \
  "ztc2rNZAagXV6zXOaRwuzH6ZnK2briNtBpWA7c1NGhdjXsEBT07zkQmMgAoSS8b9edbjw+"                                             \
  "8rGNYQZOynSU70p3vCCkLuXAkgDa3sZXkYsBagoAkC5OnJKuYlXpWSiYfX8IHeNXJ91wMfghk4om8Uykw+N/"                               \
  "NNIBcdRcM2RiBZtGUx8U4DRutCmgOcK0fFptI61m/"                                                                          \
  "K4+dYByjrvyNrzPJqkpw5G3ET2NlVOaRcP5r9mOW7DHF878Ku0L1ChQng9X+"                                                       \
  "P4CcYxxTo0EWGy1jqnimnRHTjD9800YDfcg2dRHMvcXUCmtwKC14lHIWKg+"                                                        \
  "DZxVgC4FI1Q4r4OWDJjl6GTgByNc8wIbEsohfaRbDlw2ckeOmM4EEqQR3uOT1GEqZllegXNzK/"                                         \
  "cOEkoM+eorAO5zJmk0Lsb+V9onFNN1phtxvHE5ZC3lBCowBFpcLbAUxUi8kdGWsk1jbDtz2huuaO5In+"                                   \
  "VNSmzKxA5FrEX6rGF6Sq0GZHdMpDFz3V9zIsbg7EFhG9jcaB+"                                                                  \
  "0HNV2Du4av55WYt6NqNaBg0VIbir7kMzVo0ajuyjaI8gQKmUlBJGupXEELNQd1DZN/"                                                 \
  "eBVRNcIHeWz9dG5iizw5yTxMq+2U1KzjfjnoJVuIOOPJ6flrS1KfUkUAQDWnDvogujYtSIr84AwBPO6+ShblquxerCSsnlYo2mPowOV8mKppKPs3/"  \
  "1yFqagjeinV+zRmRutGG/n5ld1wTi9XR56NWUe728T1JaxfxVivjDy1CWNGBy7qsSa9EtsevE2zqcK+lu1PncnQvt09O+j3TCkROEw/"            \
  "hljgk88qHWBIfXs88w3RsdjI4owaqUxhaKYdtSUJBbOGmq39lv89j1BgGMlRKBnFRQE/"                                               \
  "bZkJYaCQMTA7424FnnVvUXI2ss27dwRjCJ8NfGgEGOzmnxWc9DBPC0tWBq6fV7xKmX+SqlQsh+Xn3/"                                     \
  "nE2wDAR7R0g34i32vF9dk9XIpm1j48VSE286guWqMAwjErZCHPR2TCG2AqRrJqzvkBYv3ipsL1Bi6AQsUhzSXFoZdiUhzzwLCZg/"               \
  "QQ4FJxLQWYpEiY2Z3INskWV2z8Hc2x3GGtTl9fdWzTIntVFU/yeQZnGz4H+sSylBcBgEgUdO8cKvxjRO5CvjTm9HD/"                         \
  "LvvRIYqBdrefcDeb4Ca1BJXLo2AqBYk3Wv6LEzi99WnzFeqtCzpbn26WpHB8jieGYDBU05GaFqHwi2HC6maJ3CBvcpDW05Q7L8zccuS+/"          \
  "yUvr+lexW+WR5O+NI6mLlH6dLYFTl/hqpAlhB+Tz8KbwuP2fDq51FC8Nn57B5uawWlsZ9zewPsrPSsfs3pUMJs4RUjJt/"                      \
  "x1KtkMjx7vZ+lLouTDVyUDQ+l3mWppoHh9MT6jX9LxA\",\"selfEncryptionKey\":\"vR+w/lx9qitj/"                                \
  "W2+SfFxbjeRM8VdaYGsxG6lxYCVQ0w=\",\"@alice🛠\":\"vR+w/lx9qitj/W2+SfFxbjeRM8VdaYGsxG6lxYCVQ0w=\"}"

int main(int argc, char *argv[]) {
  int ret = 1;

  atlogger_set_logging_level(ATLOGGER_LOGGING_LEVEL_DEBUG);

  atclient_atkeys atkeys;
  atclient_atkeys_init(&atkeys);

  atclient_atkeys atkeys1;
  atclient_atkeys_init(&atkeys1);

  atclient atclient1;
  atclient_init(&atclient1);

  atclient_authenticate_options authenticate_options;
  atclient_authenticate_options_init(&authenticate_options);

  if ((ret = atclient_atkeys_populate_from_string(&atkeys, ATKEYS_STRING_ALICE)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "failed to populate atkeys from string\n");
    goto exit;
  }

  // log what fields are initializwed
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "is_pkam_public_key_base64_initialized: %d\n",
               atclient_atkeys_is_pkam_public_key_base64_initialized(&atkeys));
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "is_pkam_private_key_base64_initialized: %d\n",
               atclient_atkeys_is_pkam_private_key_base64_initialized(&atkeys));
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "is_encrypt_public_key_base64_initialized: %d\n",
               atclient_atkeys_is_encrypt_public_key_base64_initialized(&atkeys));
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "is_encrypt_private_key_base64_initialized: %d\n",
               atclient_atkeys_is_encrypt_private_key_base64_initialized(&atkeys));
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "is_self_encryption_key_base64_initialized: %d\n",
               atclient_atkeys_is_self_encryption_key_base64_initialized(&atkeys));
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "is_apkam_symmetric_key_base64_initialized: %d\n",
               atclient_atkeys_is_apkam_symmetric_key_base64_initialized(&atkeys));
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "is_enrollment_id_initialized: %d\n",
               atclient_atkeys_is_enrollment_id_initialized(&atkeys));

  if ((ret = atclient_atkeys_write_to_path(&atkeys, ATKEYS_FILE_PATH_COPY))) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "failed to write to path\n");
    goto exit;
  }

  if ((ret = atclient_atkeys_populate_from_path(&atkeys1, ATKEYS_FILE_PATH_COPY))) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "failed to populate from path\n");
    goto exit;
  }

  // log what fields are initializwed
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "is_pkam_public_key_base64_initialized: %d\n",
               atclient_atkeys_is_pkam_public_key_base64_initialized(&atkeys1));
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "is_pkam_private_key_base64_initialized: %d\n",
               atclient_atkeys_is_pkam_private_key_base64_initialized(&atkeys1));
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "is_encrypt_public_key_base64_initialized: %d\n",
               atclient_atkeys_is_encrypt_public_key_base64_initialized(&atkeys1));
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "is_encrypt_private_key_base64_initialized: %d\n",
               atclient_atkeys_is_encrypt_private_key_base64_initialized(&atkeys1));
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "is_self_encryption_key_base64_initialized: %d\n",
               atclient_atkeys_is_self_encryption_key_base64_initialized(&atkeys1));
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "is_apkam_symmetric_key_base64_initialized: %d\n",
               atclient_atkeys_is_apkam_symmetric_key_base64_initialized(&atkeys1));
  atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_DEBUG, "is_enrollment_id_initialized: %d\n",
               atclient_atkeys_is_enrollment_id_initialized(&atkeys1));

  // compare the two atkeys
  if (strcmp(atkeys.pkam_public_key_base64, atkeys1.pkam_public_key_base64) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "pkam_public_key_base64 mismatch\n");
    goto exit;
  }

  if (strcmp(atkeys.pkam_private_key_base64, atkeys1.pkam_private_key_base64) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "pkam_private_key_base64 mismatch\n");
    goto exit;
  }

  if (strcmp(atkeys.encrypt_public_key_base64, atkeys1.encrypt_public_key_base64) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "encrypt_public_key_base64 mismatch\n");
    goto exit;
  }

  if (strcmp(atkeys.encrypt_private_key_base64, atkeys1.encrypt_private_key_base64) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "encrypt_private_key_base64 mismatch\n");
    goto exit;
  }

  if (strcmp(atkeys.self_encryption_key_base64, atkeys1.self_encryption_key_base64) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "self_encryption_key_base64 mismatch\n");
    goto exit;
  }

  if ((ret = atclient_authenticate_options_set_atdirectory_host(&authenticate_options, ATDIRECTORY_HOST)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "failed to set atdirectory host\n");
    goto exit;
  }

  if ((ret = atclient_authenticate_options_set_atdirectory_port(&authenticate_options, ATDIRECTORY_PORT)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "failed to set atdirectory port\n");
    goto exit;
  }

  if ((ret = atclient_pkam_authenticate(&atclient1, ATSIGN, &atkeys1, &authenticate_options, NULL)) != 0) {
    atlogger_log(TAG, ATLOGGER_LOGGING_LEVEL_ERROR, "failed to pkam auth\n");
    goto exit;
  }

exit: {
  atclient_atkeys_free(&atkeys);
  atclient_atkeys_free(&atkeys1);
  atclient_free(&atclient1);
  return ret;
}
}
