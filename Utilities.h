bool myDEBUG = false;
/*
  Note: I have "customized" the LoRa library by moving
  uint8_t readRegister(uint8_t address);
  void writeRegister(uint8_t address, uint8_t value);
  to public: in LoRa.h – as we need access to the registers, obviously.
*/

void writeRegister(uint8_t reg, uint8_t value) {
  LoRa.writeRegister(reg, value);
}
uint8_t readRegister(uint8_t reg) {
  return LoRa.readRegister(reg);
}

#ifdef NeedBase64Decode
static const unsigned char pr2six[256] = {
  /* ASCII table */
  64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
  64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
  64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63,
  52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64,
  64,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
  15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 64,
  64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
  41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64,
  64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
  64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
  64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
  64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
  64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
  64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
  64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
  64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64
};

int Base64decode_len(char *bufcoded) {
  int nbytesdecoded;
  register const unsigned char *bufin;
  register int nprbytes;
  bufin = (const unsigned char *) bufcoded;
  while (pr2six[*(bufin++)] <= 63);
  nprbytes = (bufin - (const unsigned char *) bufcoded) - 1;
  nbytesdecoded = ((nprbytes + 3) / 4) * 3;
  return nbytesdecoded + 1;
}

int Base64decode(uint8_t* bufplain, char *bufcoded) {
  int nbytesdecoded;
  register const unsigned char *bufin;
  register unsigned char *bufout;
  register int nprbytes;
  bufin = (const unsigned char *) bufcoded;
  while (pr2six[*(bufin++)] <= 63);
  nprbytes = (bufin - (const unsigned char *) bufcoded) - 1;
  nbytesdecoded = ((nprbytes + 3) / 4) * 3;
  bufout = (unsigned char *) bufplain;
  bufin = (const unsigned char *) bufcoded;
  while (nprbytes > 4) {
    *(bufout++) = (unsigned char) (pr2six[*bufin] << 2 | pr2six[bufin[1]] >> 4);
    *(bufout++) = (unsigned char) (pr2six[bufin[1]] << 4 | pr2six[bufin[2]] >> 2);
    *(bufout++) = (unsigned char) (pr2six[bufin[2]] << 6 | pr2six[bufin[3]]);
    bufin += 4;
    nprbytes -= 4;
  }
  /* Note: (nprbytes == 1) would be an error, so just ingore that case */
  if (nprbytes > 1) {
    *(bufout++) =
      (unsigned char) (pr2six[*bufin] << 2 | pr2six[bufin[1]] >> 4);
  }
  if (nprbytes > 2) {
    *(bufout++) =
      (unsigned char) (pr2six[bufin[1]] << 4 | pr2six[bufin[2]] >> 2);
  }
  if (nprbytes > 3) {
    *(bufout++) =
      (unsigned char) (pr2six[bufin[2]] << 6 | pr2six[bufin[3]]);
  }
  *(bufout++) = '\0';
  nbytesdecoded -= (4 - nprbytes) & 3;
  return nbytesdecoded;
}
#endif

#ifdef NeedBase64Encode
static const char basis_64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int Base64encode_len(int len) {
  return ((len + 2) / 3 * 4) + 1;
}

int Base64encode(char *encoded, uint8_t* plain, int len) {
  int i;
  char *p;
  p = encoded;
  for (i = 0; i < len - 2; i += 3) {
    *p++ = basis_64[(plain[i] >> 2) & 0x3F];
    *p++ = basis_64[((plain[i] & 0x3) << 4) | ((int) (plain[i + 1] & 0xF0) >> 4)];
    *p++ = basis_64[((plain[i + 1] & 0xF) << 2) | ((int) (plain[i + 2] & 0xC0) >> 6)];
    *p++ = basis_64[plain[i + 2] & 0x3F];
  }
  if (i < len) {
    *p++ = basis_64[(plain[i] >> 2) & 0x3F];
    if (i == (len - 1)) {
      *p++ = basis_64[((plain[i] & 0x3) << 4)];
      *p++ = '=';
    } else {
      *p++ = basis_64[((plain[i] & 0x3) << 4) | ((int) (plain[i + 1] & 0xF0) >> 4)];
      *p++ = basis_64[((plain[i + 1] & 0xF) << 2)];
    }
    *p++ = '=';
  }
  *p++ = '\0';
  return p - encoded;
}
#endif

void hex2array(char* src, uint8_t* dst, uint16_t sLen) {
  uint16_t i, n = 0;
  for (i = 0; i < sLen; i += 2) {
    uint8_t x, c;
    c = src[i];
    if (c != '-') {
      if (c > 'Z') c -= 32;
      if (c > '9') c -= 55;
      else c -= '0';
      x = c << 4;
      c = src[i + 1];
      if (c > 'Z') c -= 32;
      if (c > '9') c -= 55;
      else c -= '0';
      dst[n++] = (x + c);
    }
  }
}

void array2hex(uint8_t* inBuf, uint16_t sLen, char *outBuf, uint8_t dashFreq = 0) {
  uint16_t i, len, n = 0;
  const char * hex = "0123456789ABCDEF";
  for (i = 0; i < sLen; ++i) {
    outBuf[n++] = hex[(inBuf[i] >> 4) & 0xF];
    outBuf[n++] = hex[inBuf[i] & 0xF];
    if (dashFreq > 0 && i != sLen - 1) {
      if ((i + 1) % dashFreq == 0) outBuf[n++] = '-';
    }
  }
  outBuf[n++] = 0;
}

void xorBufs(uint8_t* buff0, uint8_t* buff1, uint16_t len, uint8_t* buff2) {
  for (uint16_t x = 0; x < len; x++) buff2[x] = (buff0[x] ^ buff1[x]);
}

void xorBufs(uint8_t* buff0, uint8_t* buff1, uint16_t len0, uint16_t len1) {
  uint16_t ix = 0;
  for (uint16_t x = 0; x < len0; x++) {
    buff0[x] ^= buff1[ix++];
    if (ix == len1) ix = 0;
  }
}

void xorBufSingle(uint8_t* buf, uint8_t c, uint16_t len) {
  for (uint16_t x = 0; x < len; x++) buf[x] ^= c;
}


void initMatasano() {
#ifdef NeedBestScore
  Serial.print(F(" * Initializing freqs array..."));
  uint8_t sc = 255;
  freqs['E'] = sc;
  sc -= 2;
  freqs['T'] = sc;
  sc -= 2;
  freqs['A'] = sc;
  sc -= 2;
  freqs['O'] = sc;
  sc -= 2;
  freqs['I'] = sc;
  sc -= 2;
  freqs['N'] = sc;
  sc -= 2;
  freqs['S'] = sc;
  sc -= 2;
  freqs['R'] = sc;
  sc -= 2;
  freqs['H'] = sc;
  sc -= 2;
  freqs['L'] = sc;
  sc -= 2;
  freqs['D'] = sc;
  sc -= 2;
  freqs['C'] = sc;
  sc -= 2;
  freqs['U'] = sc;
  sc -= 2;
  freqs['M'] = sc;
  sc -= 2;
  freqs['F'] = sc;
  sc -= 2;
  freqs['P'] = sc;
  sc -= 2;
  freqs['G'] = sc;
  sc -= 2;
  freqs['W'] = sc;
  sc -= 2;
  freqs['Y'] = sc;
  sc -= 2;
  freqs['B'] = sc;
  sc -= 2;
  freqs['V'] = sc;
  sc -= 2;
  freqs['K'] = sc;
  sc -= 2;
  freqs['X'] = sc;
  sc -= 2;
  freqs['J'] = sc;
  sc -= 2;
  freqs['Q'] = sc;
  sc = 255;
  freqs['e'] = sc;
  sc -= 2;
  freqs['t'] = sc;
  sc -= 2;
  freqs['a'] = sc;
  sc -= 2;
  freqs['o'] = sc;
  sc -= 2;
  freqs['i'] = sc;
  sc -= 2;
  freqs['n'] = sc;
  sc -= 2;
  freqs['s'] = sc;
  sc -= 2;
  freqs['r'] = sc;
  sc -= 2;
  freqs['h'] = sc;
  sc -= 2;
  freqs['l'] = sc;
  sc -= 2;
  freqs['d'] = sc;
  sc -= 2;
  freqs['c'] = sc;
  sc -= 2;
  freqs['u'] = sc;
  sc -= 2;
  freqs['m'] = sc;
  sc -= 2;
  freqs['f'] = sc;
  sc -= 2;
  freqs['p'] = sc;
  sc -= 2;
  freqs['g'] = sc;
  sc -= 2;
  freqs['w'] = sc;
  sc -= 2;
  freqs['y'] = sc;
  sc -= 2;
  freqs['b'] = sc;
  sc -= 2;
  freqs['v'] = sc;
  sc -= 2;
  freqs['k'] = sc;
  sc -= 2;
  freqs['x'] = sc;
  sc -= 2;
  freqs['j'] = sc;
  sc -= 2;
  freqs['q'] = sc;
  for (uint8_t i = 0; i < 10; i++) freqs[0x30 + i] = 9;
  Serial.println(F(" done!"));
#endif
#ifdef CH_2_12
  Serial.print(F(" * Initializing Problem12 key..."));
  fillRandom(p12Key, 16);
  Serial.println(F(" done!"));
#endif
}

#ifdef NeedBestScore
uint16_t freqs[256] = {0};
int ScoreString(uint8_t* mb, uint16_t j) {
  uint16_t i, x, score, n;
  uint16_t myFreqs[256];
  score = 0;
  for (i = 0; i < 256; i++) myFreqs[i] = 0;
  for (i = 0; i < j; i++) {
    x = mb[i];
    if (x == 0) break;
    myFreqs[x] += 1;
  }
  for (i = 0; i < 25; i++) {
    score = score + myFreqs[i + 65] * freqs[i + 65];
    score = score + myFreqs[i + 97] * freqs[i + 97];
  }
  for (i = 0; i < 10; i++) score = score + myFreqs[i + 0x30] * freqs[i + 0x30];
  return score;
}

int maxScore, maxScoreHolder;
int GetBestScore(uint8_t* tmp0, uint16_t len) {
  uint8_t i;
  int score;
  maxScore = -1;
  maxScoreHolder = -1;
  uint8_t tmp1[len];
  for (i = 0; i < 255; i++) {
    memcpy(tmp1, tmp0, len);
    xorBufSingle(tmp1, (i + 1), len);
    score = ScoreString(tmp1, len);
    if (myDEBUG) {
      Serial.print(i + 1);
      Serial.print(F(": - "));
      Serial.print((char*)tmp1);
      Serial.print(F("- Score: "));
      Serial.println(score);
    }
    if (score > maxScore) {
      maxScore = score;
      maxScoreHolder = i + 1;
    }
  }
  return maxScoreHolder;
}
#endif

#ifdef CH_1_6
int getHammingDistance(uint8_t* buf0, uint8_t* buf1, uint8_t len) {
  uint8_t dist = 0;
  for (uint8_t i = 0; i < len; i++) {
    uint8_t n = 1;
    for (uint8_t x = 0; x < 8; x++) {
      if ((buf0[i] & n) != (buf1[i] & n)) dist += 1;
      n = n << 1;
    }
  }
  return dist;
}
#endif

#ifdef NeedDecryptECB
int16_t decryptECB(uint8_t* myBuf, uint16_t olen, uint8_t* pKey) {
  // Test the total len vs requirements:
  // AES: min 16 bytes
  // HMAC if needed: 28 bytes
  uint16_t reqLen = 16;
  if (olen < reqLen) return -1;
  uint8_t len;
  // or just copy over
  memcpy(encBuf, myBuf, olen);
  len = olen;
  struct AES_ctx ctx;
  AES_init_ctx(&ctx, pKey);
  uint16_t rounds = len / 16, steps = 0;
  for (uint16_t ix = 0; ix < rounds; ix++) {
    // void AES_ECB_encrypt(const struct AES_ctx* ctx, uint8_t* buf);
    AES_ECB_decrypt(&ctx, encBuf + steps);
    steps += 16;
    // decrypts in place, 16 bytes at a time
  } encBuf[steps] = 0;
  return len;
}
#endif

#ifdef NeedEncryptECB
uint16_t encryptECB(uint8_t* myBuf, uint16_t len, uint8_t* pKey) {
  // first ascertain length
  uint16_t olen;
  struct AES_ctx ctx;
  olen = len;
  if (olen != 16) {
    if (olen % 16 > 0) {
      if (olen < 16) olen = 16;
      else olen += 16 - (olen % 16);
    }
  }
  memset(encBuf, (olen - len), olen);
  memcpy(encBuf, myBuf, len);
  AES_init_ctx(&ctx, pKey);
  uint8_t rounds = olen / 16, steps = 0;
  for (uint8_t ix = 0; ix < rounds; ix++) {
    AES_ECB_encrypt(&ctx, (uint8_t*)(encBuf + steps));
    steps += 16;
    // encrypts in place, 16 bytes at a time
  }
  return olen;
}

bool PKCS7(uint8_t* buff, uint16_t blockLen, uint16_t padLen) {
  if (blockLen >= padLen) return false;
  uint8_t c = padLen - blockLen;
  uint16_t i;
  for (i = 0; i < c; i++) buff[blockLen + i] = c;
  return true;
}
#endif

#ifdef NeedEncryptCBC
int16_t encryptCBC(uint8_t* myBuf, uint8_t olen, uint8_t* pKey, uint8_t* Iv) {
  uint8_t rounds = olen / 16;
  if (rounds == 0) rounds = 1;
  else if (olen - (rounds * 16) != 0) rounds += 1;
  uint8_t length = rounds * 16;
  memset(encBuf, (length - olen), length);
  memcpy(encBuf, myBuf, olen);
  struct AES_ctx ctx;
  AES_init_ctx_iv(&ctx, pKey, Iv);
  AES_CBC_encrypt_buffer(&ctx, encBuf, length);
  return length;
}
#endif

#ifdef NeedDecryptCBC
int16_t decryptCBC(uint8_t* myBuf, uint8_t olen, uint8_t* pKey, uint8_t* Iv) {
  uint8_t rounds = olen / 16;
  if (rounds == 0) rounds = 1;
  else if (olen - (rounds * 16) != 0) rounds += 1;
  uint8_t length = rounds * 16;
  // We *could* trust the user with the buffer length, but...
  // Let's just make sure eh?
  memcpy(encBuf, myBuf, olen);
  struct AES_ctx ctx;
  AES_init_ctx_iv(&ctx, pKey, Iv);
  AES_CBC_decrypt_buffer(&ctx, encBuf, length);
  return length;
}
#endif
#ifdef CH_2_11
#define NeedEncryptECB
#define NeedEncryptCBC
uint8_t OracleP11(uint8_t* buff, uint8_t len) {
  uint8_t before, after;
  uint8_t values[3];
  uint8_t pKey[16];
  fillRandom(pKey, 16);
  fillRandom(values, 3);
  before = values[0] % 5 + 5;
  after = values[1] % 5 + 5;
  whichAES = values[2] % 2;
  uint8_t olen = len + before + after;
  // Serial.print("before: "); Serial.print(before);
  // Serial.print(", after: "); Serial.print(after);
  // Serial.print(", whichAES: "); Serial.print(whichAES);
  // if(whichAES == 0) Serial.println(" ECB enabled.");
  // else Serial.println(" CBC enabled.");
  // Serial.print("Total len: "); Serial.println(olen);
  fillRandom(OracleBuff, before);
  memcpy(OracleBuff + before, buff, len);
  fillRandom(OracleBuff + before + len, after);
  uint8_t rounds = olen / 16;
  if (rounds == 0) rounds = 1;
  else if (olen - (rounds * 16) != 0) rounds += 1;
  uint8_t length = rounds * 16;
  PKCS7(OracleBuff, olen, length);
  if (whichAES == 0) encryptECB(OracleBuff, length, pKey);
  else {
    uint8_t IV[16];
    fillRandom(IV, 16);
    encryptCBC(OracleBuff, length, pKey, IV);
  }
  return length;
}
#endif

#ifdef CH_2_12
uint16_t OracleP12(uint8_t* buff, uint16_t len) {
  uint8_t Iv[16];
  fillRandom(Iv, 16);
  uint8_t myBuff[512];
  if (len > 0) memcpy(myBuff, buff, len);
  memcpy(myBuff + len, Problem12b, p12bLen);
  uint16_t olen = len + p12bLen;
  uint16_t rounds = olen / 16;
  if (rounds == 0) rounds = 1;
  else if (olen - (rounds * 16) != 0) rounds += 1;
  uint16_t padLen = rounds * 16;
  PKCS7(myBuff, olen, padLen);
  return encryptECB(myBuff, padLen, p12Key);
}
#endif

#ifdef NeedDuplicates
bool detectDuplicates(uint8_t* line, uint8_t len, bool breakEarly = false) {
  uint8_t lastMatch[16];
  uint8_t olen = len - 16;
  bool result = false;
  for (uint8_t j = 0; j < olen; j += 16) {
    if (memcmp(lastMatch, line + j, 16) != 0) {
      for (uint8_t k = j + 16; k < len; k += 16) {
        if (memcmp(line + j, line + k, 16) == 0) {
          memcpy(lastMatch, line + j, 16);
          result = true;
          if (breakEarly) return true;
        }
      }
    } else {
      result = true;
    }
  }
  return result;
}
#endif
