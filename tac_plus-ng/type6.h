#ifndef __TYPE6_H__
#define __TYPE6_H__
char *decrypt_type6(const char *encoded, const char *master_key);
// 1 if encoded has the form of a type 6 value: base41, with room for the salt and the MAC
int type6_form(const char *encoded);
char *encrypt_type6(const char *cleartext, const char *master_key);
#endif

