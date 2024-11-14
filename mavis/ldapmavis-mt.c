/*
 * ldapmavis-mt
 '
 ' multithread-enabled ldapmavis variant, for use with external-mt
 *
 * $Id$
 */

#include "misc/sysconf.h"
#include "mavis.h"
#include <sysexits.h>
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <ldap.h>
#include <ctype.h>
#include <sys/resource.h>
#ifdef WITH_PCRE2
#include <pcre2.h>
#endif
#include "misc/utf.h"
#include "misc/version.h"

#define TRISTATE_DUNNO  0
#define TRISTATE_YES    1
#define TRISTATE_NO     2
static int is_mt = TRISTATE_DUNNO;

static int scope = LDAP_SCOPE_SUBTREE;
static int scope_group = LDAP_SCOPE_SUBTREE;
static int ldap_tacmember_map_ou = 0;
static int ldap_tls_protocol_min = LDAP_OPT_X_TLS_PROTOCOL_TLS1_2;
static time_t ldap_timeout = 30;
static time_t ldap_network_timeout = 5;
static int capabilities = 0;
static int capabilities_set = 0;
static char *ldap_url = NULL;
static char *base_dn = NULL;
static char *base_dn_group = NULL;
static char *ldap_tacmember_attr = NULL;
static char *ldap_filter = NULL;
static char *ldap_filter_group = NULL;
static char *ldap_dn = NULL;
static char *ldap_pw = NULL;
static size_t ldap_filter_len = 0;
static size_t ldap_filter_group_len = 0;
static int ldap_group_depth = -2;
static pcre2_code *ldap_memberof_regex = NULL;
static pcre2_code *ad_result_regex = NULL;
static pcre2_code *ad_dsid_regex = NULL;
static int ldap_sizelimit = 100;


static void usage(void)
{
    fprintf(stderr, "\nUsage: ldapmavis-mt\n\
\n\
Important environment variables and ther defaults:\n\
 LDAP_URL                      ldaps://localhost ldap://localhost\n\
 LDAP_USER                     unset (LDAP bind user DN)\n\
 LDAP_PASSWD                   unset (LDAP bind user password)\n\
 LDAP_BASE                     unset (LDAP search base)\n\
 LDAP_SIZELIMIT                100 (maximum number of LDAP search results)\n\
 LDAB_MEMBEROF_REGEX           ^cn=([^,]+),.* (please adjust this)\n\
\n\
Leaving the ones below as-is is likely safe:\n\
 LDAP_BASE_GROUP               same as LDAP_BASE\n\
 LDAP_SCOPE                    subtree (base, level, onelevel, subtree)\n\
 LDAP_SCOPE_GROUP              subtree (base, level, onelevel, subtree)\n\
 LDAP_TIMEOUT                  5 [seconds]\n\
 LDAP_NETWORK_TIMEOUT          5 [seconds]\n\
 LDAP_TACMEMBER                tacMember\n\
 LDAP_TACMEMBER_MAP_OU         unset (set to map OUs to TACMEMBER)\n\
 LDAP_NESTED_MEMBEROF_DEPTH    unset (set to limit group membership lookup depth)\n"
#ifdef LDAP_OPT_X_TLS_PROTOCOL_TLS1_3
	    " LDAP_TLS_PROTOCOL_MIN         TLS1_2 (TLS1_0, TLS1_1, TLS1_2, TLS1_3)\n"
#else
	    " LDAP_TLS_PROTOCOL_MIN         TLS1_2 (TLS1_0, TLS1_1, TLS1_2)\n"
#endif
	    " LDAP_FILTER                   (&(objectclass=user)(sAMAccountName=%%s)) for AD,\n\
                               (uid=%%s) else\n\
 LDAP_FILTER_GROUP             (&(objectclass=groupOfNames)(member=%%s))\n\
\n\
Copyright (C) 2023 by Marc Huber <Marc.Huber@web.de>\n\
");
    exit(-1);
}

static int LDAP_eval_rootdse(LDAP * ldap, LDAPMessage * res)
{
#define LDAP_CAP_ACTIVE_DIRECTORY_OID "1.2.840.113556.1.4.800"	// supportedCapabilities
#define LDAP_CAP_ACTIVE_DIRECTORY_ADAM_OID "1.2.840.113556.1.4.1851"	// supportedCapabilities
#define LDAP_SERVER_FAST_BIND_OID "1.2.840.113556.1.4.1781"	// supportedCapabilities
#define LDAP_EXTENSION_PASSWORD_MODIFY "1.3.6.1.4.1.4203.1.11.1"	// supportedExtension
#define LDAP_SERVER_START_TLS_OID "1.3.6.1.4.1.1466.20037"	// supportedExtension
#define CAP_AD 1
#define CAP_389DS 2
#define CAP_PWMODIFY 4
#define CAP_FASTBIND 8
#define CAP_STARTTLS 16
    LDAPMessage *entry;
    for (entry = ldap_first_entry(ldap, res); entry; entry = ldap_next_entry(ldap, entry)) {
	/* Print the DN string of the object */
	BerElement *be = NULL;
	char *attribute = NULL;
	for (attribute = ldap_first_attribute(ldap, entry, &be); attribute; attribute = ldap_next_attribute(ldap, entry, be)) {

	    if (!(capabilities & CAP_AD) && !strcasecmp(attribute, "supportedCapabilities")) {
		struct berval **v = ldap_get_values_len(ldap, entry, attribute);
		if (v) {
		    for (int i = 0; v[i]; i++) {
			if (!strcmp(v[i]->bv_val, LDAP_CAP_ACTIVE_DIRECTORY_OID)
			    || !strcmp(v[i]->bv_val, LDAP_CAP_ACTIVE_DIRECTORY_ADAM_OID)) {
			    capabilities |= CAP_AD;
			} else if (!strcmp(v[i]->bv_val, LDAP_SERVER_FAST_BIND_OID)) {
			    capabilities |= CAP_FASTBIND;
			}
		    }
		    ldap_value_free_len(v);
		}
	    } else if (!(capabilities & CAP_PWMODIFY) && !strcasecmp(attribute, "supportedExtension")) {
		struct berval **v = ldap_get_values_len(ldap, entry, attribute);
		if (v) {
		    for (int i = 0; v[i]; i++) {
			if (!strcmp(v[i]->bv_val, LDAP_EXTENSION_PASSWORD_MODIFY)) {
			    capabilities |= CAP_PWMODIFY;
			} else if (!strcmp(v[i]->bv_val, LDAP_SERVER_START_TLS_OID)) {
			    capabilities |= CAP_STARTTLS;
			}
		    }
		    ldap_value_free_len(v);
		}
	    } else if (!(capabilities & CAP_AD) && !strcasecmp(attribute, "vendorName")) {
		struct berval **v = ldap_get_values_len(ldap, entry, attribute);
		if (v) {
		    for (int i = 0; v[i]; i++) {
			if (strstr(v[i]->bv_val, "389 Project")) {
			    capabilities |= CAP_389DS;
			    break;
			}
		    }
		    ldap_value_free_len(v);
		}
	    }
	}
    }
    return capabilities;
}

static int LDAP_bind(LDAP *, const char *, const char *);

static int LDAP_init(LDAP ** ldap, int *capabilities)
{
    int rc = ldap_initialize(ldap, ldap_url);
    if (rc != LDAP_SUCCESS)
	fprintf(stderr, "%d: %s\n", __LINE__, ldap_err2string(rc));

    int i = LDAP_VERSION3;
    rc = ldap_set_option(*ldap, LDAP_OPT_PROTOCOL_VERSION, &i);
    if (rc != LDAP_SUCCESS)
	fprintf(stderr, "%d: %s\n", __LINE__, ldap_err2string(rc));

    i = LDAP_OPT_X_TLS_NEVER;
    rc = ldap_set_option(*ldap, LDAP_OPT_X_TLS_REQUIRE_CERT, &i);
    if (rc != LDAP_SUCCESS)
	fprintf(stderr, "%d: %s\n", __LINE__, ldap_err2string(rc));

    i = 0;
    rc = ldap_set_option(*ldap, LDAP_OPT_X_TLS_NEWCTX, &i);
    if (rc != LDAP_SUCCESS)
	fprintf(stderr, "%d: %s\n", __LINE__, ldap_err2string(rc));

    rc = ldap_set_option(*ldap, LDAP_OPT_REFERRALS, LDAP_OPT_OFF);
    if (rc != LDAP_SUCCESS)
	fprintf(stderr, "%d: %s\n", __LINE__, ldap_err2string(rc));

    rc = ldap_set_option(*ldap, LDAP_OPT_RESTART, LDAP_OPT_ON);
    if (rc != LDAP_SUCCESS)
	fprintf(stderr, "%d: %s\n", __LINE__, ldap_err2string(rc));

    rc = ldap_set_option(*ldap, LDAP_OPT_X_TLS_PROTOCOL_MIN, &ldap_tls_protocol_min);
    if (rc != LDAP_SUCCESS)
	fprintf(stderr, "%d: %s\n", __LINE__, ldap_err2string(rc));

    struct timeval tv = {.tv_sec = ldap_timeout };
    rc = ldap_set_option(*ldap, LDAP_OPT_TIMEOUT, &tv);
    if (rc != LDAP_SUCCESS)
	fprintf(stderr, "%d: %s\n", __LINE__, ldap_err2string(rc));

    tv.tv_sec = ldap_network_timeout;
    rc = ldap_set_option(*ldap, LDAP_OPT_NETWORK_TIMEOUT, &tv);
    if (rc != LDAP_SUCCESS)
	fprintf(stderr, "%d: %s\n", __LINE__, ldap_err2string(rc));

    rc = LDAP_bind(*ldap, ldap_dn, ldap_pw);
    if (rc != LDAP_SUCCESS)
	fprintf(stderr, "%d: %s: %s\n", __LINE__, ldap_dn, ldap_err2string(rc));

    if (!capabilities_set) {
	char *attrs[] = { "+", NULL };	// OpenLDAP
	LDAPMessage *res;
	rc = ldap_search_ext_s(*ldap, "", LDAP_SCOPE_BASE, "(objectClass=*)", attrs, 0, NULL, NULL, NULL, ldap_sizelimit, &res);
	if (rc == LDAP_SUCCESS)
	    capabilities_set = 1;
	else
	    fprintf(stderr, "%d: %s\n", __LINE__, ldap_err2string(rc));
	if (ldap_count_entries(*ldap, res))
	    *capabilities = LDAP_eval_rootdse(*ldap, res);
	ldap_msgfree(res);
	res = NULL;
	rc = ldap_search_ext_s(*ldap, "", LDAP_SCOPE_BASE, "(objectClass=*)", NULL, 0, NULL, NULL, NULL, ldap_sizelimit, &res);
	if (rc == LDAP_SUCCESS)
	    capabilities_set = 1;
	else
	    fprintf(stderr, "%d: %s\n", __LINE__, ldap_err2string(rc));
	if (ldap_count_entries(*ldap, res))
	    *capabilities = LDAP_eval_rootdse(*ldap, res);
	ldap_msgfree(res);
    }
    if (*capabilities & CAP_STARTTLS)
	ldap_start_tls_s(*ldap, NULL, NULL);

    if (rc != LDAP_SUCCESS)
	fprintf(stderr, "%d: %s\n", __LINE__, ldap_err2string(rc));

    return rc;
}

static int LDAP_bind(LDAP * ldap, const char *ldap_dn, const char *ldap_password)
{
    struct berval *ber = NULL;
    if (ldap_dn && ldap_password) {
	ber = alloca(sizeof(struct berval));
	ber->bv_len = strlen(ldap_password);
	ber->bv_val = (char *) ldap_password;
    }
    return ldap_sasl_bind_s(ldap, ldap_dn, LDAP_SASL_SIMPLE, ber, NULL, NULL, NULL);
}

static int LDAP_bind_user(LDAP * ldap, const char *ldap_dn, const char *ldap_password)
{
    struct berval ber = {.bv_len = strlen(ldap_password), ber.bv_val = (char *) ldap_password };
    return ldap_sasl_bind_s(ldap, ldap_dn, LDAP_SASL_SIMPLE, &ber, NULL, NULL, NULL);
}

struct dnhash {
    struct dnhash *next;
    size_t len;
    size_t match_start;
    size_t match_len;
    char name[1];
};

static struct dnhash **dnhash_new(void)
{
    return (struct dnhash **) calloc(256, sizeof(struct dnhash));
}

static void dnhash_drop(struct dnhash **h)
{
    for (int i = 0; i < 256; i++)
	while (h[i]) {
	    struct dnhash *next = h[i]->next;
	    free(h[i]);
	    h[i] = next;
	}
    free(h);
}

static int dnhash_add(struct dnhash **ha, char *dn, size_t match_start, size_t match_len)
{
    u_char hash = 0;
    size_t len = 0;

    for (char *s = dn; *s; s++) {
	hash ^= (u_char) * s;
	len++;
    }
    struct dnhash *h = ha[hash];
    while (h && (h->len != len || strcmp(h->name, dn)))
	h = h->next;
    if (h)
	return -1;
    h = calloc(1, sizeof(struct dnhash) + len);
    h->len = len;
    h->match_start = match_start;
    h->match_len = match_len;
    strncpy(h->name, dn, len);
    h->next = ha[hash];
    ha[hash] = h;
    return 0;
}

static int dnhash_add_entry(LDAP * ldap, struct dnhash **h, char *dn, int level)
{
    pcre2_match_data *match_data = pcre2_match_data_create_from_pattern(ldap_memberof_regex, NULL);
    int pcre_res = pcre2_match((pcre2_code *) ldap_memberof_regex, (PCRE2_SPTR8) dn, (PCRE2_SIZE) strlen(dn), 0, 0, match_data, NULL);
    if (pcre_res < 0 && pcre_res != PCRE2_ERROR_NOMATCH) {
	fprintf(stderr, "PCRE2 matching error: %d", pcre_res);
	return -1;
    }
    if (pcre_res == PCRE2_ERROR_NOMATCH)
	return -1;

    PCRE2_SIZE *ovector = pcre2_get_ovector_pointer(match_data);
    uint32_t ovector_count = pcre2_get_ovector_count(match_data);

    if (ovector_count < 1)
	return -1;

    size_t match_start = 0;
    size_t match_len = 0;
    if (ovector_count > 1) {
	match_start = ovector[2];
	match_len = ovector[3] - ovector[2];
    }

    int rc = dnhash_add(h, dn, match_start, match_len);
    if (match_data)
	pcre2_match_data_free(match_data);
    if (rc)
	return -1;

    if (level < 1 && ldap_group_depth > -2)
	return 0;

    char *attrs[] = { "memberOf", NULL };
    LDAPMessage *res = NULL;
    rc = ldap_search_ext_s(ldap, dn, LDAP_SCOPE_BASE, "(objectClass=*)", attrs, 0, NULL, NULL, NULL, ldap_sizelimit, &res);
    if (rc != LDAP_SUCCESS)
	fprintf(stderr, "%d: %s\n", __LINE__, ldap_err2string(rc));

    if (rc == LDAP_SUCCESS && ldap_count_entries(ldap, res) == 1) {
	LDAPMessage *entry = ldap_first_entry(ldap, res);

	BerElement *be = NULL;
	for (char *attribute = ldap_first_attribute(ldap, entry, &be); attribute; attribute = ldap_next_attribute(ldap, entry, be)) {
	    struct berval **v = ldap_get_values_len(ldap, entry, attribute);
	    if (v) {
		if (!strcasecmp(attribute, "memberOf")) {
		    int i = 0;
		    for (; v[i]; i++)
			dnhash_add_entry(ldap, h, v[i]->bv_val, level - 1);
		}
	    }
	    ldap_value_free_len(v);
	}
    }
    if (res)
	ldap_msgfree(res);

    return 0;
}

static int dnhash_add_entry_groupOfNames(LDAP * ldap, struct dnhash **h, char *dn, int level)
{
    if (level < 1 && ldap_group_depth > -2)
	return 0;

    char *attrs[] = { "member", NULL };
    LDAPMessage *res = NULL;
    size_t filter_len = strlen(dn) + ldap_filter_group_len;
    char *filter = alloca(filter_len);
    snprintf(filter, filter_len, ldap_filter_group, dn);
    int rc = ldap_search_ext_s(ldap, base_dn_group, scope_group, filter, attrs, 0, NULL, NULL, NULL, ldap_sizelimit, &res);
    if (rc != LDAP_SUCCESS)
	fprintf(stderr, "%d: %s\n", __LINE__, ldap_err2string(rc));

    if (rc == LDAP_SUCCESS) {
	LDAPMessage *entry;
	for (entry = ldap_first_entry(ldap, res); entry; entry = ldap_next_entry(ldap, entry)) {
	    char *gdn = ldap_get_dn(ldap, entry);
	    fprintf(stderr, "checking gdn %s\n", gdn);
	    pcre2_match_data *match_data = pcre2_match_data_create_from_pattern(ldap_memberof_regex, NULL);
	    int pcre_res = pcre2_match((pcre2_code *) ldap_memberof_regex, (PCRE2_SPTR8) gdn, (PCRE2_SIZE) strlen(gdn), 0, 0, match_data, NULL);
	    if (pcre_res < 0 && pcre_res != PCRE2_ERROR_NOMATCH) {
		fprintf(stderr, "PCRE2 matching error: %d", pcre_res);
		return -1;
	    }
	    if (pcre_res != PCRE2_ERROR_NOMATCH) {
		PCRE2_SIZE *ovector = pcre2_get_ovector_pointer(match_data);
		uint32_t ovector_count = pcre2_get_ovector_count(match_data);

		if (ovector_count < 1)
		    return -1;

		size_t match_start = 0;
		size_t match_len = 0;
		if (ovector_count > 1) {
		    match_start = ovector[2];
		    match_len = ovector[3] - ovector[2];
		}

		int rc = dnhash_add(h, gdn, match_start, match_len);
		if (!rc)
		    dnhash_add_entry_groupOfNames(ldap, h, gdn, level - 1);
	    }
	    if (match_data)
		pcre2_match_data_free(match_data);
	    ldap_memfree(gdn);
	}
    }
    if (res)
	ldap_msgfree(res);
    return 0;
}

struct ad_error_codes {
    char *id;
    char *text;
};

static struct ad_error_codes ad_error_codes[] = {
    { "525", "Invalid credentials." },	// "User not found.", actually
    { "52e", "Invalid credentials." },
    { "530", "Not permitted to logon at this time." },
    { "531", "Not permitted to logon at this workstation." },
    { "532", "Password expired." },
    { "533", "Account disabled." },
    { "701", "Account expired." },
    { "773", "User must reset password." },
    { "775", "User account locked." },
    { NULL, NULL },
};

static char *translate_ldap_error(char *err /* from ldap_err2string() */ , char *diag /* detailed errror */ , char **out /* freed by caller */ )
{
    if (capabilities & CAP_AD && diag) {
	pcre2_match_data *match_data = pcre2_match_data_create_from_pattern(ad_result_regex, NULL);
	int pcre_res = pcre2_match((pcre2_code *) ad_result_regex, (PCRE2_SPTR8) diag, (PCRE2_SIZE) strlen(diag), 0, 0, match_data, NULL);
	if (!pcre_res) {
	    PCRE2_SIZE *ovector = pcre2_get_ovector_pointer(match_data);
	    uint32_t ovector_count = pcre2_get_ovector_count(match_data);
	    if (ovector_count == 2) {
		size_t match_start = ovector[2];
		size_t match_len = ovector[3] - ovector[2];
		char *id = alloca(match_len + 1);
		strncpy(id, diag + match_start, match_len);
		id[match_len] = 0;
		struct ad_error_codes *a = ad_error_codes;
		while (a->id && strcmp(a->id, id))
		    a++;
		if (a->id) {
		    size_t out_len = 30 + strlen(a->text);
		    *out = calloc(1, out_len);
		    snprintf(*out, out_len, "Permission denied: %s", a->text);
		    return *out;
		}
	    }
	}
    }
    if (!err && !diag)
	return "Permission denied.";
    int len = 30 + (err ? strlen(err) : 0) + (diag ? strlen(diag) : 0);
    char *message = alloca(len + 30);
    snprintf(message, len, "%s%s%s", err ? err : "", (err && diag) ? ": " : "", diag ? diag : "");
    if (!strcmp(message, "invalidCredentials"))
	return "Permission denied.";
    char *m = message;
    for (; *m; m++)
	if (*m == '\n')
	    *m = ' ';
    size_t out_len = len + 30;
    *out = calloc(1, out_len);
    snprintf(*out, out_len, "Permission denied (%s).", message);
    return *out;
}

static pthread_mutex_t mutex_lock;

static void av_write(av_ctx * ac, uint32_t result)
{
    size_t len = av_array_to_char_len(ac);
    char *buf = alloca(len + sizeof(struct mavis_ext_hdr_v1));
    if (is_mt == TRISTATE_YES) {
	len = av_array_to_char(ac, buf + sizeof(struct mavis_ext_hdr_v1), len, NULL);

	struct mavis_ext_hdr_v1 *h = (struct mavis_ext_hdr_v1 *) buf;
	h->magic = htonl(MAVIS_EXT_MAGIC_V1);
	h->body_len = htonl((uint32_t) len);
	h->result = htonl(result);

	len += sizeof(struct mavis_ext_hdr_v1);
	pthread_mutex_lock(&mutex_lock);
	write(1, buf, len);
	pthread_mutex_unlock(&mutex_lock);
    } else {
	len = av_array_to_char(ac, buf, len, NULL);
	len += snprintf(buf + len, sizeof(struct mavis_ext_hdr_v1), "=%u\n", result);
	write(1, buf, len);
    }
    av_free(ac);
}

static void *run_thread(void *arg)
{
    LDAP *ldap = NULL;
    LDAP_init(&ldap, &capabilities);

    char buf[4096];
    *buf = 0;
    av_ctx *ac = (av_ctx *) arg;
    int result = MAVIS_DOWN;

    char *attrs[] = {
	"shadowExpire", "memberOf", "dn", "uidNumber", "gidNumber", "loginShell",
	"homeDirectory", "sshPublicKey", "krbPasswordExpiration", ldap_tacmember_attr, NULL
    };
    char *username = av_get(ac, AV_A_USER);
    size_t filter_len = ldap_filter_len + strlen(username);
    char *filter = alloca(filter_len);
    snprintf(filter, filter_len, ldap_filter, username);

    LDAPMessage *res = NULL;
    int rc = ldap_search_ext_s(ldap, base_dn, scope, filter, attrs, 0, NULL, NULL, NULL, ldap_sizelimit, &res);
    if (rc != LDAP_SUCCESS)
	fprintf(stderr, "%d: %s\n", __LINE__, ldap_err2string(rc));

    if (rc == LDAP_SUCCESS && ldap_count_entries(ldap, res) != 1) {
	av_set(ac, AV_A_RESULT, AV_V_RESULT_FAIL);
	result = MAVIS_FINAL;
    } else if (rc == LDAP_SUCCESS) {
	LDAPMessage *entry = ldap_first_entry(ldap, res);

	char *dn = ldap_get_dn(ldap, entry);
	av_set(ac, AV_A_DN, dn);

	time_t expiry = -1;
	int memberOfAdded = 0;

	char *tactype = av_get(ac, AV_A_TACTYPE);
	int is_auth = !strcmp(tactype, AV_V_TACTYPE_AUTH) || !strcmp(tactype, AV_V_TACTYPE_CHPW);

	BerElement *be = NULL;
	struct dnhash **hash = dnhash_new();

	for (char *attribute = ldap_first_attribute(ldap, entry, &be); attribute; attribute = ldap_next_attribute(ldap, entry, be)) {
	    struct berval **v = ldap_get_values_len(ldap, entry, attribute);
	    if (v) {
		if (!strcasecmp(attribute, "memberOf")) {
		    int i = 0;
		    for (i = 0; v[i]; i++)
			memberOfAdded |= !dnhash_add_entry(ldap, hash, v[i]->bv_val, ldap_group_depth);
		} else if (!strcasecmp(attribute, ldap_tacmember_attr)) {
		    size_t b_len = 4;
		    int i = 0;
		    for (i = 0; v[i]; i++)
			b_len += v[i]->bv_len;
		    char *b = calloc(1, b_len);
		    char *p = b;
		    for (i = 0; v[i]; i++) {
			if (*p != *b)
			    *p++ = ',';
			*p++ = '"';
			memcpy(p, v[i]->bv_val, v[i]->bv_len);
			p += v[i]->bv_len;
			*p++ = '"';
		    }
		    av_set(ac, AV_A_TACMEMBER, b);
		    free(b);
		} else if (!strcasecmp(attribute, "sshPublicKey")) {
		    size_t b_len = 4;
		    int i = 0;
		    for (i = 0; v[i]; i++)
			b_len += v[i]->bv_len;
		    char *b = calloc(1, b_len);
		    char *p = b;
		    for (i = 0; v[i]; i++) {
			if (*p != *b)
			    *p++ = ',';
			*p++ = '"';
			memcpy(p, v[i]->bv_val, v[i]->bv_len);
			p += v[i]->bv_len;
			*p++ = '"';
		    }
		    av_set(ac, AV_A_SSHKEY, b);
		    free(b);
		} else if (*v) {
		    if (!strcasecmp(attribute, "uidNumber")) {
			av_set(ac, AV_A_UID, v[0]->bv_val);
		    } else if (!strcasecmp(attribute, "gidNumber")) {
			av_set(ac, AV_A_GID, v[0]->bv_val);
		    } else if (!strcasecmp(attribute, "loginShell")) {
			av_set(ac, AV_A_SHELL, v[0]->bv_val);
		    } else if (!strcasecmp(attribute, "homeDirectory")) {
			av_set(ac, AV_A_SHELL, v[0]->bv_val);
		    } else if (!strcasecmp(attribute, "shadowExpire")) {
			int i = atoi(v[0]->bv_val);
			if (i > -1)
			    expiry = i * 86400;
		    } else if (!strcasecmp(attribute, "krbPasswordExpiration")) {
			struct tm tm = { 0 };
			char z;
			if (7 == sscanf(v[0]->bv_val, "%4d%2d%2d%2d%2d%2d%c", &tm.tm_year, &tm.tm_mon, &tm.tm_mday, &tm.tm_hour, &tm.tm_min, &tm.tm_sec, &z)
			    && z == 'Z') {
			    tm.tm_year -= 1900;
			    tm.tm_mon -= 1;
			    expiry = mktime(&tm);
			}
		    }
		}
		ldap_value_free_len(v);
	    }
	}

	if (!memberOfAdded)
	    memberOfAdded |= !dnhash_add_entry_groupOfNames(ldap, hash, dn, ldap_group_depth);

	char *tacmember_ou = "";
	if (ldap_tacmember_map_ou) {
	    tacmember_ou = alloca(strlen(dn));
	    char *d = dn;
	    char *t = tacmember_ou;
	    while (*d && *d != ',')
		d++;
	    while (*d) {
		if (d[0] == ',' && tolower((int) d[1]) == 'o' && tolower((int) d[2]) == 'u' && d[3] == '=') {
		    d += 4;
		    if (t != tacmember_ou)
			*t++ = ',';
		    *t++ = '"';
		    while (*d && *d != ',')
			*t++ = *d++;
		    *t++ = '"';
		    if (*d)
			d++;
		} else
		    do {
			d++;
		    } while (*d && *d != ',');
	    }
	    *t = 0;
	}

	int i;
	int tacmember_len = strlen(tacmember_ou) + 1;
	int memberof_len = 0;
	for (i = 0; i < 256; i++) {
	    struct dnhash *h = hash[i];
	    for (; h; h = h->next) {
		memberof_len += 3 + h->len;
		tacmember_len += 3 + h->match_len;
	    }
	}
	if (tacmember_len || memberof_len) {
	    char *t = alloca(tacmember_len < memberof_len ? memberof_len : tacmember_len);
	    if (memberof_len) {
		char *b = t;
		for (i = 0; i < 256; i++) {
		    struct dnhash *h = hash[i];
		    for (; h; h = h->next) {
			if (b != t)
			    *b++ = ',';
			*b++ = '"';
			memcpy(b, h->name, h->len);
			b += h->len;
			*b++ = '"';
		    }
		}
		*b = 0;
		av_set(ac, AV_A_MEMBEROF, t);
	    }
	    if (tacmember_len) {
		char *b = t;
		while (*tacmember_ou)
		    *b++ = *tacmember_ou++;
		for (i = 0; i < 256; i++) {
		    struct dnhash *h = hash[i];
		    for (; h; h = h->next) {
			if (b != t)
			    *b++ = ',';
			*b++ = '"';
			memcpy(b, h->name + h->match_start, h->match_len);
			b += h->match_len;
			*b++ = '"';
		    }
		}
		*b = 0;
		av_set(ac, AV_A_TACMEMBER, t);
	    }
	}
	dnhash_drop(hash);

	ldap_msgfree(res);

	if (is_auth) {
	    char *cap = av_get(ac, AV_A_CALLER_CAP);
	    int caller_cap_chpw = (cap && strstr(cap, ":chpw:"));

	    if (expiry > -1 && expiry < time(NULL)) {
		av_set(ac, AV_A_USER_RESPONSE, "Password has expired.");
		if (caller_cap_chpw && (capabilities & (CAP_PWMODIFY | CAP_AD)))
		    av_set(ac, AV_A_PASSWORD_MUSTCHANGE, "1");
		else {
		    av_set(ac, AV_A_RESULT, AV_V_RESULT_FAIL);
		    av_write(ac, MAVIS_FINAL);
		    ldap_memfree(dn);
		    if (ldap)
			ldap_unbind_ext_s(ldap, NULL, NULL);
		    return NULL;
		}
	    }
	    rc = LDAP_bind_user(ldap, dn, av_get(ac, AV_A_PASSWORD));
	    if (rc == LDAP_SUCCESS) {
		av_set(ac, AV_A_RESULT, AV_V_RESULT_OK);
		result = MAVIS_FINAL;
	    } else {
		char *diag = NULL;
		char *out = NULL;
		ldap_get_option(ldap, LDAP_OPT_DIAGNOSTIC_MESSAGE, (void *) &diag);
		char *err = ldap_err2string(rc);
		if (rc == LDAP_INVALID_CREDENTIALS && (capabilities & CAP_AD) && caller_cap_chpw
		    && !pcre2_match((pcre2_code *) ad_dsid_regex, (PCRE2_SPTR8) diag, (PCRE2_SIZE) strlen(diag), 0, 0, NULL, NULL)
		    ) {
		    if (!strcmp(tactype, AV_V_TACTYPE_AUTH)) {
			av_set(ac, AV_A_USER_RESPONSE, "Password has expired.");
			av_set(ac, AV_A_RESULT, AV_V_RESULT_OK);
			av_set(ac, AV_A_PASSWORD_MUSTCHANGE, "1");
			result = MAVIS_FINAL;
		    }
		} else {
		    av_set(ac, AV_A_USER_RESPONSE, translate_ldap_error(err, diag, &out));
		    av_set(ac, AV_A_RESULT, AV_V_RESULT_FAIL);
		}
		if (out)
		    free(out);
		if (diag)
		    ldap_memfree(diag);
	    }
	} else if (!strcmp(tactype, AV_V_TACTYPE_INFO)) {
	    result = MAVIS_FINAL;
	    av_set(ac, AV_A_RESULT, AV_V_RESULT_OK);
	} else {
	    av_set(ac, AV_A_RESULT, AV_V_RESULT_FAIL);
	    result = MAVIS_FINAL;
	}
	if (!strcmp(tactype, AV_V_TACTYPE_CHPW)) {
	    if (capabilities & CAP_AD) {
		char *oldpw = av_get(ac, AV_A_PASSWORD);
		size_t oldpw_len = strlen(oldpw);
		char *quoted_oldpw = alloca(oldpw_len + 3);
		*quoted_oldpw = '"';
		memcpy(quoted_oldpw + 1, oldpw, oldpw_len++);
		quoted_oldpw[oldpw_len++] = '"';
		quoted_oldpw[oldpw_len++] = 0;
		char *oldpw16 = NULL;
		size_t oldpw16_len = 0;

		char *newpw = av_get(ac, AV_A_PASSWORD_NEW);
		size_t newpw_len = strlen(newpw);
		char *quoted_newpw = alloca(newpw_len + 3);
		*quoted_newpw = '"';
		memcpy(quoted_newpw + 1, newpw, newpw_len++);
		quoted_newpw[newpw_len++] = '"';
		quoted_newpw[newpw_len++] = 0;
		char *newpw16 = NULL;
		size_t newpw16_len = 0;

		if (!utf8_to_utf16le(quoted_oldpw, oldpw_len, &oldpw16, &oldpw16_len)
		    && !utf8_to_utf16le(quoted_newpw, newpw_len, &newpw16, &newpw16_len)) {

		    struct berval oldber;
		    oldber.bv_len = oldpw16_len;
		    oldber.bv_val = oldpw16;
		    struct berval *oldval[] = { &oldber, NULL };
		    LDAPMod oldattr;
		    oldattr.mod_bvalues = oldval;
		    oldattr.mod_type = "unicodePwd";
		    oldattr.mod_op = LDAP_MOD_DELETE | LDAP_MOD_BVALUES;

		    struct berval newber;
		    newber.bv_len = newpw16_len;
		    newber.bv_val = newpw16;
		    struct berval *newval[] = { &newber, NULL };
		    LDAPMod newattr;
		    newattr.mod_bvalues = newval;
		    newattr.mod_type = "unicodePwd";
		    newattr.mod_op = LDAP_MOD_ADD | LDAP_MOD_BVALUES;

		    LDAPMod *mod[3];
		    mod[0] = &oldattr;
		    mod[1] = &newattr;
		    mod[2] = NULL;

		    int rc = ldap_modify_ext_s(ldap, dn, mod, NULL, NULL);

		    if (rc == LDAP_SUCCESS) {
			av_set(ac, AV_A_RESULT, AV_V_RESULT_OK);
		    } else {
			av_set(ac, AV_A_RESULT, AV_V_RESULT_FAIL);
			av_set(ac, AV_A_USER_RESPONSE, ldap_err2string(rc));
		    }
		}
		if (oldpw16)
		    free(oldpw16);
		if (newpw16)
		    free(newpw16);
	    } else if (capabilities & CAP_PWMODIFY) {
		BerElement *ber = ber_alloc_t(LBER_USE_DER);
		ber_printf(ber, "{tststsN}",
			   LDAP_TAG_EXOP_MODIFY_PASSWD_ID, dn,
			   LDAP_TAG_EXOP_MODIFY_PASSWD_OLD, av_get(ac, AV_A_PASSWORD), LDAP_TAG_EXOP_MODIFY_PASSWD_NEW, av_get(ac, AV_A_PASSWORD_NEW));

		struct berval bv = { 0, NULL };
		ber_flatten2(ber, &bv, 0);
		int rc = ldap_extended_operation_s(ldap, LDAP_EXOP_MODIFY_PASSWD, &bv, NULL, NULL, NULL, NULL);
		ber_free(ber, 1);

		if (rc == LDAP_SUCCESS) {
		    av_set(ac, AV_A_RESULT, AV_V_RESULT_OK);
		} else {
		    av_set(ac, AV_A_RESULT, AV_V_RESULT_FAIL);
		    av_set(ac, AV_A_USER_RESPONSE, ldap_err2string(rc));
		}
	    } else {
		av_set(ac, AV_A_RESULT, AV_V_RESULT_FAIL);
	    }
	    result = MAVIS_FINAL;
	}

	if (ldap)
	    ldap_unbind_ext_s(ldap, NULL, NULL);
	ldap_memfree(dn);
    } else {
	av_set(ac, AV_A_RESULT, AV_V_RESULT_ERROR);
	result = MAVIS_FINAL;
    }
    av_write(ac, result);
    return NULL;
}

int main(int argc, char **argv __attribute__((unused)))
{
    if (argc > 1)
	usage();

    ldap_url = getenv("LDAP_HOSTS");
    if (!ldap_url)
	ldap_url = getenv("LDAP_URL");
    if (!ldap_url)
	ldap_url = "ldaps://localhost ldap://localhost";

    char *tmp;
    tmp = getenv("LDAP_SCOPE");
    if (tmp) {
	if (strcasecmp(tmp, "base"))
	    scope = LDAP_SCOPE_BASE;
	else if (strcasecmp(tmp, "level"))
	    scope = LDAP_SCOPE_ONELEVEL;
	else if (strcasecmp(tmp, "onelevel"))
	    scope = LDAP_SCOPE_ONELEVEL;
	else if (strcasecmp(tmp, "subtree"))
	    scope = LDAP_SCOPE_SUBTREE;
	else
	    fprintf(stderr, "LDAP scope '%s' not recognized, will be ignored.\n", tmp);
    }

    tmp = getenv("LDAP_SCOPE_GROUP");
    if (tmp) {
	if (strcasecmp(tmp, "base"))
	    scope_group = LDAP_SCOPE_BASE;
	else if (strcasecmp(tmp, "level"))
	    scope_group = LDAP_SCOPE_ONELEVEL;
	else if (strcasecmp(tmp, "onelevel"))
	    scope_group = LDAP_SCOPE_ONELEVEL;
	else if (strcasecmp(tmp, "subtree"))
	    scope_group = LDAP_SCOPE_SUBTREE;
	else
	    fprintf(stderr, "LDAP scope '%s' not recognized, will be ignored.\n", tmp);
    }

    base_dn = getenv("LDAP_BASE");
    if (!base_dn) {
	fprintf(stderr, "No Base DN specified, aborting.\n");
	exit(EXIT_FAILURE);
    }

    base_dn_group = getenv("LDAP_BASE_GROUP");
    if (!base_dn_group)
	base_dn_group = base_dn;

    tmp = getenv("LDAP_TIMEOUT");
    if (tmp)
	ldap_timeout = atoi(tmp);

    tmp = getenv("LDAP_NETWORK_TIMEOUT");
    if (tmp)
	ldap_network_timeout = atoi(tmp);

    tmp = getenv("LDAP_SIZELIMIT");
    if (tmp)
	ldap_sizelimit = atoi(tmp);

    tmp = getenv("LDAP_MEMBEROF_REGEX");
    if (!tmp) {
	fprintf(stderr, "Please consider customizing \"LDAP_MEMBEROF_REGEX\", otherwise it will match all groups.\n");
	tmp = "^cn=([^,]+),.*";
    }
    PCRE2_SIZE erroffset;
    int errcode = 0;
    ldap_memberof_regex = pcre2_compile((PCRE2_SPTR8) tmp, PCRE2_ZERO_TERMINATED, PCRE2_CASELESS | PCRE2_UTF, &errcode, &erroffset, NULL);
    if (!ldap_memberof_regex) {
	PCRE2_UCHAR buffer[256];
	pcre2_get_error_message(errcode, buffer, sizeof(buffer));
	fprintf(stderr, "In PCRE2 expression \"%s\" at offset %d: %s", tmp, (int) erroffset, buffer);
    }

    ldap_tacmember_attr = getenv("LDAP_TACMEMBER");
    if (!ldap_tacmember_attr)
	ldap_tacmember_attr = "tacMember";

    tmp = getenv("LDAP_NESTED_GROUP_DEPTH");
    if (tmp)
	ldap_group_depth = atoi(tmp);

    tmp = getenv("LDAP_TLS_PROTOCOL_MIN");
    if (tmp) {
	if (!strcmp(tmp, "TLS1_0"))
	    ldap_tls_protocol_min = LDAP_OPT_X_TLS_PROTOCOL_TLS1_0;
	else if (!strcmp(tmp, "TLS1_1"))
	    ldap_tls_protocol_min = LDAP_OPT_X_TLS_PROTOCOL_TLS1_1;
	else if (!strcmp(tmp, "TLS1_2"))
	    ldap_tls_protocol_min = LDAP_OPT_X_TLS_PROTOCOL_TLS1_2;
#ifdef LDAP_OPT_X_TLS_PROTOCOL_TLS1_3
	else if (!strcmp(tmp, "TLS1_3"))
	    ldap_tls_protocol_min = LDAP_OPT_X_TLS_PROTOCOL_TLS1_3;
#endif
	else
	    fprintf(stderr, "LDAP_TLS_PROTOCOL_MIN: %s unrecognized, ignoring\n", tmp);
    }

    ldap_filter = getenv("LDAP_FILTER");
    ldap_filter_group = getenv("LDAP_FILTER_GROUP");
    ldap_dn = getenv("LDAP_USER");
    ldap_pw = getenv("LDAP_PASSWD");

    errcode = 0;
    ad_result_regex = pcre2_compile((PCRE2_SPTR8) ",\\s+data\\s+([^,]+),", PCRE2_ZERO_TERMINATED, 0, &errcode, &erroffset, NULL);

    if (!ad_result_regex)
	fprintf(stderr, "trouble at line %d\n", __LINE__ - 1);
    if (!ad_result_regex) {
	PCRE2_UCHAR buffer[1024];
	pcre2_get_error_message(errcode, buffer, sizeof(buffer));
	fprintf(stderr, "PCRE2 error: %s\n", buffer);
    }



    ad_dsid_regex = pcre2_compile((PCRE2_SPTR8) "DSID-.*, data (532|533|773) ", PCRE2_ZERO_TERMINATED, 0, &errcode, &erroffset, NULL);
    if (!ad_dsid_regex)
	fprintf(stderr, "trouble at line %d\n", __LINE__ - 1);
    if (!ad_result_regex) {
	PCRE2_UCHAR buffer[1024];
	pcre2_get_error_message(errcode, buffer, sizeof(buffer));
	fprintf(stderr, "PCRE2 error: %s\n", buffer);
    }

    LDAP *ldap = NULL;
    int result = LDAP_init(&ldap, &capabilities);
    if (result)
	fprintf(stderr, "%d: %s\n", __LINE__, ldap_err2string(result));

    if (capabilities & CAP_389DS && (!ldap_dn || !ldap_pw))
	fprintf(stderr, "The 389 directory server will not return the memberOf attribute for anonymous binds. "
		"Please set the LDAP_USER and LDAP_PASSWD environment variables.\n");
    if (!ldap_filter)
	ldap_filter = (capabilities & CAP_AD) ? "(&(objectclass=user)(sAMAccountName=%s))" : "(uid=%s)";
    ldap_filter_len = strlen(ldap_filter);

    if (!ldap_filter_group)
	ldap_filter_group = "(&(objectclass=groupOfNames)(member=%s))";
    ldap_filter_group_len = strlen(ldap_filter_group);

    {
	struct rlimit rlim;
	getrlimit(RLIMIT_NOFILE, &rlim);
	rlim.rlim_cur = rlim.rlim_max;
	setrlimit(RLIMIT_NOFILE, &rlim);
    }

    while (1) {
	struct mavis_ext_hdr_v1 hdr;
	size_t hdr_off = 0;
	av_ctx *ac = NULL;

	if (is_mt != TRISTATE_NO) {
	    while (sizeof(struct mavis_ext_hdr_v1) != hdr_off) {
		int len = read(0, (char *) &hdr + hdr_off, sizeof(struct mavis_ext_hdr_v1) - hdr_off);
		if (len < 1) {
		    exit(-1);
		}
		hdr_off += len;
	    }
	}

	if (is_mt != TRISTATE_NO && ntohl(hdr.magic) == MAVIS_EXT_MAGIC_V1) {
	    if (is_mt == TRISTATE_DUNNO) {
		if (pthread_mutex_init(&mutex_lock, NULL))
		    fprintf(stderr, "pthread_mutex_init() failed, expect trouble\n");
		is_mt = TRISTATE_YES;
	    }
	    size_t len = ntohl(hdr.body_len);
	    char *b = calloc(1, len + 1);
	    size_t off = 0;
	    while (len - off > 0) {
		size_t nlen = read(0, b + off, len - off);
		if (nlen < 1) {
		    fprintf(stderr, "Short read (body).\n");
		    exit(1);
		}
		off += nlen;
	    }
	    ac = av_new(NULL, NULL);
	    av_char_to_array(ac, b, NULL);
	    free(b);
	} else {
	    if (is_mt == TRISTATE_YES) {
		fprintf(stderr, "Bad magic.\n");
		exit(-1);
	    } else {
		static char *buf = NULL;
#define BUFSIZE 4095
		if (!buf)
		    buf = calloc(1, BUFSIZE + 1);
		static size_t off = 0;
		if (is_mt == TRISTATE_DUNNO) {
		    memcpy(buf, &hdr, sizeof(hdr));
		    off = sizeof(hdr);
		    fcntl(0, F_SETFL, O_NONBLOCK);
		    is_mt = TRISTATE_NO;
		}
		struct pollfd pfd = {.events = POLLIN };
		char *end = strstr(buf, "\n=\n");
		while (end || (1 == poll(&pfd, 1, -1) && off < BUFSIZE)) {
		    if (!end) {
			ssize_t len = read(0, buf + off, BUFSIZE - off);
			if (len < 1) {
			    exit(-1);
			}
			off += len;
			buf[off] = 0;
			end = strstr(buf, "\n=\n");
		    }
		    if (end) {
			*(end + 1) = 0;
			ac = av_new(NULL, NULL);
			av_char_to_array(ac, buf, NULL);
			end += 3;
			memmove(buf, end, off - (end - buf) + 1);
			off -= end - buf;
			break;
		    }
		}
		if (!ac) {
		    fprintf(stderr, "Legacy read buffer too small\n");
		    exit(-1);
		}
	    }
	}

	char *tactype = av_get(ac, AV_A_TACTYPE);
	if (!tactype) {
	    av_write(ac, MAVIS_DOWN);
	} else if (!av_get(ac, AV_A_PASSWORD) && !strcmp(tactype, AV_V_TACTYPE_AUTH)) {
	    av_set(ac, AV_A_RESULT, AV_V_RESULT_FAIL);
	    av_write(ac, MAVIS_FINAL);
	} else if ((!av_get(ac, AV_A_PASSWORD) || !av_get(ac, AV_A_PASSWORD_NEW)) && !strcmp(tactype, AV_V_TACTYPE_CHPW)) {
	    av_set(ac, AV_A_RESULT, AV_V_RESULT_FAIL);
	    av_write(ac, MAVIS_FINAL);
	} else if (is_mt == TRISTATE_YES) {
	    pthread_t thread;
	    pthread_attr_t thread_attr;
	    pthread_attr_init(&thread_attr);
	    char *fname = "pthread_create";
	    int res = pthread_attr_setdetachstate(&thread_attr, PTHREAD_CREATE_DETACHED);
	    if (res)
		fname = "pthread_attr_setdetachstate";
	    else
		res = pthread_create(&thread, &thread_attr, run_thread, ac);
	    if (res) {
		char *err = strerror(res);
		av_setf(ac, AV_A_COMMENT, "%s(): %s%s[%d]", fname, err ? err : "", err ? " " : "", res);
		fprintf(stderr, "%s\n", av_get(ac, AV_A_COMMENT));
		av_set(ac, AV_A_RESULT, AV_V_RESULT_ERROR);
		av_write(ac, MAVIS_FINAL);
	    }
	} else {
	    run_thread(ac);
	}
    }
    exit(EX_OK);
}
