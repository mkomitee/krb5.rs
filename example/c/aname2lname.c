#include <stdio.h>
#include <string.h>
#include <krb5.h>

const int MAX_USERNAME = 256;
const char* prog = "aname2lname";

int check(const char* principal) {
    krb5_context ctx = NULL;
    krb5_principal princ = NULL;
    krb5_error_code code;
    char lname[MAX_USERNAME];
    int result = 0;

    code = krb5_init_context(&ctx);
    if (code != 0) {
        fprintf(stderr, "%s: error in krb5_init_context: %d\n", prog, code);
        result = 1;
        goto end;
    }

    code = krb5_parse_name(ctx, principal, &princ);
    if (code != 0) {
        fprintf(stderr, "%s: error in krb5_parse_name: %d\n", prog, code);
        result = 1;
        goto end;
    }

    code = krb5_aname_to_localname(ctx, princ, MAX_USERNAME-1, lname);
    if (code != 0) {
        fprintf(stderr, "%s: error in krb5_aname_to_localname: %d\n",
                prog,
                code);
        result = 1;
        goto end;
    }

    if (strcmp(lname, "user") != 0) {
        fprintf(stderr, "%s: error, got %s, expected %s\n", prog, lname, "user");
        result = 1;
        goto end;
    }

    fprintf(stderr, "%s: ok\n", prog);

end:
    if (princ != NULL) {
        krb5_free_principal(ctx, princ);
    }
    if (ctx != NULL) {
        krb5_free_context(ctx);
    }
    return result;
}

int main() {
    return check("user@EXAMPLE.COM");
}
