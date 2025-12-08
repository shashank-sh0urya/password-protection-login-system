#include <microhttpd.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define PORT 8080

char stored_user[50];
char stored_salt[20];
char stored_hash[70];
int current_otp = 0;

/* ---------- Structure for POST data ---------- */
struct post_data {
    char username[64];
    char password[64];
    char otp[10];
};

/* ---------- JSON helper ---------- */
struct MHD_Response* json_response(const char *data) {
    struct MHD_Response *res =
        MHD_create_response_from_buffer(strlen(data), (void *)data, MHD_RESPMEM_PERSISTENT);
    MHD_add_response_header(res, "Content-Type", "application/json");
    return res;
}

/* ---------- Generate Salt ---------- */
void generate_salt(char *salt) {
    const char *chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    for (int i = 0; i < 16; i++) {
        salt[i] = chars[rand() % strlen(chars)];
    }
    salt[16] = '\0';
}

/* ---------- Hash Password ---------- */
void hash_password(const char *password, const char *salt, char *output) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    char salted[200];
    snprintf(salted, sizeof(salted), "%s%s", salt, password);
    SHA256((unsigned char *)salted, strlen(salted), hash);

    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        sprintf(output + (i * 2), "%02x", hash[i]);
}

/* ---------- Strong password check ---------- */
int is_strong_password(const char *p) {
    int len = strlen(p);
    int u=0,l=0,n=0,s=0;
    if (len < 12) return 0;

    for (int i = 0; i < len; i++) {
        if (p[i] >= 'A' && p[i] <= 'Z') u=1;
        else if (p[i] >= 'a' && p[i] <= 'z') l=1;
        else if (p[i] >= '0' && p[i] <= '9') n=1;
        else s=1;
    }
    return (u && l && n && s);
}

/* ---------- POST Data Parser ---------- */
static enum MHD_Result post_iterator(void *cls, enum MHD_ValueKind kind,
                         const char *key, const char *filename,
                         const char *content_type, const char *transfer_encoding,
                         const char *data, uint64_t off, size_t size) {

    struct post_data *pd = (struct post_data *)cls;

    if (strcmp(key, "username") == 0) {
        strncpy(pd->username, data, size);
        pd->username[size] = '\0';
    }

    if (strcmp(key, "password") == 0) {
        strncpy(pd->password, data, size);
        pd->password[size] = '\0';
    }

    if (strcmp(key, "otp") == 0) {
        strncpy(pd->otp, data, size);
        pd->otp[size] = '\0';
    }

    return MHD_YES;
}

/* ---------- Request Handler ---------- */
static enum MHD_Result request_handler(void *cls, struct MHD_Connection *connection,
                                       const char *url, const char *method,
                                       const char *version, const char *upload_data,
                                       size_t *upload_data_size, void **con_cls) {

    static struct post_data pd;
    static struct MHD_PostProcessor *pp = NULL;

    if (strcmp(method, "POST") != 0)
        return MHD_NO;

    if (*con_cls == NULL) {
        *con_cls = &pd;
        memset(&pd, 0, sizeof(pd));
        pp = MHD_create_post_processor(connection, 1024, post_iterator, &pd);
        return MHD_YES;
    }

    if (*upload_data_size != 0) {
        MHD_post_process(pp, upload_data, *upload_data_size);
        *upload_data_size = 0;
        return MHD_YES;
    }

    MHD_destroy_post_processor(pp);

    /* ---------- REGISTER ---------- */
    if (strcmp(url, "/register") == 0) {
        if (strlen(pd.username) == 0 || strlen(pd.password) == 0) {
            struct MHD_Response *res = json_response("{\"error\":\"Missing fields\"}");
            return MHD_queue_response(connection, 400, res);
        }

        if (!is_strong_password(pd.password)) {
            struct MHD_Response *res = json_response("{\"error\":\"Weak password\"}");
            return MHD_queue_response(connection, 400, res);
        }

        strcpy(stored_user, pd.username);
        generate_salt(stored_salt);
        hash_password(pd.password, stored_salt, stored_hash);

        struct MHD_Response *res = json_response("{\"message\":\"User registered\"}");
        return MHD_queue_response(connection, 200, res);
    }

    /* ---------- LOGIN ---------- */
    if (strcmp(url, "/login") == 0) {
        char temp_hash[70];
        hash_password(pd.password, stored_salt, temp_hash);

        if (strcmp(pd.username, stored_user) != 0 || strcmp(temp_hash, stored_hash) != 0) {
            struct MHD_Response *res = json_response("{\"error\":\"Invalid credentials\"}");
            return MHD_queue_response(connection, 401, res);
        }

        current_otp = rand() % 900000 + 100000;
        char buf[128];
        sprintf(buf, "{\"message\":\"OTP generated\",\"otp\":%d}", current_otp);

        struct MHD_Response *res = json_response(buf);
        return MHD_queue_response(connection, 200, res);
    }

    /* ---------- VERIFY OTP ---------- */
    if (strcmp(url, "/verify-otp") == 0) {
        int otp = atoi(pd.otp);

        if (otp == current_otp) {
            struct MHD_Response *res = json_response("{\"message\":\"Login successful\"}");
            return MHD_queue_response(connection, 200, res);
        } else {
            struct MHD_Response *res = json_response("{\"error\":\"Invalid OTP\"}");
            return MHD_queue_response(connection, 401, res);
        }
    }

    return MHD_NO;
}

/* ---------- MAIN ---------- */
int main() {
    srand(time(NULL));

    struct MHD_Daemon *daemon =
        MHD_start_daemon(MHD_USE_SELECT_INTERNALLY, PORT,
                         NULL, NULL, &request_handler, NULL, MHD_OPTION_END);

    if (!daemon) {
        printf("Failed to start server\n");
        return 1;
    }

    printf("Secure server running at http://localhost:%d\n", PORT);
    getchar();

    MHD_stop_daemon(daemon);
    return 0;
}
