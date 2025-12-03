#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>
#include <openssl/sha.h>

// Function to generate random salt
void generateSalt(char *salt, int length) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    for (int i = 0; i < length; i++) {
        salt[i] = charset[rand() % (sizeof(charset) - 1)];
    }
    salt[length] = '\0';
}

// SHA-256 hashing
void hashPassword(const char *password, const char *salt, char *outputHash) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    char saltedPassword[200];

    snprintf(saltedPassword, sizeof(saltedPassword), "%s%s", salt, password);
    SHA256((unsigned char *)saltedPassword, strlen(saltedPassword), hash);

    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        sprintf(outputHash + (i * 2), "%02x", hash[i]);
}

// Strong password validation
int validatePassword(char *password) {
    int len = strlen(password);
    int up=0, low=0, num=0, special=0;

    if (len < 12) return 0;

    for (int i = 0; i < len; i++) {
        if (isupper(password[i])) up = 1;
        else if (islower(password[i])) low = 1;
        else if (isdigit(password[i])) num = 1;
        else special = 1;
    }

    return (up && low && num && special);
}

// MFA: Generate a 6-digit OTP
int generateOTP() {
    return rand() % 900000 + 100000;
}

// Registration function
void registerUser() {
    char username[50], password[50];
    char salt[16], hash[65];

    printf("Enter username: ");
    scanf("%s", username);

    do {
        printf("Create strong password: ");
        scanf("%s", password);

        if (!validatePassword(password))
            printf("Password must be at least 12 characters long and contain uppercase, "
                   "lowercase, digits, and symbols.\n");
    } while (!validatePassword(password));

    generateSalt(salt, 15);
    hashPassword(password, salt, hash);

    FILE *fp = fopen("users.txt", "w");
    fprintf(fp, "%s %s %s\n", username, salt, hash);
    fclose(fp);

    printf("\nUser registered successfully!\n");
}

// Login function
void loginUser() {
    char username[50], password[50];
    char fileUser[50], salt[20], storedHash[70];
    char computedHash[70];

    FILE *fp = fopen("users.txt", "r");
    if (!fp) {
        printf("No registered user found. Register first.\n");
        return;
    }

    fscanf(fp, "%s %s %s", fileUser, salt, storedHash);
    fclose(fp);

    printf("Username: ");
    scanf("%s", username);

    if (strcmp(username, fileUser) != 0) {
        printf("User not found.\n");
        return;
    }

    printf("Password: ");
    scanf("%s", password);

    hashPassword(password, salt, computedHash);

    if (strcmp(computedHash, storedHash) == 0) {
        int otp = generateOTP();
        int userOtp;

        printf("\nMFA Enabled! Your OTP is: %d\n", otp);
        printf("Enter OTP: ");
        scanf("%d", &userOtp);

        if (userOtp == otp) {
            printf("\nLogin Successful! Access Granted.\n");
        } else {
            printf("Invalid OTP. Access Denied.\n");
        }

    } else {
        printf("Incorrect password.\n");
    }
}

int main() {
    srand(time(0));
    int choice;

    while (1) {
        printf("\n===== SECURE LOGIN SYSTEM =====\n");
        printf("1. Register\n");
        printf("2. Login\n");
        printf("3. Exit\n");
        printf("Choose option: ");
        scanf("%d", &choice);

        switch (choice) {
            case 1: registerUser(); break;
            case 2: loginUser(); break;
            case 3: exit(0);
            default: printf("Invalid choice!\n");
        }
    }

    return 0;
}
