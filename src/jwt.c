/*
Copyright (c) 2009-2021 Roger Light <roger@atchoo.org>

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License 2.0
and Eclipse Distribution License v1.0 which accompany this distribution.

The Eclipse Public License is available at
   https://www.eclipse.org/legal/epl-2.0/
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.

SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause

Contributors:
   Roger Light - initial implementation and documentation.
*/

#include "config.h"

#if defined(WITH_BRIDGE) && defined(WITH_CJSON) && defined(WITH_TLS)

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#include <cjson/cJSON.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include "json_help.h"
#include "base64_mosq.h"
#include "logging_mosq.h"
#include "memory_mosq.h"

static char *create_header(void);
static char *create_claim_set(char *audience, time_t issued_at, time_t expiration);
static char *base64url_encode(char *in, size_t in_len);
static EVP_PKEY *read_private_key(char *keyfile);
static char *sign(EVP_PKEY *key, char *in, size_t len_in, int *len_out);

char *jwt__create(char *audience, time_t issued_at, time_t expiration, char *keyfile)
{
	char *header;
	char *claims;
	char *jwt_raw;
	char *header_enc;
	char *claims_enc;
	EVP_PKEY *key;
	char *rsa_buf;
	int rsa_buf_len;
	char *rsa_buf_enc;
	char *jwt = NULL;

	header = create_header();
	if (NULL == header) goto err1;
	claims = create_claim_set(audience, issued_at, expiration);
	if (NULL == claims) goto err2;

	header_enc = base64url_encode(header, strlen(header));
	if (NULL == header_enc) goto err3;
	claims_enc = base64url_encode(claims, strlen(claims));
	if (NULL == claims_enc) goto err4;

	jwt_raw = mosquitto__malloc(strlen(header_enc) + strlen(claims_enc) + 2);
	if (NULL == jwt_raw) goto err5;
	sprintf(jwt_raw, "%s.%s", header_enc, claims_enc);

	key = read_private_key(keyfile);
	if (NULL == key) {
		log__printf(NULL, MOSQ_LOG_ERR, "Error reading private key from file %s", keyfile);
		goto err6;
	}

	rsa_buf = sign(key, jwt_raw, strlen(jwt_raw), &rsa_buf_len);
	if (NULL == rsa_buf) goto err7;

	rsa_buf_enc = base64url_encode(rsa_buf, (size_t) rsa_buf_len);
	if (NULL == rsa_buf_enc) goto err8;

	jwt = mosquitto__malloc(strlen(jwt_raw) + strlen(rsa_buf_enc) + 2);
	if (NULL == jwt) goto err9;

	sprintf(jwt, "%s.%s", jwt_raw, rsa_buf_enc);

err9:
	mosquitto__free(rsa_buf_enc);
err8:
	mosquitto__free(rsa_buf);
err7:
	mosquitto__free(key);
err6:
	mosquitto__free(jwt_raw);
err5:
	mosquitto__free(claims_enc);
err4:
	mosquitto__free(header_enc);
err3:
	mosquitto__free(claims);
err2:
	mosquitto__free(header);
err1:

	return jwt;
}

static char *create_header(void)
{
	char *json_str;
	cJSON *header = cJSON_CreateObject();

	cJSON *typ = cJSON_CreateStringReference("JWT");
	cJSON *alg = cJSON_CreateStringReference("RS256");

	cJSON_AddItemToObject(header, "typ", typ);
	cJSON_AddItemToObject(header, "alg", alg);

	json_str = cJSON_PrintUnformatted(header);
	cJSON_Delete(header);

	return json_str;
}

static char *create_claim_set(char *audience, time_t issued_at, time_t expiration)
{
	char *json_str;

	cJSON *claims = cJSON_CreateObject();

	cJSON *aud = cJSON_CreateString(audience);

	cJSON_AddIntToObject(claims, "iat", (int) issued_at);
	cJSON_AddIntToObject(claims, "exp", (int) expiration);
	cJSON_AddItemToObject(claims, "aud", aud);

	json_str = cJSON_PrintUnformatted(claims);
	cJSON_Delete(claims);

	return json_str;
}

static char *base64url_encode(char *in, size_t in_len)
{
	char *out;
	int status;

	status = base64__encode((unsigned char *)in, in_len, &out);

	if (0 == status) {
		for (size_t i = 0, end = strlen(out); i < end; i++) {
			switch (out[i]) {
				case '+':
					out[i] = '-';
					break;
				case '/':
					out[i] = '_';
					break;
				case '=':
					out[i] = '\0';
					end = i;
					break;
			}
		}
		return out;
	}

	return NULL;
}

static EVP_PKEY *read_private_key(char *keyfile)
{
	FILE *fd;
	EVP_PKEY* key = NULL;

	fd = fopen(keyfile, "r");
	if (NULL == fd) {
		log__printf(NULL, MOSQ_LOG_ERR, "Could not read private key file %d for JWT remote password", keyfile);
		goto err1;
	}

	key = PEM_read_PrivateKey(fd, NULL, NULL, NULL);
	if (NULL == key) {
		log__printf(NULL, MOSQ_LOG_ERR, "Could not parse private key file %d for JWT remote password", keyfile);
		goto err2;
	}

err2:
	fclose(fd);
err1:
	return key;
}

static char *sign(EVP_PKEY *key, char *in, size_t len_in, int *len_out)
{
	EVP_MD_CTX *context = NULL;
	size_t output_len;
	char *output = NULL;

	context = EVP_MD_CTX_create();
    if (NULL == context) goto err1;

	if (1 != EVP_DigestSignInit(context, NULL, EVP_sha256(), NULL, key)) goto err2;

	if (1 != EVP_DigestSignUpdate(context, in, len_in)) goto err2;

	 if (1 != EVP_DigestSignFinal(context, NULL, &output_len)) goto err2;

	output = mosquitto__malloc(output_len);
	if (NULL == output) goto err2;

	if (1 != EVP_DigestSignFinal(context, (unsigned char *)output, &output_len)) {
		mosquitto__free(output);
		goto err2;
	}

	*len_out = (int) output_len;

err2:
	EVP_MD_CTX_destroy(context);
err1:

	return output;
}

#endif
