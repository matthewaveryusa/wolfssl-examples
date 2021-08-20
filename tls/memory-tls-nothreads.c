/* memory-tls.c
 *
 * Copyright (C) 2006-2020 wolfSSL Inc.
 *
 * This file is part of wolfSSL. (formerly known as CyaSSL)
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */


/* in memory TLS connection with I/O callbacks, no sockets
 *
 gcc -Wall memory-tls.c  -l wolfssl -lpthread

*/
#define MAX_RECORD_SIZE 4096
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {

/* client messages to server in memory */
WOLFSSL_CTX* cli_ctx;
unsigned char to_server[1024*17];
int server_bytes;
int server_write_idx;
int server_read_idx;

/* server messages to client in memory */
WOLFSSL_CTX* srv_ctx;
unsigned char to_client[1024*17];
int client_bytes;
int client_write_idx;
int client_read_idx;
} ctx_t;


/* server send callback */
int ServerSend(WOLFSSL* ssl, char* buf, int sz, ctx_t* ctx)
{
    //printf("wolfSSL ServerSend, %d\n", sz);
    memcpy(&ctx->to_client[ctx->client_write_idx], buf, sz);
    ctx->client_write_idx += sz;
    ctx->client_bytes += sz;

    return sz;
}


/* server recv callback */
int ServerRecv(WOLFSSL* ssl, char* buf, int sz, ctx_t* ctx)
{
    //printf("wolfSSL ServerRecv, %d\n", sz);
    if(ctx->server_bytes < sz) {
      sz = ctx->server_bytes;
    }
    if(sz == 0) {
      return WOLFSSL_CBIO_ERR_WANT_READ;
    }
    memcpy(buf, &ctx->to_server[ctx->server_read_idx], sz);
    ctx->server_read_idx += sz;

    if (ctx->server_read_idx == ctx->server_write_idx) {
        ctx->server_read_idx = ctx->server_write_idx = 0;
        ctx->server_bytes = 0;
    }


    return sz;
}


/* client send callback */
int ClientSend(WOLFSSL* ssl, char* buf, int sz, ctx_t* ctx)
{

    //printf("wolfSSL ClientSend, %d\n", sz);
    memcpy(&ctx->to_server[ctx->server_write_idx], buf, sz);
    ctx->server_write_idx += sz;
    ctx->server_bytes += sz;

    return sz;
}


/* client recv callback */
int ClientRecv(WOLFSSL* ssl, char* buf, int sz, ctx_t* ctx)
{
    //printf("wolfSSL ClientRecv, %d\n", sz);
    if(ctx->client_bytes < sz) {
      sz = ctx->client_bytes;
    }
    if(sz == 0) {
      return WOLFSSL_CBIO_ERR_WANT_READ;
    }

    memcpy(buf, &ctx->to_client[ctx->client_read_idx], sz);
    ctx->client_read_idx += sz;

    if (ctx->client_read_idx == ctx->client_write_idx) {
        ctx->client_read_idx = ctx->client_write_idx = 0;
        ctx->client_bytes = 0;
    }
    return sz;
}


static void err_sys(const char* msg)
{
    printf("wolfSSL error: %s\n", msg);
    exit(1);
}


#define key "../certs/ecc-key.pem"
#define cert "../certs/server-ecc.pem"
#define cacert "../certs/ca-ecc-cert.pem"

int main()
{

    ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    /* set up server */
    ctx.srv_ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
    if (ctx.srv_ctx == NULL) err_sys("bad server ctx new");
    //wolfSSL_CTX_set_session_cache_mode(ctx.srv_ctx, SSL_SESS_CACHE_OFF);

    int ret = wolfSSL_CTX_use_PrivateKey_file(ctx.srv_ctx, key, SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) err_sys("bad server key file load");

    ret = wolfSSL_CTX_use_certificate_file(ctx.srv_ctx, cert, SSL_FILETYPE_PEM);
    if (ret != SSL_SUCCESS) err_sys("bad server cert file load");

    wolfSSL_SetIOSend(ctx.srv_ctx, (CallbackIOSend) ServerSend);
    wolfSSL_SetIORecv(ctx.srv_ctx, (CallbackIORecv) ServerRecv);

    /* set up client */
    ctx.cli_ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if (ctx.cli_ctx == NULL) err_sys("bad client ctx new");
    //wolfSSL_CTX_set_session_cache_mode(ctx.cli_ctx, SSL_SESS_CACHE_OFF);
    //wolfSSL_CTX_UseMaxFragment(ctx.cli_ctx, WOLFSSL_MFL_2_11);

    ret = wolfSSL_CTX_load_verify_locations(ctx.cli_ctx, cacert, NULL);
    if (ret != SSL_SUCCESS) err_sys("bad ca load");

    wolfSSL_SetIOSend(ctx.cli_ctx, (CallbackIOSend) ClientSend);
    wolfSSL_SetIORecv(ctx.cli_ctx, (CallbackIORecv) ClientRecv);

    char *x = malloc(4096);
    wolfSSL_get_ciphers(x,4096);
    printf("enabled ciphers: %s\n", x);
    memset(x, '@', 4096);
    x[4095] = '\0';
    
    unsigned char buf[4096];
    memset(buf, 0, sizeof(buf));


    for(int i = 0; i < 100000; ++i) {

    WOLFSSL* cli_ssl = wolfSSL_new(ctx.cli_ctx);
    wolfSSL_SetIOReadCtx(cli_ssl, &ctx);
    wolfSSL_SetIOWriteCtx(cli_ssl, &ctx);
    if (cli_ssl == NULL) err_sys("bad client new");

    WOLFSSL* srv_ssl = wolfSSL_new(ctx.srv_ctx);
    if (ctx.srv_ctx == NULL) err_sys("bad server new");
    wolfSSL_SetIOReadCtx(srv_ssl, &ctx);
    wolfSSL_SetIOWriteCtx(srv_ssl, &ctx);

    int is_client_turn = 1;
    int client_done = 0;
    int server_done = 0;
    while(1) {
        if(is_client_turn) {
          ret = wolfSSL_connect(cli_ssl); //send client hello
        } else {
          ret = wolfSSL_accept(srv_ssl); //send client hello
        }

        if (ret != SSL_SUCCESS) {
          int err = wolfSSL_get_error(cli_ssl, 0);
          if(err == WOLFSSL_ERROR_WANT_READ) {
              is_client_turn = is_client_turn ? 0 : 1;
          } else {
            char buffer[4096];
            wolfSSL_ERR_error_string(err, buffer);
            printf("err = %d, %d, %s\n", err, ret, buffer);
            err_sys("bad tls connect");
          }
        } else {
            if(is_client_turn) {
                client_done = 1;
                is_client_turn = 0;
            } else {
                server_done = 1;
                is_client_turn = 1;
            }
            if(client_done && server_done) {
                break;
            }
        }
    }
    printf("%d wolfSSL client success!\n", i);
    
    ret = wolfSSL_write(cli_ssl, x, 4096);
    ret = wolfSSL_read(srv_ssl, buf, 4096);
    //printf("client msg = %s\n", buf);

    /* keep connection open */
    //wolfSSL_free(srv_ssl);
    wolfSSL_free(cli_ssl);
    //reset buffers:
    ctx.client_read_idx = 0;
    ctx.server_read_idx = 0;
    ctx.server_write_idx = 0;
    ctx.client_write_idx = 0;
    ctx.server_bytes = 0;
    ctx.client_bytes = 0;
    }
    wolfSSL_CTX_free(ctx.cli_ctx);
    wolfSSL_CTX_free(ctx.srv_ctx);

    return 0;
}
