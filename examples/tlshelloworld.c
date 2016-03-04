#include "../tlslayer.c"

#include <stdio.h>
#include <string.h>    //strlen
#ifdef _WIN32
    #include <winsock2.h>
    #define socklen_t int
    #define sleep(x)    Sleep(x*1000)
#else
    #include <sys/socket.h>
    #include <arpa/inet.h>
#endif

int read_from_file(const char *fname, void *buf, int max_len) {
    FILE *f = fopen(fname, "rb");
    if (f) {
        int size = fread(buf, 1, max_len - 1, f);
        if (size > 0)
            ((unsigned char *)buf)[size] = 0;
        else
            ((unsigned char *)buf)[0] = 0;
        fclose(f);
        return size;
    }
    return 0;
}

void load_keys(TLSContext *context, char *fname, char *priv_fname) {
    unsigned char buf[0xFFFF];
    unsigned char buf2[0xFFFF];
    int size = read_from_file(fname, buf, 0xFFFF);
    int size2 = read_from_file(priv_fname, buf2, 0xFFFF);
    if (size > 0) {
        if (context) {
            tls_load_certificates(context, buf, size);
            tls_load_private_key(context, buf2, size2);
            // tls_print_certificate(fname);
        }
    }
}

int send_pending(int client_sock, TLSContext *context) {
    unsigned int out_buffer_len = 0;
    const unsigned char *out_buffer = tls_get_write_buffer(context, &out_buffer_len);
    unsigned int out_buffer_index = 0;
    int send_res = 0;
    while ((out_buffer) && (out_buffer_len > 0)) {
        int res = send(client_sock, (char *)&out_buffer[out_buffer_index], out_buffer_len, 0);
        if (res <= 0) {
            send_res = res;
            break;
        }
        out_buffer_len -= res;
        out_buffer_index += res;
    }
    tls_buffer_clear(context);
    return send_res;
}

int main(int argc , char *argv[]) {
    int socket_desc , client_sock , read_size;
    socklen_t c;
    struct sockaddr_in server , client;
    char client_message[0xFFFF];

#ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#else
    signal(SIGPIPE, SIG_IGN);
#endif

    socket_desc = socket(AF_INET , SOCK_STREAM , 0);
    if (socket_desc == -1) {
        printf("Could not create socket");
        return 0;
    }
     
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(2000);
     
    if( bind(socket_desc,(struct sockaddr *)&server , sizeof(server)) < 0) {
        perror("bind failed. Error");
        return 1;
    }
    int enable = 1;
    setsockopt(socket_desc, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int));
     
    listen(socket_desc , 3);
     
    c = sizeof(struct sockaddr_in);

    unsigned int size;

    TLSContext *server_context = tls_create_context(1, TLS_V12);
    // load keys
    load_keys(server_context, "testcert/fullchain.pem", "testcert/privkey.pem");
    
    char source_buf[0xFFFF];
    int source_size = read_from_file("tlshelloworld.c", source_buf, 0xFFFF);
    while (1) {
        client_sock = accept(socket_desc, (struct sockaddr *)&client, &c);
        if (client_sock < 0) {
            perror("accept failed");
            return 1;
        }
        
        TLSContext *context = tls_accept(server_context);

        // make the TLS context serializable (this must be called before negotiation)
        tls_make_exportable(context, 1);

        fprintf(stderr, "Client connected\n");
        while (read_size = recv(client_sock, client_message, 0xFFFFF , 0)) {
            if (tls_consume_stream(context, client_message, read_size, NULL) > 0)
                break;
            //if (!tls_pending(context))
            //    break;
        }
        send_pending(client_sock, context);
        fprintf(stderr, "USED CIPHER: %s\n", tls_cipher_name(context));
        int ref_packet_count = 0;
        int res;
        while ((read_size = recv(client_sock, client_message, 0xFFFF , 0)) > 0) {
            tls_consume_stream(context, client_message, read_size, NULL);
            send_pending(client_sock, context);
            if (tls_established(context)) {
                unsigned char read_buffer[0xFFFF];
                int read_size = tls_read(context, read_buffer, 0xFFFF - 1);
                if (read_size > 0) {
                    read_buffer[read_size] = 0;
                    unsigned char export_buffer[0xFFF];
                    // simulate serialization / deserialization to another process
/* COOL STUFF => */ int size = tls_export_context(context, export_buffer, sizeof(export_buffer));
                    if (size > 0) {
/* COOLER STUFF => */   TLSContext *imported_context = tls_import_context(export_buffer, size);
// This is cool because a context can be sent to an existing process.
// It will work both with fork and with already existing worker process.
                        fprintf(stderr, "Imported context (size: %i): %x\n", size, imported_context);
                        if (imported_context) {
                            // destroy old context
                            tls_destroy_context(context);
                            // simulate serialization/deserialization of context
                            context = imported_context;
                        }
                    }
                    // ugly inefficient code ... don't write like me
                    char send_buffer[0xF000];
                    char send_buffer_with_header[0xF000];
                    char out_buffer[0xFFF];
                    snprintf(send_buffer, sizeof(send_buffer), "Hello world from TLS 1.2 (used chipher is: %s)\r\n\r\nCertificate: %s\r\n\r\nBelow is the received header:\r\n%s\r\nAnd the source code for this example: \r\n\r\n%s", tls_cipher_name(context), tls_certificate_to_string(server_context->certificates[0], out_buffer, 0xFFF), read_buffer, source_buf);
                    int content_length = strlen(send_buffer);
                    snprintf(send_buffer_with_header, sizeof(send_buffer), "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-type: text/plain\r\nContent-length: %i\r\n\r\n%s", content_length, send_buffer);
                    tls_write(context, send_buffer_with_header, strlen(send_buffer_with_header));
                    tls_close_notify(context);
                    send_pending(client_sock, context);
                    // use so_linger or shutdown istead of sleep to ensure a clean close
                    sleep(1);
                    break;
                }
            }
        }
#ifdef __WIN32
        closesocket(client_sock);
#else
        close(client_sock);
#endif
        tls_destroy_context(context);
    }
    tls_destroy_context(server_context);
    return 0;
}
