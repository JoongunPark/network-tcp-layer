/**
 * @file        ktcp_easy_impl.c
 * @author      leeopop
 * @date        Aug 2013
 * @version     $Revision: 1.00 $
 * @brief       Template for easy-KTCP project
 *
 * This is the main project template for transport layer implementation.
 * All functions below are linked with KENS kernel, so do not change the name or type of function.
 */

#include "ktcp_easy_impl.h"
#include "ktcp_easy_lib.h"

//suggesting header
#include <stdlib.h>
#include <errno.h>
#include "linked_list.h"
#define BUFMAX 10*1024*1024
#define RBUFMAX 3072
typedef struct
{
	ktcp_easy_impl my_syscall;

	//add global variables here
	ktcp_easy_lib* ktcp_lib;
        list contextlist;
        list connectionlist;
        list bindlist;
        short cnt;

}global_context_t;

enum states{
    CLOSED,
    LISTEN,
    SYN_RCVD,
    SYN_RCVD_ACK,
    SYN_SENT,
    ESTAB,
    FIN_WAIT_1,
    FIN_WAIT_2,
    TIMED_WAIT,
    CLOSE_WAIT,
    LAST_ACK,
};

enum con_state{
    OPEN,
    BIND,
    CONNECT,
    LISTEN_,
    ACCEPT,
    CLOSE
//    ESTAB_
};

typedef struct{
    uint16_t source_port;
    uint16_t dest_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t headlen;
    uint8_t flags; /* UAPRSF */
    uint16_t recieve_window;
    uint16_t checksum;
    uint16_t urg_ptr;
}tcp_header;


typedef struct a{ 
    int sourcelen;
    struct sockaddr_in* source;
    int destlen;
    struct sockaddr_in* dest;
    enum states state;
    enum con_state cstate;
    uint32_t seqnum;
    uint32_t acknum;
  //  uint32_t acknum_r;

    uint32_t lastack;
    char buffer[BUFMAX+1];
    list r_buffer;
    list rc_buffer;

    int buflen;
    int start;

    int rc_buflen;
    int rc_start;

    uint16_t rwnd;
    uint16_t rwnd_r;
    uint16_t cwnd;

    list pendinglist;
    int backlog;
    void* listenfd;
    int nc;


    void *listen_handle;

    uint32_t td_ack;
    int td_ack_cnt;

    void* tcp_data;
    int real_data_size;

}ctx;      

typedef struct{
    struct in_addr sip;
    struct in_addr dip;
    tcp_header *header;
 //   enum states newstate;
}pending_data;

typedef struct{
    tcp_header *header;
    void *data;
    int data_size;
}r_data;



ktcp_easy_impl* my_startup(ktcp_easy_lib* lib);

static void my_shutdown(global_context_t* tcp_context); //finalize tcp context manager

static my_context my_open(global_context_t* tcp_context, int *err); //called when kopen is called
static void my_close(global_context_t* tcp_context, my_context handle,int *err); //handle: memory allocated from my_open
static bool my_bind(global_context_t* tcp_context, my_context handle, const struct sockaddr *my_addr, socklen_t addrlen,int *err);
static bool my_listen(global_context_t* tcp_context, my_context handle, int backlog, int *err);
static bool my_connect(global_context_t* tcp_context, my_context handle, const struct sockaddr *serv_addr, socklen_t addrlen, int *err);
static bool my_accept(global_context_t* tcp_context, my_context handle, int *err);
static bool my_getsockname(global_context_t* tcp_context, my_context handle, struct sockaddr *name, socklen_t *namelen, int *err);
static bool my_getpeername(global_context_t* tcp_context, my_context handle, struct sockaddr *name, socklen_t *namelen, int *err);
static void my_timer(global_context_t* tcp_context, my_context handle, int actual_called);
static void my_ip_dispatch_tcp(global_context_t* tcp_context, struct in_addr src_addr, struct in_addr dest_addr, const void * data, size_t data_size);
static int my_app_dispatch_tcp(global_context_t* tcp_context, my_context handle, const void* data, size_t data_size);


tcp_header* make_header(uint16_t source_port, uint16_t dest_port, uint32_t seq_num, uint32_t ack_num, uint8_t headlen, uint8_t flags, uint16_t recieve_window, uint16_t checksum, uint16_t urg_ptr);

uint16_t tcp_checksum(tcp_header *header, struct in_addr sip, struct in_addr dip, int size, int datalen);

my_context get_ctx(global_context_t* tcp_context, struct in_addr src_addr, struct in_addr dest_addr, unsigned short src_port, unsigned short dest_port);
my_context get_ctx_syn(global_context_t* tcp_context, struct in_addr src_addr, unsigned short src_port);
void send_ack(global_context_t* tcp_context, ctx* handle, tcp_header* header, void* data, int data_size);
void flush_buf(global_context_t* tcp_context, ctx* handle);
void pushpush(global_context_t* tcp_context, ctx *cli,tcp_header* header, void* data, int data_size);
void baby(global_context_t* tcp_context, ctx *handle, tcp_header* header);
/**
 * @todo
 *
 * @brief
 * This function is called when KENS TCP layer is starting.
 *
 * @param ktcp_easy_lib library functions to use
 * @return prepared ktcp_easy_impl context for further use
 */
ktcp_easy_impl* my_startup(ktcp_easy_lib* lib)
{
	global_context_t* my_tcp = malloc(sizeof(global_context_t));

	my_tcp->my_syscall.shutdown = (void (*)(ktcp_easy_impl*))my_shutdown;
	my_tcp->my_syscall.open = (my_context (*)(ktcp_easy_impl*, int *))my_open;
	my_tcp->my_syscall.close = (void (*)(ktcp_easy_impl*, my_context,int *))my_close;
	my_tcp->my_syscall.bind = (bool (*)(ktcp_easy_impl*, my_context, const struct sockaddr *, socklen_t,int *))my_bind;
	my_tcp->my_syscall.listen = (bool (*)(ktcp_easy_impl*, my_context, int, int *))my_listen;
	my_tcp->my_syscall.connect = (bool (*)(ktcp_easy_impl*, my_context, const struct sockaddr *, socklen_t, int *))my_connect;
	my_tcp->my_syscall.accept = (bool (*)(ktcp_easy_impl*, my_context, int *))my_accept;
	my_tcp->my_syscall.getsockname = (bool (*)(ktcp_easy_impl*, my_context, struct sockaddr *, socklen_t *, int *))my_getsockname;
	my_tcp->my_syscall.getpeername = (bool (*)(ktcp_easy_impl*, my_context, struct sockaddr *, socklen_t *, int *))my_getpeername;
	my_tcp->my_syscall.timer = (void (*)(ktcp_easy_impl*, my_context, int))my_timer;
	my_tcp->my_syscall.ip_dispatch_tcp = (void (*)(ktcp_easy_impl*, struct in_addr, struct in_addr, const void *, size_t))my_ip_dispatch_tcp;
	my_tcp->my_syscall.app_dispatch_tcp = (int (*)(ktcp_easy_impl*, my_context, const void*, size_t))my_app_dispatch_tcp;

	my_tcp->ktcp_lib = lib;
        my_tcp->cnt = 30000;
	//add your initialization codes here
        my_tcp->contextlist = list_open();
        my_tcp->connectionlist = list_open();
        my_tcp->bindlist = list_open();
	return (ktcp_easy_impl*)my_tcp;
}

/**
 * @todo
 *
 * @brief
 * This function is called when KENS TCP layer is exiting.
 *
 * @param tcp_context global context generated in my_startup. This includes KENS libraries and global variables.
 */
static void my_shutdown(global_context_t* tcp_context)
{
	free(tcp_context);
}


/**
 * @todo
 *
 * @brief
 * Mapped with 'ksocket'.
 *
 * @param tcp_context global context generated in my_startup.
 * @param err ERRNO value
 * @return TCP context data to be used (used to identify each application sockets)
 */
static my_context my_open(global_context_t* tcp_context, int *err)
{
    ctx *init;

    if((init = (ctx *)malloc(sizeof(ctx)))==NULL){
	return NULL;
    }
    init->source = NULL;
    init->dest = NULL;

    init->sourcelen = 0;
    init->destlen = 0;
    init->seqnum = 1;
    init->state = CLOSED;
    init->cstate = OPEN;
    init->buflen = 0;
    init->start = 0;
    init->nc = 0;
    init->rwnd_r = 3072;
    
    init->rc_buffer = list_open();
    init->r_buffer = list_open();

    init->td_ack = 0;
    init->td_ack_cnt = 0;
    
    init->cwnd = 1;

    list_add_tail(tcp_context->contextlist, (void *)init);
    return list_get_tail(tcp_context->contextlist);
}

/**
 * @todo
 *
 * @brief
 * Mapped with 'kclose'.
 *
 * @uaram tcp_context global context generated in my_startup.
 * @param handle TCP context created via 'my_open'
 * @param err ERRNO value
 */
static void my_close(global_context_t* tcp_context, my_context handle,int *err)
{

 //   printf("aaa\n");
    ctx *h = (ctx *)handle;


    if (h->cstate != OPEN){
        list_remove(tcp_context->bindlist, handle); 
    }


    if (h->state != ESTAB && h->state != SYN_RCVD && h->state != CLOSE_WAIT) return;
    tcp_header* header = 
    make_header(htons(h->source->sin_port), htons(h->dest->sin_port), h->seqnum, h->acknum, (uint8_t)0x50, (uint8_t)0x01, h->rwnd_r, 0, 0);
    h->seqnum++;
    header->checksum = tcp_checksum(header, h->source->sin_addr, h->dest->sin_addr,  20, 0);
    tcp_context->ktcp_lib->tcp_dispatch_ip(h->source->sin_addr, h->dest->sin_addr, (void *)header, 20);

    
    if (h->state == ESTAB || h->state == SYN_RCVD){
        pushpush(tcp_context, h, header, NULL, 0);
        h->state = FIN_WAIT_1;
        h->cstate = CLOSE;
    }else{
        h->state = LAST_ACK;
        h->cstate = CLOSE;
    }

 //   printf("bbb\n");
}

/**
 * @todo
 *
 * @brief
 * Mapped with 'kbind'.
 *
 * @param tcp_context global context generated in my_startup.
 * @param handle TCP context created via 'my_open'
 * @param my_addr address of this socket
 * @param addrlen length of my_addr structure
 * @param err ERRNO value
 * @return whether this operation is successful
 */
static bool my_bind(global_context_t* tcp_context, my_context handle, const struct sockaddr *my_addr, socklen_t addrlen,int *err)
{
    list_position iter;

    if(handle == NULL) return false;
    if(((ctx *)handle)->cstate != OPEN){
        *err = EINVAL;
        return false;
    }
    ctx *temp;
    struct sockaddr_in *my_addr_ = (struct sockaddr_in *)my_addr;
    iter = list_get_head_position(tcp_context->bindlist);
    while(iter){
        temp = (ctx *)list_get_at(iter);       
        if ((my_addr_->sin_addr.s_addr==temp->source->sin_addr.s_addr) || (my_addr_->sin_addr.s_addr ==htonl(INADDR_ANY)) || (temp->source->sin_addr.s_addr == htonl(INADDR_ANY))){
            if (my_addr_->sin_port==temp->source->sin_port){
                *err=EADDRINUSE;
                return false;
            }
        }
        iter = list_get_next_position(iter);
    }
    temp = malloc(sizeof(struct sockaddr_in));
    memcpy(temp, my_addr_, addrlen);
    ((ctx *)handle)->source = temp;
    ((ctx *)handle)->sourcelen = addrlen; 
    ((ctx *)handle)->cstate = BIND;

    list_add_tail(tcp_context->bindlist, handle);
    return true;
}

/**
 * @todo
 *
 * @brief
 * Mapped with 'klisten'.
 *
 * @param tcp_context global context generated in my_startup.
 * @param handle TCP context created via 'my_open'
 * @param backlog maximum number of concurrently opening connections
 * @param err ERRNO value
 * @return whether this operation is successful
 */
static bool my_listen(global_context_t* tcp_context, my_context handle, int backlog, int *err)
{
    ctx* h = (ctx *)handle;

    if (h->cstate == BIND) h->cstate = LISTEN_;
    h->pendinglist = list_open();
    h->backlog = backlog;
    return true;
}

/**
 * @todo
 *
 * @brief
 * Mapped with 'kconnect'.
 *
 * @param tcp_context global context generated in my_startup.
 * @param handle TCP context created via 'my_open'
 * @param serv_addr remote address connecting to
 * @param addrlen length of serv_addr structure
 * @param err ERRNO value
 * @return whether this operation is successful
 */
static bool my_connect(global_context_t* tcp_context, my_context handle, const struct sockaddr *serv_addr, socklen_t addrlen, int *err)
{
    ctx *cli = (ctx *)handle;

    uint16_t sport = htons(((struct sockaddr_in *)serv_addr)->sin_port);
    struct in_addr sip = ((struct sockaddr_in *)serv_addr)->sin_addr;

    if (cli->state != CLOSED){
        return false;
    }   
    cli->state = SYN_SENT;

    cli->destlen = sizeof(struct sockaddr_in);
    struct sockaddr_in *temp = malloc(sizeof(struct sockaddr_in));

    memcpy(temp, serv_addr, sizeof(struct sockaddr_in));
    cli->dest = temp;
    if(cli->cstate == OPEN){
        temp = malloc(sizeof(struct sockaddr_in));

        int flag = 0;
        
        do{
            flag = 0;
            temp->sin_family = AF_INET;
            temp->sin_port = htons(tcp_context->cnt);
            temp->sin_addr.s_addr = tcp_context->ktcp_lib->ip_host_address(sip);
            tcp_context->cnt++;

            list_position iter = list_get_head_position(tcp_context->bindlist);
            while(iter){
                ctx* temp2 = (ctx *)list_get_at(iter);                
                if ((temp->sin_addr.s_addr==temp2->source->sin_addr.s_addr) || (temp->sin_addr.s_addr ==htonl(INADDR_ANY)) || (temp2->source->sin_addr.s_addr == htonl(INADDR_ANY))){
                    if (temp->sin_port==temp2->source->sin_port){
                        flag=1;    
                    }
                }
                iter = list_get_next_position(iter);
            }

        }while(flag);
        cli->source = temp;
        cli->sourcelen = sizeof(struct sockaddr_in);

        list_add_tail(tcp_context->bindlist, cli);
    }
    tcp_header* header = 
        make_header((uint16_t)htons(cli->source->sin_port), sport, cli->seqnum, 0, (uint8_t)0x50, (uint8_t)0x02, cli->rwnd_r, 0, 0);
    
    header->checksum = tcp_checksum(header, cli->source->sin_addr, sip,  20, 0);
    tcp_context->ktcp_lib->tcp_dispatch_ip(cli->source->sin_addr, sip, (void *)header, 20);

    cli->cstate=CONNECT;

    pushpush(tcp_context,handle,header,NULL,0);
    return true;
}

/**
 * @todo
 *
 * @brief
 * Mapped with 'kaccept'.
 * 'kaccept' is immediately blocked (my_accept is not blocked).
 * Even if 'kaccept' is called after connection is established, it is blocked.
 * 'kaccept' can be waken up via tcp_context->ktcp_lib->tcp_passive_open.
 *
 * @param tcp_context global context generated in my_startup.
 * @param handle TCP context created via 'my_open' (listening socket)
 * @param err ERRNO value
 * @return whether this operation is successful
 */
static bool my_accept(global_context_t* tcp_context, my_context handle, int *err)
{
    ctx* h = (ctx *)handle;
    if (list_get_count(h->pendinglist) != 0){
        ctx* new = list_remove_head(h->pendinglist);
        new->cstate = ACCEPT;
        if (new->state == SYN_RCVD_ACK){
            new->state = ESTAB;
            if (!tcp_context->ktcp_lib->tcp_passive_open(h, new)) return false;
        }
        return true;
    }else{
        h->state = LISTEN;
        h->cstate = ACCEPT;
    }

    return true;
}

/**
 * @todo
 *
 * @brief
 * Mapped with 'kgetsockname'.
 *
 * @param tcp_context global context generated in my_startup.
 * @param handle TCP context created via 'my_open'
 * @param name address of socket address structure
 * Write my address here.
 *
 * @param namelen length of address structure
 * Write length of my address structure size here.
 * This value should be initialized with the actual size of 'name' structure.
 *
 * @param err ERRNO value
 * @return whether this operation is successful
 */
static bool my_getsockname(global_context_t* tcp_context, my_context handle, struct sockaddr *name, socklen_t *namelen, int *err)
{
    ctx* h = (ctx *)handle;
    if (h->source==NULL) return false;
    
    memcpy(name,(struct sockaddr *)h->source, h->sourcelen);
    *namelen = h->sourcelen;
    return true;
}

/**
 * @todo
 *
 * @brief
 * Mapped with 'kgetpeername'.
 *
 * @param tcp_context global context generated in my_startup.
 * @param handle TCP context created via 'my_open'
 * @param name address of socket address structure
 * Write peer address here.
 *
 * @param namelen length of address structure
 * Write length of my address structure size here.
 * This value should be initialized with the actual size of 'name' structure.
 *
 * @param err ERRNO value
 * @return whether this operation is successful
 */
static bool my_getpeername(global_context_t* tcp_context, my_context handle, struct sockaddr *name, socklen_t *namelen, int *err)
{
    ctx* h = (ctx *)handle;
    if (h->state!=ESTAB) return false;
    memcpy(name,(struct sockaddr *)h->dest, h->destlen);
    *namelen = h->destlen;
    return true;
}

/**
 * @todo
 *
 * @brief
 * Every time application calls 'write', this function is called.
 *
 * @param tcp_context global context generated in my_startup.
 * @param handle TCP context linked with application socket
 * @param dest_addr destination IP address (in network ordering)
 * @param data written data via 'write'
 * @param data_size size of data
 * @return actual written bytes (-1 means closed socket)
 */
static int my_app_dispatch_tcp(global_context_t* tcp_context, my_context handle, const void* data, size_t data_size)
{
    ctx* h = (ctx *)handle;
    tcp_header *header;
    void *tcp_data;     
    int ret = data_size;
    size_t written;
   // printf("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n");
   //
    int cnt = 0;

    if(h->state==ESTAB || h->state == CLOSE_WAIT)
    {
            while(data_size > 0)
            {
                int real_data_size = (data_size > 512) ? 512 : data_size;
                
                if(h->rwnd - real_data_size < 0)
                    break;
                tcp_data = malloc(20+real_data_size);
                header = make_header(htons(h->source->sin_port),htons(h->dest->sin_port),h->seqnum, h->acknum, (uint8_t)0x50, (uint8_t)0x10, h->rwnd_r, 0, 0);
                memcpy(tcp_data,header,20);
                memcpy(tcp_data+20,data,real_data_size);
                header->checksum = tcp_checksum(tcp_data, h->source->sin_addr, h->dest->sin_addr,  20+real_data_size,real_data_size);
                memcpy(tcp_data,header,20);
                written = tcp_context->ktcp_lib->tcp_dispatch_ip(h->source->sin_addr,h->dest->sin_addr,tcp_data,20+ real_data_size);
                
                pushpush(tcp_context,handle,header, tcp_data+20 , real_data_size);

                free(tcp_data);
                
                h->seqnum += real_data_size;
                data += real_data_size;
                data_size-=real_data_size;
                h->rwnd-=real_data_size;
            }
            if(data_size > 0)
            {
                if(h->buflen+data_size > BUFMAX)
                    return -1;
                if(data_size + h->start > BUFMAX)
                {
                    memcpy(h->buffer + h->start, data, BUFMAX-h->start);
                    data+=BUFMAX-h->start;
                    data_size -= BUFMAX-h->start;
                    memcpy(h->buffer, data, data_size);   
                }
                else{
                    memcpy(h->buffer + h->start+h->buflen,data,data_size);
                }
                h->buflen +=data_size;
            } 
            return ret;
    }       
    return -1;
}

/**
 * @todo
 *
 * @brief
 * When ip packet is received, this callback function is called.
 * Most IP headers are removed, and only data part is passed.
 * However, source IP address and destination IP address are passed for header computation.
 *
 * @param tcp_context global context generated in my_startup.
 * @param src_addr source IP address (in network ordering)
 * @param dest_addr destination IP address (in network ordering)
 * @param data IP payload
 * @param data_size size of data
 */
static void my_ip_dispatch_tcp(global_context_t* tcp_context, struct in_addr src_addr, struct in_addr dest_addr, const void * data, size_t data_size)
{

    tcp_header *header = (tcp_header *)data;
    ctx* handle;
    if ((header->flags & 0x02) == 0x02){
        handle = get_ctx_syn(tcp_context, dest_addr, (unsigned short)header->dest_port);
    }else{
        handle = get_ctx(tcp_context, dest_addr, src_addr,(unsigned short)header->dest_port,(unsigned short)header->source_port);
    }
    if (handle == NULL) {
        return;    
    }

//    printf("%d %d\n", handle->cstate, handle->state);

    struct in_addr sip = dest_addr;
    struct in_addr dip = src_addr;
    
    unsigned short sport = htons(header->dest_port);
    unsigned short dport = htons(header->source_port);

    uint16_t checksum = tcp_checksum(header, sip, dip, data_size, data_size-20);
  //  printf("%x\n", checksum);
    if (checksum) return;

    if (handle->state == CLOSE_WAIT){
        if (header->flags == 0x01){
            header = make_header(htons(handle->source->sin_port),htons(handle->dest->sin_port),handle->seqnum, handle->acknum+1, (uint8_t)0x50, (uint8_t)0x10, handle->rwnd_r, 0, 0);
            header->checksum = tcp_checksum(header, handle->source->sin_addr, handle->dest->sin_addr,  20, 0);
            tcp_context->ktcp_lib->tcp_dispatch_ip(handle->source->sin_addr,handle->dest->sin_addr,header,20);
            return;
        }else if (header->flags == 0x10){
            baby(tcp_context, handle, header);
        }

    //    handle->rwnd += htonl(header->ack_num)- handle->lastack;
        handle->lastack = (uint32_t)htonl(header->ack_num);
        handle->acknum = htonl(header->seq_num) + data_size - 20;
        flush_buf(tcp_context, handle);
    }else if(handle->state == FIN_WAIT_1){
        

     //   handle->rwnd += htonl(header->ack_num)- handle->lastack;
        handle->lastack = (uint32_t)htonl(header->ack_num);
      
        if (data_size > 20){
            send_ack(tcp_context, handle, header, data, data_size);         
        }else{
         //   printf("aaaaaaaa\n");
            baby(tcp_context, handle, header);
         //   handle->state = FIN_WAIT_2;
        }

    }else if(handle->state == FIN_WAIT_2){
      //  handle->rwnd += htonl(header->ack_num)- handle->lastack;
        handle->lastack = (uint32_t)htonl(header->ack_num);
        if (header->flags ==  0x01){
           // printf("aaaaaaaaaaaaaaaaaa\n");
            handle->acknum = htonl(header->seq_num) + data_size - 20;

            header = make_header(htons(handle->source->sin_port),htons(handle->dest->sin_port),handle->seqnum, handle->acknum+1, (uint8_t)0x50, (uint8_t)0x10, handle->rwnd_r, 0, 0);
            header->checksum = tcp_checksum(header, handle->source->sin_addr, handle->dest->sin_addr,  20, 0);
            tcp_context->ktcp_lib->tcp_dispatch_ip(handle->source->sin_addr,handle->dest->sin_addr,header,20);
            handle->state = TIMED_WAIT;
        }else if (data_size > 20){
            send_ack(tcp_context, handle, header, data, data_size);
        }else{
          //  baby(tcp_context, handle, header);
        }
    }else if(handle->state == LAST_ACK){
           //     baby(tcp_context, handle, header);
        return;
    }else if(handle->state == TIMED_WAIT){
        if (header->flags == 0x01){
           // printf("bbbbbbbbbbbbbbbbbbb\n");
            header = make_header(htons(handle->source->sin_port),htons(handle->dest->sin_port),handle->seqnum, handle->acknum+1, (uint8_t)0x50, (uint8_t)0x10, handle->rwnd_r, 0, 0);
            header->checksum = tcp_checksum(header, handle->source->sin_addr, handle->dest->sin_addr,  20, 0);
            tcp_context->ktcp_lib->tcp_dispatch_ip(handle->source->sin_addr,handle->dest->sin_addr,header,20);
            return;
        }
    }



    if (handle->cstate == CONNECT){
        if (handle->state == SYN_SENT){
            if(!checksum){
                if(((header->flags & 0x12) == 0x12)){
                    baby(tcp_context, handle, header);
                    handle->state = ESTAB;
                    list_add_tail(tcp_context->connectionlist, handle);
                    handle->lastack = htonl(header->ack_num);
                    handle->acknum = htonl(header->seq_num) + 1;
                    handle->rwnd = htons(header->recieve_window);

                    handle->buflen = 0;
                    if (!tcp_context->ktcp_lib->tcp_active_open((void *)handle)) return false;
                }
                else if((header->flags & 0x02) == 0x02){
                    handle->state = SYN_RCVD;
                    list_add_tail(tcp_context->connectionlist, handle);
                }
                handle->seqnum++;
                header = make_header(sport,dport,handle->seqnum, htonl(header->seq_num)+1, (uint8_t)0x50, (uint8_t)0x10, handle->rwnd_r, 0, 0);
                header->checksum = tcp_checksum(header, sip, dip, 20, 0);
                tcp_context->ktcp_lib->tcp_dispatch_ip(sip, dip, (void *)header, 20);
            }
        }else if(handle->state == SYN_RCVD){
            if (!checksum){
                if (header->flags == 0x02){
                    header = make_header(sport,dport,handle->seqnum, htonl(header->seq_num)+1, (uint8_t)0x50, (uint8_t)0x10, handle->rwnd_r, 0, 0);
                    header->checksum = tcp_checksum(header, sip, dip, 20, 0);
                    tcp_context->ktcp_lib->tcp_dispatch_ip(sip, dip, (void *)header, 20);
                    return;
                }

                if ((header->flags & 0x10) == 0x10){
                    baby(tcp_context, handle, header);
                    handle->state = ESTAB;              
                    handle->lastack = htonl(header->ack_num);
                    handle->acknum = htonl(header->seq_num) + 1;
                    handle->rwnd = htons(header->recieve_window);
                    handle->buflen = 0;
                    if (!tcp_context->ktcp_lib->tcp_active_open((void *)handle)) return false;
                }
            }
         }else if(handle->state == ESTAB){
       //     handle->rwnd += htonl(header->ack_num)- handle->lastack;
            handle->lastack = (uint32_t)htonl(header->ack_num);
            if ((header->flags & 0x02) == 0x02){
                header = make_header(sport,dport,handle->seqnum, htonl(header->seq_num)+1, (uint8_t)0x50, (uint8_t)0x10, handle->rwnd_r, 0, 0);
                header->checksum = tcp_checksum(header, sip, dip, 20, 0);
                tcp_context->ktcp_lib->tcp_dispatch_ip(sip, dip, (void *)header, 20);
                return;
            }
            if (header->flags == 0x01){
                handle->acknum = htonl(header->seq_num) + data_size - 20;
                header = make_header(htons(handle->source->sin_port),htons(handle->dest->sin_port),handle->seqnum, handle->acknum+1, (uint8_t)0x50, (uint8_t)0x10, handle->rwnd_r, 0, 0);
                header->checksum = tcp_checksum(header, handle->source->sin_addr, handle->dest->sin_addr,  20, 0);
                tcp_context->ktcp_lib->tcp_dispatch_ip(handle->source->sin_addr,handle->dest->sin_addr,header,20);

                handle->state = CLOSE_WAIT;
                return;
            }

            if (header->flags == 0x10){
                baby(tcp_context, handle, header);
            }

            int written;
            if(handle->buflen == 0 && data_size > 20){
                send_ack(tcp_context, handle, header, data, data_size);
            }
            flush_buf(tcp_context, handle);
         }
    }else if (handle->cstate == LISTEN_){
        if (handle->state == CLOSED){
            if (!checksum && (header->flags & 0x02) == 0x02){
                if (handle->backlog > list_get_count(handle->pendinglist) ){
                    if (get_ctx(tcp_context, dest_addr, src_addr,(unsigned short)header->dest_port,(unsigned short)header->source_port) != NULL){
                        return;
                    }
 

                    ctx* new = (ctx *)malloc(sizeof(ctx));
                    list_add_tail(tcp_context->connectionlist, new);
                    new->sourcelen = sizeof(struct sockaddr_in); 
                    new->source = malloc(sizeof(struct sockaddr_in));
                    new->source->sin_family = AF_INET;
                    new->source->sin_addr = sip;
                    new->source->sin_port = header->dest_port;
                    new->destlen = sizeof(struct sockaddr_in); 
                    new->dest = malloc(sizeof(struct sockaddr_in));
                    new->dest->sin_family = AF_INET;
                    new->dest->sin_addr = dip;
                    new->dest->sin_port = header->source_port;

                    new->listenfd = handle;
                    new->cstate = LISTEN_;
                    new->state = SYN_RCVD;

                    new->seqnum = handle->seqnum;
                    new->start = 0;
                    new->rwnd_r = 3072;
                    new->seqnum++;
                    new->nc = 0;
                    new->lastack = htonl(header->ack_num);
                    new->acknum = htonl(header->seq_num);
                    new->rwnd = htons(header->recieve_window);
                    new->rc_buffer = list_open();
                    new->r_buffer = list_open();

                    new->listen_handle = handle;    

                    new->td_ack = 0;
                    new->td_ack_cnt = 0;
                    
                    new->cwnd = 1;
                       
                    list_add_tail(handle->pendinglist, new);

                    tcp_header* header2 = make_header(htons(header->dest_port), htons(header->source_port), handle->seqnum, htonl(header->seq_num)+1, (uint8_t)0x50, (uint8_t)0x12, handle->rwnd_r, 0, 0);
                    header2->checksum = tcp_checksum(header2, sip, dip, 20, 0);
                    tcp_context->ktcp_lib->tcp_dispatch_ip(sip, dip, (void *)header2, 20);
                    pushpush(tcp_context, new, header2, NULL, 0);

                }   
            }
        }else if(handle->state == SYN_RCVD){
            baby(tcp_context, handle, header);
            handle->state = SYN_RCVD_ACK;


        }
    }else if (handle->cstate == ACCEPT){
        if (handle->state == LISTEN){

            if (get_ctx(tcp_context, dest_addr, src_addr,(unsigned short)header->dest_port,(unsigned short)header->source_port) != NULL){
                return;
            }


            ctx* new = (ctx *)malloc(sizeof(ctx));
            list_add_tail(tcp_context->connectionlist, new);
            new->sourcelen = sizeof(struct sockaddr_in); 
            new->source = malloc(sizeof(struct sockaddr_in));
            new->source->sin_family = AF_INET;
            new->source->sin_addr = sip;
            new->source->sin_port = header->dest_port;
            new->destlen = sizeof(struct sockaddr_in); 
            new->dest = malloc(sizeof(struct sockaddr_in));
            new->dest->sin_family = AF_INET;
            new->dest->sin_addr = dip;
            new->dest->sin_port = header->source_port;

            new->listenfd = handle;

            new->cstate = ACCEPT;
            new->state = SYN_RCVD;

            new->seqnum = handle->seqnum;
            new->start = 0;
            new->rwnd_r = 3072;

            tcp_header* header2 = make_header(htons(header->dest_port), htons(header->source_port), new->seqnum, htonl(header->seq_num)+1, (uint8_t)0x50, (uint8_t)0x12, new->rwnd_r, 0, 0);

            new->seqnum++;
            new->nc = 0;
 
            header2->checksum = tcp_checksum(header2, sip, dip, 20, 0);
            tcp_context->ktcp_lib->tcp_dispatch_ip(sip, dip, (void *)header2, 20);
            new->lastack = htonl(header->ack_num);
            new->acknum = htonl(header->seq_num);
            new->rwnd = htons(header->recieve_window);
            new->rc_buffer = list_open();
            new->r_buffer = list_open();

            new->listen_handle = handle;
            
            new->td_ack = 0;
            new->td_ack_cnt = 0;

            new->cwnd = 1;

            pushpush(tcp_context, new, header2, NULL, 0);

            handle->state = CLOSED;
            handle->cstate = LISTEN_;
        }else if (handle->state == SYN_RCVD){
            handle->state = ESTAB;
            baby(tcp_context, handle, header);
            if (!tcp_context->ktcp_lib->tcp_passive_open(handle->listen_handle, handle)) return;
            handle->lastack = htonl(header->ack_num);
            handle->acknum = htonl(header->seq_num);
            handle->rwnd = htons(header->recieve_window);
            handle->buflen = 0;
        }else if (handle->state == ESTAB){
          //  handle->rwnd += htonl(header->ack_num)- handle->lastack;
            handle->lastack = (uint32_t)htonl(header->ack_num);
            if (header->flags == 0x01){
                handle->acknum = htonl(header->seq_num) + data_size - 20;
                header = make_header(htons(handle->source->sin_port),htons(handle->dest->sin_port),handle->seqnum, handle->acknum+1, (uint8_t)0x50, (uint8_t)0x10, handle->rwnd_r, 0, 0);
                header->checksum = tcp_checksum(header, handle->source->sin_addr, handle->dest->sin_addr,  20, 0);
                tcp_context->ktcp_lib->tcp_dispatch_ip(handle->source->sin_addr,handle->dest->sin_addr,header,20);

                handle->state = CLOSE_WAIT;
                return;
            }
            if (header->flags == 0x10){
                baby(tcp_context, handle, header);
            }
            
            if(handle->buflen == 0 && data_size > 20){
                send_ack(tcp_context, handle, header, data, data_size);
            }

            flush_buf(tcp_context, handle);
        }    
    }

}

/**
 * @todo
 *
 * @brief
 * This function is called when timer activated.
 * Each timer is bound to each context.
 *
 * @param tcp_context global context generated in my_startup.
 * @param handle TCP context bound to this timer
 * @param actual_called actual time this timer called (in mtime)
 */
static void my_timer(global_context_t* tcp_context, my_context handle, int actual_called)
{
    
  //  printf("aaa\n");
    ctx* h = (ctx *)handle;
    /*
    if (h->nc == 1){
        tcp_context->ktcp_lib->tcp_dispatch_ip(h->source->sin_addr,h->dest->sin_addr,h->tcp_data,20+ h->real_data_size);
        return;
    }*/

    h->cwnd = 1;
    int mtime;
    int cnt = 0;

    if (list_get_count(h->rc_buffer) == 0) return;

    list_position iter;
    r_data *temp;
    iter = list_get_head_position(h->rc_buffer);
    while(iter && cnt < h->cwnd){
        temp = (r_data *)list_get_at(iter);
        void* pack = malloc(sizeof(tcp_header) + temp->data_size);
        memcpy(pack,temp->header,20);
        memcpy(pack+20,temp->data,temp->data_size);
        tcp_context->ktcp_lib->tcp_dispatch_ip(h->source->sin_addr,h->dest->sin_addr,pack,temp->data_size+20);
        iter = list_get_next_position(iter);
        cnt++;
    }
    mtime = tcp_context->ktcp_lib->tcp_get_mtime();
    tcp_context->ktcp_lib->tcp_register_timer(h,mtime + 200);

    
    
}
/** my implemetation**/


tcp_header* make_header(uint16_t source_port, uint16_t dest_port, uint32_t seq_num, uint32_t ack_num, uint8_t headlen, uint8_t flags, uint16_t recieve_window, uint16_t checksum, uint16_t urg_ptr){
    tcp_header* header = malloc(sizeof(tcp_header)); 
    
    header->source_port=htons(source_port);
    header->dest_port=htons(dest_port);
    header->seq_num=htonl(seq_num);
    header->ack_num=htonl(ack_num);
    header->headlen=headlen;
    header->flags=flags;
    header->recieve_window=htons(recieve_window);
    header->checksum=htons(checksum);
    header->urg_ptr=htons(urg_ptr);

    return header;
}

uint16_t tcp_checksum(tcp_header *header, struct in_addr sip, struct in_addr dip, int size, int datalen){
    uint16_t *h = (uint16_t *)header;
    uint32_t sum  = 0;
    while(size>0){
        sum += *h++;
        size-=2;
    }

    uint32_t sipp = sip.s_addr;
    uint32_t dipp = dip.s_addr;
    sum += sipp & 0xffff;
    sum += (sipp >> 16) & 0xffff;
    sum += dipp & 0xffff;
    sum += (dipp >> 16) & 0xffff;
    sum += htons(0x0006);
    sum += htons((uint16_t)(20+datalen));


    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (uint16_t)(~sum);
}

my_context get_ctx(global_context_t* tcp_context, struct in_addr src_addr, struct in_addr dest_addr, unsigned short src_port, unsigned short dest_port){
    ctx* temp;

    list_position iter;
    iter = list_get_head_position(tcp_context->connectionlist);
    while(iter){
        temp = (ctx *)list_get_at(iter);

        if ((temp->source->sin_port == src_port) &&
            (temp->dest->sin_port == dest_port) &&
            ((temp->source->sin_addr.s_addr == src_addr.s_addr) || (temp->source->sin_addr.s_addr == 0)) &&
            (temp->dest->sin_addr.s_addr == dest_addr.s_addr)){
            return temp;
        }
        iter = list_get_next_position(iter);
    }
    return NULL;
}

my_context get_ctx_syn(global_context_t* tcp_context, struct in_addr src_addr, unsigned short src_port){
    ctx* temp;

    list_position iter;
    iter = list_get_head_position(tcp_context->contextlist);

    while(iter){
        temp = (ctx *)list_get_at(iter);
        if ((temp->source->sin_port == src_port) &&
            ((temp->source->sin_addr.s_addr == src_addr.s_addr) || (temp->source->sin_addr.s_addr == 0))
            )
        {
                return temp;
        }
        iter = list_get_next_position(iter);
    }
    return NULL;
}

void send_ack(global_context_t* tcp_context, ctx* handle, tcp_header* header, void* data, int data_size){
    if (data_size > 20){
            if (htonl(header->seq_num) >= handle->acknum){

                r_data *d = malloc(sizeof(r_data));
                d->header = malloc(sizeof(tcp_header));
                memcpy(d->header, header, 20);
                d->data = malloc(data_size-20);
                memcpy(d->data, data+20, data_size-20);
                d->data_size = data_size-20;

                list_position iter = NULL;
                
                if (list_get_count(handle->r_buffer) == 0){
                    list_add_head(handle->r_buffer, d);
                    handle->rwnd_r -= d->data_size;
                }else{               
                    iter = list_get_head_position(handle->r_buffer);
                    while(iter){
                        r_data *temp = (r_data *)list_get_at(iter);
                        if (htonl(temp->header->seq_num) > htonl(d->header->seq_num)){
                            list_insert_before(iter, d);
                            handle->rwnd_r -= d->data_size;
                             break;
                        }else if(htonl(temp->header->seq_num) == htonl(d->header->seq_num)){
                          //  free(d);
                               break;
                        }
                        iter = list_get_next_position(iter);
                    }
                    if (!iter){
                      //  printf("aaaaaaaa\n");
                        list_add_tail(handle->r_buffer, d);
                        handle->rwnd_r -= d->data_size;
                    }
                }
               

                iter = list_get_head_position(handle->r_buffer);
              //  printf("%d %d\n", d->header->seq_num, handle->acknum);
                while (iter){
                    r_data *d = (r_data *)list_get_at(iter);
                  // printf("%d %d\n", htonl(d->header->seq_num), handle->acknum);
                    if (htonl(d->header->seq_num) == handle->acknum){
                    //    printf("%d %d\n",htonl(d->header->seq_num),handle->acknum );
                        void* tcp_data = malloc(d->data_size);
                        memcpy(tcp_data, d->data, d->data_size);
                        tcp_context->ktcp_lib->tcp_dispatch_app(handle,tcp_data,d->data_size);
                        free(tcp_data);

                        handle->acknum += d->data_size;
                        handle->rwnd_r += d->data_size;
                        list_remove_head(handle->r_buffer);

                        iter = list_get_next_position(iter);
                                         //   free(d);
                    }else{
                        break;
                    }
                }
            }

            header = make_header(htons(handle->source->sin_port),htons(handle->dest->sin_port),handle->seqnum, handle->acknum, (uint8_t)0x50, (uint8_t)0x10, handle->rwnd_r, 0, 0);
            header->checksum = tcp_checksum(header, handle->source->sin_addr, handle->dest->sin_addr,  20, 0);
            tcp_context->ktcp_lib->tcp_dispatch_ip(handle->source->sin_addr,handle->dest->sin_addr,header,20);
    }
}

void flush_buf(global_context_t* tcp_context, ctx* handle){
        int cnt;

        while(handle->buflen > 0)
        {
            int real_data_size = (handle->buflen > 512) ? 512 : handle->buflen;
            int written;
            
            if(handle->rwnd - real_data_size < 0 || handle->cwnd <= cnt)
                break;
            void *tcp_data = malloc(20+real_data_size);
            tcp_header *header = make_header(htons(handle->source->sin_port),htons(handle->dest->sin_port),handle->seqnum, handle->acknum, (uint8_t)0x50, (uint8_t)0x10, handle->rwnd_r, 0, 0);
            memcpy(tcp_data,header,20);
            if(real_data_size + handle->start > BUFMAX)
            {
                memcpy(tcp_data+20,handle->buffer+handle->start,BUFMAX-handle->start);
                memcpy(tcp_data+20+BUFMAX-handle->start,handle->buffer,real_data_size-BUFMAX+handle->start);
                handle->start = real_data_size - BUFMAX + handle->start; 
            }
            else{
                memcpy(tcp_data+20,handle->buffer+handle->start,real_data_size);
                handle->start += real_data_size; 
            }
            header->checksum = tcp_checksum(tcp_data, handle->source->sin_addr, handle->dest->sin_addr,  20+real_data_size,real_data_size);
            memcpy(tcp_data,header,20);
/*
            handle->nc = 1;
            handle->real_data_size = real_data_size;
            handle->tcp_data = tcp_data;
            tcp_context->ktcp_lib->tcp_register_timer(handle, tcp_context->ktcp_lib->tcp_get_mtime()+10*cnt);
            handle->nc = 0;*/
            written = tcp_context->ktcp_lib->tcp_dispatch_ip(handle->source->sin_addr,handle->dest->sin_addr,tcp_data,20+ real_data_size); 
        //    int i=0;
        //    while(i<10000) i++;           
            handle->seqnum += real_data_size;
            handle->buflen-=real_data_size;
            handle->rwnd-=real_data_size;
            
            cnt++;
            pushpush(tcp_context, handle, header, tcp_data+20, real_data_size);
        }
}

void pushpush(global_context_t* tcp_context,ctx *cli,tcp_header* header, void* data, int data_size){

    r_data *new = malloc(sizeof(r_data));

    new->header = header;
    new->data_size = data_size;
    new->data = malloc(data_size);
    
    memcpy(new->data,data,data_size);
    list_add_tail(cli->rc_buffer, new);
    
    if(list_get_count(cli->rc_buffer) == 1){
        int mtime = tcp_context->ktcp_lib->tcp_get_mtime();
        tcp_context->ktcp_lib->tcp_register_timer(cli,mtime + 200);
    }
    /*
    if(cli->state == ESTAB)
        cli->cwnd--;*/    
}

void baby(global_context_t* tcp_context, ctx *handle, tcp_header* header){
    if (htonl(header->ack_num) > handle->td_ack){
        handle->td_ack = htonl(header->ack_num);
        handle->td_ack_cnt = 1;
    }else if (htonl(header->ack_num) == handle->td_ack){
        handle->td_ack_cnt++;
        if (handle->td_ack_cnt == 3){
            int temp1 = handle->cwnd/2;
            
            tcp_context->ktcp_lib->tcp_unregister_timer(handle);
          /*  int mtime = tcp_context->ktcp_lib->tcp_get_mtime();
            tcp_context->ktcp_lib->tcp_register_timer(handle,mtime);*/
          
            ctx* h = (ctx *)handle;
          //  h->cwnd = 1;
            int mtime;
            int cnt = 0;

            if (list_get_count(h->rc_buffer) == 0) return;

            list_position iter;
            r_data *temp;
            iter = list_get_head_position(h->rc_buffer);
            while(iter && cnt < h->cwnd){
                temp = (r_data *)list_get_at(iter);
                void* pack = malloc(sizeof(tcp_header) + temp->data_size);
                memcpy(pack,temp->header,20);
                memcpy(pack+20,temp->data,temp->data_size);
                tcp_context->ktcp_lib->tcp_dispatch_ip(h->source->sin_addr,h->dest->sin_addr,pack,temp->data_size+20);
                iter = list_get_next_position(iter);
                cnt++;
            }
            mtime = tcp_context->ktcp_lib->tcp_get_mtime();
            tcp_context->ktcp_lib->tcp_register_timer(h,mtime + 200);

            handle->cwnd = temp1;
          //  my_timer(tcp_context, handle, 0); 
            handle->td_ack_cnt = 0;
        }
    }

   // printf("aaaaaaaa\n"); 
    if (list_get_count(handle->rc_buffer) != 0){
        r_data* d = (r_data *)list_get_head(handle->rc_buffer);
       //  printf("%d %d\n", htonl(d->header->seq_num)+1, htonl(header->ack_num));

    
        if ((d->header->flags & 0x02) == 0x02 || d->header->flags == 0x01){
            if (htonl(d->header->seq_num)+1 == htonl(header->ack_num)){
                if (d->header->flags == 0x01 && handle->state == FIN_WAIT_1) handle->state = FIN_WAIT_2;
                tcp_context->ktcp_lib->tcp_unregister_timer(handle);
                list_remove_head(handle->rc_buffer);
            }
        }else{
          //  list_position iter
          
           // printf("=============\n");
            while(true){
                if (list_get_count(handle->rc_buffer) == 0) break;
                r_data* d = (r_data *)list_get_head(handle->rc_buffer);
                if (d==NULL) break;

             //   printf("%d %d\n", htonl(d->header->seq_num) + d->data_size, htonl(header->ack_num));
                if (htonl(d->header->seq_num)+d->data_size <= htonl(header->ack_num)){
                    tcp_context->ktcp_lib->tcp_unregister_timer(handle);
                    handle->rwnd+=d->data_size;
                    handle->cwnd+=1;
                    if (handle->cwnd > 6){
                        handle->cwnd = 6;
                    }
                    list_remove_head(handle->rc_buffer);
                }else{
                    break;
                }
            }
        //    printf("============\n");
            
            if (list_get_count(handle->rc_buffer) != 0){
                int mtime = tcp_context->ktcp_lib->tcp_get_mtime();
                tcp_context->ktcp_lib->tcp_register_timer(handle,mtime + 200);
            }
            
        }
    }
}



