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

typedef struct
{
	ktcp_easy_impl my_syscall;

	//add global variables here
	ktcp_easy_lib* ktcp_lib;
        list contextlist;
        list connectionlist;
        short cnt;

}global_context_t;

enum states{
    CLOSED,
    LISTEN,
    SYN_RCVD,
    SYN_SENT,
    ESTAB
};

enum con_state{
    OPEN,
    BIND,
    CONNECT,
    LISTEN_,
    ACCEPT,
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

    list pendinglist;
    int backlog;
}ctx;      

typedef struct{
    struct in_addr sip;
    struct in_addr dip;
    tcp_header *header;
}pending_data;



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

my_context get_ctx(global_context_t* tcp_context, struct in_addr src_addr, struct in_addr dest_addr, short src_port, short dest_port);
my_context get_ctx_syn(global_context_t* tcp_context, struct in_addr src_addr, short src_port);
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

    init->state = CLOSED;
    init->cstate = OPEN;

    list_add_tail(tcp_context->contextlist, (void *)init);
    return list_get_tail(tcp_context->contextlist);
}

/**
 * @todo
 *
 * @brief
 * Mapped with 'kclose'.
 *
 * @param tcp_context global context generated in my_startup.
 * @param handle TCP context created via 'my_open'
 * @param err ERRNO value
 */
static void my_close(global_context_t* tcp_context, my_context handle,int *err)
{
    ctx *h = (ctx *) handle;
    list_remove(tcp_context->contextlist, handle); 

    ctx* temp;
    list_position iter;
    iter = list_get_head_position(tcp_context->connectionlist);
    while(iter){
        temp = (ctx *)list_get_at(iter);
        if ((temp->source->sin_port == h->source->sin_port ) &&
            ((temp->source->sin_addr.s_addr == h->source->sin_addr.s_addr) || (temp->source->sin_addr.s_addr == 0))
            ){
                list_remove(tcp_context->connectionlist, temp);        
        }
        iter = list_get_next_position(iter);
    }

//    printf("%d\n", list_get_count(tcp_context->connectionlist));
//    return NULL;
 //   list_remove(tcp_context->connectionlist, handle);
    free(handle);
    
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

    iter = list_get_head_position(tcp_context->contextlist);
 //   printf("%d\n", list_get_count(tcp_context->contextlist));   
    while(iter){
        temp = (ctx *)list_get_at(iter);
        if (temp->source == NULL){
            iter = list_get_next_position(iter);  
            continue;
        }
      //  printf("%d %d\n", temp->source->sin_addr.s_addr, htons(temp->source->sin_port));
      //  printf("%d %d\n", my_addr_->sin_addr.s_addr, htons(my_addr_->sin_port));
        if ((my_addr_->sin_addr.s_addr==temp->source->sin_addr.s_addr) || (my_addr_->sin_addr.s_addr ==htonl(INADDR_ANY)) || (temp->source->sin_addr.s_addr == htonl(INADDR_ANY))){
            if (my_addr_->sin_port==temp->source->sin_port){
             //   printf("aaaaaaaaa\n");
                *err=EADDRINUSE;
                return false;
            }
        }
        iter = list_get_next_position(iter);
    }

//    printf("aaaaaaaaaaa\n");
    temp = malloc(sizeof(struct sockaddr_in));
    memcpy(temp, my_addr_, addrlen);
    ((ctx *)handle)->source = temp;
    ((ctx *)handle)->sourcelen = addrlen; 
    ((ctx *)handle)->cstate = BIND;

//    printf("aaaaaaaaaaaaaaaa\n");
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

  //  printf("\naaaaaaaaaaaaaaaaaaa\n");
    ctx *cli = (ctx *)handle;

    uint16_t sport = htons(((struct sockaddr_in *)serv_addr)->sin_port);
    struct in_addr sip = ((struct sockaddr_in *)serv_addr)->sin_addr;

    if (cli->state != CLOSED){
        return false;
    }   

   //  printf("aaaaaaaa\n");    
    cli->state = SYN_SENT;

    cli->destlen = sizeof(struct sockaddr_in);
    struct sockaddr_in *temp = malloc(sizeof(struct sockaddr_in));

    memcpy(temp, serv_addr, sizeof(struct sockaddr_in));
    cli->dest = temp;

  //  printf("aaaaaaaaaaaaaaaaaaa\n");
    if(cli->cstate == OPEN){
   //     do{
        struct sockaddr_in *temp;
        temp = malloc(sizeof(struct sockaddr_in));
        temp->sin_family = AF_INET;
        temp->sin_port = htons(tcp_context->cnt);
        temp->sin_addr.s_addr = tcp_context->ktcp_lib->ip_host_address(sip);
        tcp_context->cnt++;
        
        cli->source = temp;
        cli->sourcelen = sizeof(struct sockaddr_in);
      //  printf("%d\n", cnt);
  //      } while (!my_bind(tcp_context, handle, temp, sizeof(struct sockaddr),*err));
       // cli->source = temp;
    }


  //  printf("\naaafffffaaaaaaaaaaaaaaaaaa\n");

    tcp_header* header = 
        make_header((uint16_t)htons(cli->source->sin_port), sport, 0, 0, (uint8_t)0x50, (uint8_t)0x02, 3000, 0, 0);
    
    header->checksum = tcp_checksum(header, cli->source->sin_addr, sip,  20, 0);
    tcp_context->ktcp_lib->tcp_dispatch_ip(cli->source->sin_addr, sip, (void *)header, 20);

    cli->cstate=CONNECT;

//    printf("aaaaaaaaaaaaaaadfsfsfsdf\n");
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

 //   printf("cccccccccccccccccccccccc\n");

        
 //   printf("%d\n", list_get_count(h->pendinglist));
    
    if (list_get_count(h->pendinglist) != 0){
    //    printf("bbbbbbbbbbbbbbbbbbb\n");
        pending_data* t = list_remove_head(h->pendinglist);
        ctx* new = (ctx *)malloc(sizeof(ctx));
        list_add_tail(tcp_context->connectionlist, new);
        
        new->sourcelen = h->sourcelen;
        new->source = malloc(sizeof(struct sockaddr_in));
        memcpy(new->source, h->source, h->sourcelen);

        new->destlen = sizeof(struct sockaddr_in); 
        new->dest = malloc(sizeof(struct sockaddr_in));
        new->dest->sin_family = AF_INET;
        new->dest->sin_addr = t->dip;
        new->dest->sin_port = t->header->source_port;

        new->cstate = ACCEPT;
        new->state = SYN_RCVD;

        if (!tcp_context->ktcp_lib->tcp_passive_open(h, new)) return false;


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
  //  if (h->source==NULL) return false;
   
 //   printf("aaaaaaaaaaaaaaa\n");
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

 //   printf("\n--------%d %d-----------\n", header->dest_port, header->source_port);
 //
    ctx* handle;
    if ((header->flags & 0x02) == 0x02){
   //     printf("\n%d\n", dest_addr.s_addr);
        handle = get_ctx_syn(tcp_context, dest_addr, header->dest_port);
 //       printf("\n%d\n", handle==NULL);

    }else{
        handle = get_ctx(tcp_context, dest_addr, src_addr, header->dest_port,header->source_port);

    }
    
    struct in_addr sip = dest_addr;
    struct in_addr dip = src_addr;
    
    short sport = htons(header->dest_port);
    short dport = htons(header->source_port);

    uint16_t checksum = tcp_checksum(header, sip, dip, 20, 0);

//    printf("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n");
//    if (handle != NULL)   printf("\n%d %d\n", handle->state, handle->cstate);

    if (handle == NULL) return;

 //   printf("aaaaaaaaaaaaaaaaaaaaaa\n");

    if (handle->cstate == CONNECT){
        if (handle->state == SYN_SENT){
            if(!checksum){
                 //               printf("%x\n", header->flags);
                if(((header->flags & 0x12) == 0x12)){
               //  printf("aaaaaaaaaaaa\n");  
                    handle->state = ESTAB;
                }
                else if((header->flags & 0x02) == 0x02){
                    handle->state = SYN_RCVD;
                    list_add_tail(tcp_context->connectionlist, handle);
                }

           //     printf("aaaaaaaaaaaaaaaaaaaaaa\n");
                if (!tcp_context->ktcp_lib->tcp_active_open((void *)handle)) return false;

                list_remove(tcp_context->contextlist, handle);
                header = make_header(sport, dport, 1, htonl(header->seq_num)+1, (uint8_t)0x50, (uint8_t)0x10, 3000, 0, 0);
                header->checksum = tcp_checksum(header, sip, dip, 20, 0);

                tcp_context->ktcp_lib->tcp_dispatch_ip(sip, dip, (void *)header, 20);
            }
        }else if(handle->state == SYN_RCVD){
            if (!checksum){
                if ((header->flags & 0x10) == 0x10){
                    handle->state = ESTAB;              
                    list_remove(tcp_context->connectionlist, handle);
                }
            }
        }
  //      tcp_context->ktcp_lib->tcp_active_open((void *)handle);
    }else if (handle->cstate == LISTEN_){
        if (handle->state == CLOSED){
          //  printf("\n");
            if (!checksum && (header->flags & 0x02) == 0x02){
            //    printf("nnnnnnaaaaaaaaaaaaannnnnnnnnnnnn\n");
                if (handle->backlog > list_get_count(handle->pendinglist) ){

              //      printf("nnnnnnnnnnnnnnnnnnnnnnnnnnnn\n");
                    pending_data* t = malloc(sizeof(pending_data));
                    t->sip = sip;
                    t->dip = dip;
                    t->header = header;
                    list_add_tail(handle->pendinglist, t);

                    tcp_header* header2 = make_header(htons(header->dest_port), htons(header->source_port), 0, htonl(header->seq_num)+1, (uint8_t)0x50, (uint8_t)0x12, 3000, 0, 0);
                    header2->checksum = tcp_checksum(header2, sip, dip, 20, 0);
                    tcp_context->ktcp_lib->tcp_dispatch_ip(sip, dip, (void *)header2, 20);
              //      printf("aaaaaaaaaaaa\n");
                }   
            }
        }
    }else if (handle->cstate == ACCEPT){
        if (handle->state == LISTEN){
          //  pending_data* t = list_remove_head(h->pendinglist);
          //
      //      printf("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n");
            ctx* new = (ctx *)malloc(sizeof(ctx));
            list_add_tail(tcp_context->connectionlist, new);
            
            new->sourcelen = handle->sourcelen;
            new->source = malloc(sizeof(struct sockaddr_in));
            memcpy(new->source, handle->source, handle->sourcelen);

            new->destlen = sizeof(struct sockaddr_in); 
            new->dest = malloc(sizeof(struct sockaddr_in));
            new->dest->sin_family = AF_INET;
            new->dest->sin_addr = dip;
            new->dest->sin_port = header->source_port;

   //         printf("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n");

            new->cstate = ACCEPT;
            new->state = SYN_RCVD;

            tcp_header* header2 = make_header(htons(header->dest_port), htons(header->source_port), 0, htonl(header->seq_num)+1, (uint8_t)0x50, (uint8_t)0x12, 3000, 0, 0);

   //         printf("ccccccccccccccccccccccc\n");
            header2->checksum = tcp_checksum(header2, sip, dip, 20, 0);
            tcp_context->ktcp_lib->tcp_dispatch_ip(sip, dip, (void *)header2, 20);


         //   printf("bbbbbbbbbbbbbb\n");
            if (!tcp_context->ktcp_lib->tcp_passive_open(handle, new)) return;

            handle->state = CLOSED;
            handle->cstate = LISTEN_;
        }else if (handle->state == SYN_RCVD){
            handle->state = ESTAB;
            list_remove(tcp_context->connectionlist, handle);
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
   //     printf("\n%x\n", (*h));
        sum += *h++;
        size-=2;
    }

    uint32_t sipp = sip.s_addr;
    uint32_t dipp = dip.s_addr;
   // printf("%x\n %x\n", sipp,dipp);
   //
    sum += sipp & 0xffff;
    sum += (sipp >> 16) & 0xffff;
    sum += dipp & 0xffff;
    sum += (dipp >> 16) & 0xffff;
    sum += htons(0x0006);
    sum += htons((uint16_t)(20+datalen));


    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);

//    printf("%x\n", ~sum);
    return (uint16_t)(~sum);
}

my_context get_ctx(global_context_t* tcp_context, struct in_addr src_addr, struct in_addr dest_addr, short src_port, short dest_port){
    ctx* temp;

    list_position iter;
    iter = list_get_head_position(tcp_context->connectionlist);
  //  tcp_header *h = (tcp_header *)data;

    while(iter){
        temp = (ctx *)list_get_at(iter);

     //   printf ("aaaaaaa %d %d\n", temp->source->sin_port, (src_port));
     //   printf ("bbbbbbb %d %d\n", temp->dest->sin_port, dest_port);
      //  printf ("ccccccc %d %d\n", temp->source->sin_addr.s_addr, src_addr.s_addr);
        if ((temp->source->sin_port == src_port) &&
            (temp->dest->sin_port == dest_port) &&
            ((temp->source->sin_addr.s_addr == src_addr.s_addr) || (temp->source->sin_addr.s_addr == 0)) &&
            (temp->dest->sin_addr.s_addr == dest_addr.s_addr)){
       //     printf("connect111111\n");
            return temp;
        }
        iter = list_get_next_position(iter);
    }
    return NULL;
}

my_context get_ctx_syn(global_context_t* tcp_context, struct in_addr src_addr, short src_port){
    ctx* temp;

    list_position iter;
    iter = list_get_head_position(tcp_context->contextlist);
  //  tcp_header *h = (tcp_header *)data;

    while(iter){
        temp = (ctx *)list_get_at(iter);

    //    printf ("aaaaaaa %d %d\n", temp->source->sin_port, (src_port));
     //   printf ("bbbbbbb %d %d\n", temp->dest->sin_port, dest_port);
     //   printf ("ccccccc %d %d\n", temp->source->sin_addr.s_addr, src_addr.s_addr);
        if ((temp->source->sin_port == src_port) &&
            ((temp->source->sin_addr.s_addr == src_addr.s_addr) || (temp->source->sin_addr.s_addr == 0))
            ){
       //     printf("connect111111\n");
       //     if (temp->state != ESTAB)
                return temp;
        }
        iter = list_get_next_position(iter);
    }
    return NULL;
}


