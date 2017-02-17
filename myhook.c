
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <net/tcp.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_bridge.h>
#include <linux/jiffies.h>


#define DEBUG
#ifdef DEBUG
    #define debugmsg(format, ...) printk("zz>> "format"\n", ##__VA_ARGS__)
#else
    #define debugmsg(format, ...)
#endif         

#define LOCAL static
#define NIPQUAD_FMT "%u.%u.%u.%u"
#define NIPQUAD(addr) \
 ((unsigned char *)&addr)[0],  ((unsigned char *)&addr)[1],  ((unsigned char *)&addr)[2],  ((unsigned char *)&addr)[3]
#define SOCKET_OPT_BASE 128
#define SOCKET_OPT_SETTARGET (128)
#define SOCKET_OPT_GETTARGET (128)
#define SOCKET_OPT_MAX (SOCKET_OPT_BASE+1)
#define PORT_MAX 64*1024
#define PORT_USED 1
#define PORT_UNUSED 0
#define CMD_POOL_MIN_LEN 16
#define CMD_POOL_MAX_LEN 1000

typedef struct redirect_port{
    char port[PORT_MAX];
    int* current_port; 
    spinlock_t change_lock;
    int used_port_max;
}redirect_port;

redirect_port r_port;
LOCAL void printSrcAndDesIP(struct iphdr *iph)
{
    debugmsg("src ip " NIPQUAD_FMT "\n", NIPQUAD(iph->saddr));
    debugmsg("des ip " NIPQUAD_FMT "\n", NIPQUAD(iph->daddr));
    if (iph->daddr == 0xffffffff) {
        debugmsg("---a udp broad cast received---\n");
    }
}

int my_atoi(char* pstr)  
{  
    int Ret_Integer = 0;  
    int Integer_sign = 1;  
    if(pstr == NULL)  
    {    
        return 0;  
    }  
    while((*pstr) == '\0')  
    {  
        pstr++;  
    }  
    if(*pstr == '-')  
    {  
        Integer_sign = -1;  
    }  
    if(*pstr == '-' || *pstr == '+')  
    {  
        pstr++;  
    }  
    while(*pstr >= '0' && *pstr <= '9')  
    {  
        Ret_Integer = Ret_Integer * 10 + *pstr - '0';  
        pstr++;  
    }  
    Ret_Integer = Integer_sign * Ret_Integer;        
    return Ret_Integer;  
}  

LOCAL int dns_prer_redirect(struct sk_buff *skb, struct iphdr *iph, struct udphdr *udph, __u16 new_port, char dst_src){
    
    struct rtable *rt = skb_rtable(skb); 
    int datalen, oldlen;
    oldlen = skb->len - iph->ihl*4; 
    if (!skb_make_writable(skb, skb->len))  
        return 0;
    printSrcAndDesIP(iph);
    // dst port  
    if (dst_src==0){ 
        debugmsg("old dst_port %u", htons(udph->dest));
        udph->dest = ntohs(new_port);   
        debugmsg("new dst_port %u", htons(udph->dest));
    }
    else if (dst_src==1){
        debugmsg("old src_port %u", htons(udph->source));
        udph->source = ntohs(new_port);   
        debugmsg("new src_port %u", htons(udph->source));       
    }
    
    /* update the length of the UDP packet */  
    datalen = skb->len - iph->ihl*4;  
    udph->len = htons(datalen);       
    ip_hdr(skb)->tot_len = htons(skb->len);  
    ip_send_check(ip_hdr(skb));
    /* fix udp checksum if udp checksum was previously calculated */  
    if (!udph->check && skb->ip_summed != CHECKSUM_PARTIAL)  
        return 1;  
  
    if (skb->ip_summed != CHECKSUM_PARTIAL) {  
        if (rt &&   !(rt->rt_flags & RTCF_LOCAL) &&  
            skb->dev->features & NETIF_F_V4_CSUM) {  
            skb->ip_summed = CHECKSUM_PARTIAL;  
            skb->csum_start = skb_headroom(skb) +  
                      skb_network_offset(skb) +  
                      iph->ihl * 4;  
            skb->csum_offset = offsetof(struct udphdr, check);  
            udph->check = ~csum_tcpudp_magic(iph->saddr, iph->daddr,  
                             datalen, IPPROTO_UDP,  
                             0);  
        } else {  
            udph->check = 0;  
            udph->check = csum_tcpudp_magic(iph->saddr, iph->daddr,  
                            datalen, IPPROTO_UDP,  
                            csum_partial(udph,  
                                     datalen, 0));  
            if (!udph->check)  
                udph->check = CSUM_MANGLED_0;  
        }  
    } else {  
        inet_proto_csum_replace2(&udph->check, skb,  
                     htons(oldlen), htons(datalen), 1);  
    }  
    return 0;
}

unsigned int uport_redirect_in_fun(const struct nf_hook_ops *ops/*unsigned int hooknum*/, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *)){
    //struct sk_buff *skb = *pskb;
	struct iphdr *ip_header;	
	struct udphdr *udp_header;
    __u16   new_dest = 0;
    int idx = 0;
    int i = 0;
    //int idx_num = 0;
	//debugmsg( "uport_redirect_in_fun called\n");

	if (!skb)//check the buffer
	{
		debugmsg( "skb is null\n");
		return NF_ACCEPT;
	}
	//ip_header  = ( struct iphdr* )skb_network_header(skb);
    ip_header  = ip_hdr(skb);  
	//dns hijack
	if ((ip_header->protocol == IPPROTO_UDP)){
		udp_header = (struct udphdr*)((char *)ip_header + ip_header->ihl*4);
		if(udp_header==NULL)
			return NF_ACCEPT;
        //ignore not-dns package
		if( likely(udp_header->dest != htons(53)) ) 
			return NF_ACCEPT;
        //change the dns packet payload     
		else{		
			debugmsg( "dns in packet from %s\n", skb->dev->name);
            debugmsg( "dns in packet src port %u\n", htons(udp_header->source));
            debugmsg( "dns in packet dst port %u\n", htons(udp_header->dest)); 
              
            spin_lock(&r_port.change_lock);
            do{
                if (r_port.used_port_max == 0)
                    break;
                idx = jiffies%(r_port.used_port_max);     
                debugmsg("idx = %d， used_port_max = %d ", idx, r_port.used_port_max);           
                /*
                for (i = 1024; i<PORT_MAX; i++){
                    if(likely(r_port.port[i] == PORT_UNUSED))
                        continue;
                    else{                         
                         if(idx_num == idx){
                            new_dest = i;
                            debugmsg("idx_num = %d", idx_num);
                            debugmsg("port = %d", new_dest);
                            break;   
                         }     
                         idx_num++;                       
                    }                            
                }
                */
                new_dest = r_port.current_port[idx];
                debugmsg("port = %d", new_dest);
            }while(0);
            spin_unlock(&r_port.change_lock); 
          
            if(new_dest == 0)
                return NF_ACCEPT;       
			if(dns_prer_redirect(skb, ip_header, udp_header, new_dest, 0) != 0)
			    return NF_DROP;
            else
                return NF_ACCEPT;
		}
	}
   //accept other packages
	return NF_ACCEPT;                             
}

unsigned int uport_redirect_out_fun(const struct nf_hook_ops *ops/*unsigned int hooknum*/, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *)){
	struct iphdr *ip_header;	
	struct udphdr *udp_header;
    //__u16   old_dest = 0x41E;
	//debugmsg( "uport_redirect_out_fun called\n");

	if (!skb)//check the buffer
	{
		debugmsg( "skb is null\n");
		return NF_ACCEPT;
	}
    ip_header  = ip_hdr(skb);  	
	if ((ip_header->protocol == IPPROTO_UDP)){
		udp_header = (struct udphdr*)((char *)ip_header + ip_header->ihl*4);
		if(udp_header==NULL)
			return NF_ACCEPT;
        //ignore not-dns-replay package
        spin_lock(&r_port.change_lock);    
        if (r_port.port[ntohs(udp_header->source)] == PORT_UNUSED){
            spin_unlock(&r_port.change_lock);
            return NF_ACCEPT;
        }    
        spin_unlock(&r_port.change_lock);
        //change the dns packet payload     		
        debugmsg( "dns out packet from %s\n", skb->dev->name);
        debugmsg( "dns out packet src port %u\n", htons(udp_header->source));
        debugmsg( "dns out packet dst port %u\n", htons(udp_header->dest));            
        if(likely(dns_prer_redirect(skb, ip_header, udp_header, 53, 1)) == 0)
            return NF_ACCEPT;
        else
            return NF_DROP;		
	}
    //accept other packages
	return NF_ACCEPT;                             
}

static int myrecv_cmd(struct sock *sk, int cmd, void __user *user, unsigned int len)
{
    int ret = 0;
    int port_index = 0;
    int i = 0;
    char* port_point = NULL;
    int* tmp_port = r_port.current_port;
    int* new_point = NULL;
    char port_cmd = '\0';
    unsigned char cmd_pool[CMD_POOL_MIN_LEN] = {'\0'};
    debugmsg("myrecv_cmd");
    if(cmd == SOCKET_OPT_SETTARGET)
    {
        memset(cmd_pool, 0, CMD_POOL_MIN_LEN);
        ret = copy_from_user(cmd_pool, user, len);
        if(ret != 0){
            debugmsg("error: can not copy data from userspace\n");
            return -1;
	    }
        debugmsg("msg:%s \n", cmd_pool);
        memcpy(&port_cmd, cmd_pool, 1);
        port_point = &(cmd_pool[2]);
        port_index = my_atoi(port_point);
        if(port_cmd == 'a'){
            if(r_port.port[port_index] == PORT_UNUSED){ 
                new_point = kmalloc((r_port.used_port_max+1)*sizeof(int), GFP_KERNEL);
                if(new_point == NULL){
                    debugmsg("error: kmalloc error \n");
                    return -1;
                }
                memcpy(new_point, r_port.current_port, r_port.used_port_max*sizeof(int));
                new_point[r_port.used_port_max+1] = port_index;
                spin_lock(&r_port.change_lock);              
                r_port.port[port_index] = PORT_USED;
                r_port.current_port = new_point;
                r_port.used_port_max++;                                           
                spin_unlock(&r_port.change_lock);
                debugmsg("port_index:%d is used, used_port_num = %d\n\rall used port is:", port_index, r_port.used_port_max); 
                for(i = 0; i<r_port.used_port_max; i++ ){
                    debugmsg("%d ", r_port.current_port[i]);
                }
                kfree(tmp_port);  
                tmp_port = NULL;
                new_point = NULL;
            }
        }
        else if(port_cmd == 'd'){
            if(r_port.port[port_index] == PORT_USED){
                for(i = 0; i<r_port.used_port_max; i++){
                    if(r_port.current_port[i] == port_index){ 
                        break;  
                    }
                }             
                new_point = kmalloc((r_port.used_port_max-1)*sizeof(int), GFP_KERNEL);
                if(new_point == NULL){
                    debugmsg("error: kmalloc error \n");
                    return -1;
                }                  
                memcpy(new_point, r_port.current_port, i*sizeof(int));
                memcpy(new_point+i*sizeof(int), r_port.current_port+(i+1)*sizeof(int), (r_port.used_port_max-i-1)*sizeof(int));
                spin_lock(&r_port.change_lock);
                r_port.port[port_index] = PORT_UNUSED;
                r_port.current_port = new_point;
                r_port.used_port_max--;                                
                spin_unlock(&r_port.change_lock);  
                debugmsg("port_index:%d is unused, used_port_num = %d\n\rall used port is:", port_index, r_port.used_port_max); 
                for(i = 0; i<r_port.used_port_max; i++ ){
                    debugmsg("%d ", r_port.current_port[i]);
                }                
                kfree(tmp_port);  
                tmp_port = NULL;
                new_point = NULL;                          
            }
              
        }
     
    }
    return ret;

}
static int mysend_cmd(struct sock *sk, int cmd, void __user *user, int* len)
{
	int ret = 0;
    unsigned char cmd_pool[CMD_POOL_MAX_LEN] = {'\0'};
    int i = 0;
    unsigned char* cmd_p = cmd_pool;
	if(cmd == SOCKET_OPT_GETTARGET)
	{
        debugmsg("mysend_cmd");
        memset(cmd_pool, 0, CMD_POOL_MAX_LEN);
        for (i = 1024; i<PORT_MAX; i++){
            if(likely(r_port.port[i] == 0))
                continue;
            else{                
                sprintf(cmd_p, "%d ", i);                
                cmd_p = cmd_pool+strlen(cmd_pool);                          
            }                            
        }       
        debugmsg("msg:%s \n", cmd_pool);
		ret = copy_to_user(user, cmd_pool, *len);
		if(ret != 0){
			debugmsg("error: can not copy data to userspace\n");
			return -1;
		}
	}
	return ret;
}

static struct nf_hook_ops udp_port_redirect_in_ops __read_mostly =
{
    .hook = uport_redirect_in_fun,
    .pf = PF_INET,
    .hooknum = NF_INET_LOCAL_IN,
    .priority = NF_IP_PRI_FIRST,
}; 

static struct nf_hook_ops udp_port_redirect_out_ops __read_mostly =
{
    .hook = uport_redirect_out_fun,
    .pf = PF_INET,
    .hooknum = NF_INET_LOCAL_OUT,
    .priority = NF_IP_PRI_FIRST,
};
static struct nf_sockopt_ops my_sockops = 
{
	.pf = PF_INET,
	.set_optmin = SOCKET_OPT_SETTARGET,
	.set_optmax = SOCKET_OPT_MAX,
	.set = myrecv_cmd,
	.get_optmin = SOCKET_OPT_GETTARGET,
	.get_optmax = SOCKET_OPT_MAX,
	.get = mysend_cmd,        
}; 

static int __init udp_port_redirect_init(void){
    debugmsg("myhook insmod\n");      
    memset(r_port.port, 0, PORT_MAX);
    r_port.used_port_max = 0;
    nf_register_sockopt(&my_sockops);
    spin_lock_init(&r_port.change_lock);
    r_port.current_port = NULL;
    nf_register_hook(&udp_port_redirect_in_ops);
    nf_register_hook(&udp_port_redirect_out_ops);
    return 0; 
} 
 
static void __exit udp_port_redirect_exit(void){
    debugmsg("myhook rmmod\n");    
    nf_unregister_hook(&udp_port_redirect_in_ops);
    nf_unregister_hook(&udp_port_redirect_out_ops);
    nf_unregister_sockopt(&my_sockops);
}

module_init(udp_port_redirect_init);  
module_exit(udp_port_redirect_exit);  

MODULE_LICENSE("GPL");  
MODULE_AUTHOR("zyp");  
 