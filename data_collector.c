#include <linux/bpf.h>
#include <linux/if_ether.h>     // for ethhdr
#include <linux/ip.h>           // for iphdr
#include <bpf/bpf_endian.h>     // for bpf_htons()
#include <asm/types.h>
#include <linux/types.h>        
#include <stdint.h>
#include <linux/pkt_sched.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <inttypes.h>           // For %llx
#include <asm-generic/errno-base.h>

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2
// #define TC_ACT_UNSPEC -1
#define TC_ACT_RECLASSIFY 1

#define ETH_P_IP 0x0800
#define MAX_ENTRIES 10240

// #define bpf_printk(fmt, ...)                            \
// ({                                                      \
//         char ____fmt[] = fmt;                           \
//         bpf_trace_printk(____fmt, sizeof(____fmt),      \
//                          ##__VA_ARGS__);                \
// })

#ifndef __section
# define __section(x)  __attribute__((section(x), used))
#endif

struct PUC_entry {
    unsigned int src_addr;
    unsigned int dest_addr;
    unsigned int max_pkt_size;
    unsigned int min_pkt_size;
    unsigned int sec_max_pkt_size;
    unsigned long long int max_iat;
    unsigned long long int latest_time;
    unsigned int ip_version;
    unsigned int rx_count;
    // unsigned int tx_count;
    // unsigned int tcp_count;
    // unsigned int udp_count;
    unsigned int rx_bytes;
    // unsigned int tx_bytes;
    unsigned long long int first_pkt_time;
    unsigned int flag;
};

struct bpf_elf_map {
               __u32 type;
               __u32 size_key;
               __u32 size_value;
               __u32 max_elem;
               __u32 flags;
               __u32 id;
               __u32 pinning;
               __u32 inner_id;
               __u32 inner_idx;
           };

struct bpf_elf_map __section("maps") PUC_info = {
    .type       = BPF_MAP_TYPE_HASH,
    .id         = 1,
    .size_key   = sizeof(uint32_t),
    .size_value = sizeof(struct PUC_entry),
    .max_elem   = MAX_ENTRIES,
    .pinning    = LIBBPF_PIN_BY_NAME,
};

int tc_ingress(struct __sk_buff *skb)
{
	void *data_end = (void *)(unsigned long long)skb->data_end;
	void *data = (void *)(unsigned long long)skb->data;
	struct ethhdr *eth = data;
	struct iphdr *iph;

	if (skb->protocol!=bpf_htons(ETH_P_IP))
		return TC_ACT_OK;

	if (data + sizeof(struct ethhdr) > data_end)
		return TC_ACT_OK;

	iph = (struct iphdr *)(eth+1);
	if ((void *)(iph+1)>data_end)
		return TC_ACT_OK;

    if (iph->protocol!=1)           // Checking if ping packet
        return TC_ACT_OK;

    // bpf_printk("Packet received with protocol %llx", skb->protocol);

	unsigned long long int curr_time = bpf_ktime_get_ns();
    unsigned int src_addr = iph->saddr;
    unsigned int dest_addr = iph->daddr;
    unsigned int pkt_size = bpf_ntohs(iph->tot_len);
    unsigned int iph_proto = iph->protocol;

    bpf_printk("Source: %pI4 Destination: %pI4 Protocol: %llx", &iph->saddr, &iph->daddr, skb->protocol);

    struct PUC_entry *entry;
    entry = bpf_map_lookup_elem(&PUC_info, &src_addr);

    if(entry) {
        // bpf_printk("Entry exists");
        if(entry->max_pkt_size < pkt_size) { 
            entry->sec_max_pkt_size = entry->max_pkt_size;
            entry->max_pkt_size = pkt_size;
        }
        else if(entry->sec_max_pkt_size < pkt_size && pkt_size!=entry->max_pkt_size) {
            entry->sec_max_pkt_size = pkt_size;
        }
        else if (entry->min_pkt_size > pkt_size) { 
            entry->min_pkt_size = pkt_size;
        }
        unsigned long long int iat = curr_time - entry->latest_time;
        // bpf_printk("IAT is %llu", curr_time);
        if(iat > entry->max_iat) {
            entry->max_iat = iat;
        }
        entry->latest_time = curr_time;
	    __sync_fetch_and_add(&entry->rx_count, 1);
	    __sync_fetch_and_add(&entry->rx_bytes, bpf_ntohs(iph->tot_len));
        // Parsing DT and updating flag (label)
        if(entry->min_pkt_size<=4 && entry->max_pkt_size<=7 && entry->max_pkt_size>5) {
            entry->flag=1;
        }
        else if(entry->min_pkt_size<=12 && entry->max_iat>99 && entry->max_pkt_size>4379) {
            entry->flag=1;
        }
        else if(entry->min_pkt_size<=12 && entry->min_pkt_size>1 && entry->max_iat>469570 && entry->max_pkt_size<=14) {
            entry->flag=1;
        }
    }
    else {
        struct PUC_entry new_entry = {};
        new_entry.src_addr = src_addr;
        new_entry.dest_addr = dest_addr;
        new_entry.max_pkt_size = pkt_size;
        new_entry.min_pkt_size = pkt_size;
        new_entry.sec_max_pkt_size = pkt_size;
        new_entry.max_iat = 0;
        new_entry.latest_time = curr_time;
        new_entry.ip_version = bpf_ntohs(skb->protocol);
        new_entry.rx_count = 1;
        // new_entry.tcp_count = 0;
        // new_entry.udp_count = 0;
        // if(iph_proto==6) {
        //     __sync_fetch_and_add(&)
        // }
        new_entry.rx_bytes = bpf_ntohs(iph->tot_len);
        // new_entry.tx_bytes = 0;
        new_entry.first_pkt_time = curr_time;
        if(entry->min_pkt_size<=4 && entry->max_pkt_size<=7 && entry->max_pkt_size>5) {
            new_entry.flag=1;
        }
        else {
            new_entry.flag = 0;
        }
        int err = bpf_map_update_elem(&PUC_info, &src_addr, &new_entry, BPF_ANY);
        if(err<0) {
            if(err==-12) {
                bpf_printk("Memory full");
            }
            else {
                bpf_printk("Some other error, not inserted");
            }
        }
    }

	return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";
