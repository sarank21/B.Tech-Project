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

struct label_entry {
	unsigned int src_addr;
	unsigned long long int start_time;
	unsigned long long int end_time;
	unsigned int pkt_size;
	unsigned long long int total_time;
    unsigned int label;
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

struct bpf_elf_map __section("maps") label_info = {
    .type       = BPF_MAP_TYPE_HASH,
    .id         = 1,
    .size_key   = sizeof(uint32_t),
    .size_value = sizeof(struct label_entry),
    .max_elem   = MAX_ENTRIES,
    .pinning    = LIBBPF_PIN_BY_NAME,
};

int latency_ingress(struct __sk_buff *skb)
{
	unsigned long long int curr_time = bpf_ktime_get_ns();
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

	// if (iph->protocol!=1)           // Checking if ping packet
    //     return TC_ACT_OK;


	unsigned int src_addr = iph->saddr;
    unsigned int pkt_size = bpf_ntohs(iph->tot_len);

	struct label_entry entry = {};
	struct PUC_entry *new_entry;
    new_entry = bpf_map_lookup_elem(&label_info, &src_addr);

    if(new_entry) { 
		bpf_printk("Entry already present");
		return TC_ACT_OK;
	}
	bpf_printk("New Entry: %pI4", &iph->saddr);
    if(pkt_size<=12) {
		entry.label = 1;
	}
	else if(pkt_size<=4 || (pkt_size>=5 && pkt_size<=7)){
		entry.label = 1;
	}
	else {
		entry.label = 0;
	}
	entry.start_time = curr_time;
	entry.end_time = bpf_ktime_get_ns();
	entry.src_addr = src_addr;
	entry.pkt_size = pkt_size;
	entry.total_time = entry.end_time - entry.start_time;
	// entry.label = 0;
	int err = bpf_map_update_elem(&label_info, &src_addr, &entry, BPF_ANY);
	if(err<0) {
		if(err==-12) {
			bpf_printk("Memory full");
		}
		else {
			bpf_printk("Some other error, not inserted");
		}
	}
	return TC_ACT_OK;
}

char __license[] SEC("license") = "GPL";
