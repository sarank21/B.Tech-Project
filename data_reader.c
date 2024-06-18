#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
// #include <sys/bpf/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <arpa/inet.h>
#include <dirent.h>

#define MAX_ENTRIES 1024

char* filename = "data.csv";

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

struct data_t {
    unsigned int key;
    struct PUC_entry *value;
};

void write_PUC_info(struct PUC_entry* entry) {
    FILE *fp;
    fp = fopen(filename, "a");
    struct in_addr src_addr = {entry->src_addr};
    fprintf(fp,"%s,", inet_ntoa(src_addr));
    struct in_addr dest_addr = {entry->dest_addr};
    fprintf(fp,"%s,", inet_ntoa(dest_addr));
    fprintf(fp,"%u,", entry->max_pkt_size);
    fprintf(fp,"%u,", entry->min_pkt_size);
    fprintf(fp,"%u,", entry->sec_max_pkt_size);
    fprintf(fp,"%llu,", entry->max_iat);
    fprintf(fp,"%llu,", entry->latest_time);
    fprintf(fp,"%u,", entry->ip_version);
    fprintf(fp,"%u,", entry->rx_count);
    // fprintf(fp,"%u,", entry->tx_count);
    // fprintf(fp,"%u,", entry->tcp_count);
    // fprintf(fp,"%u,", entry->udp_count);
    fprintf(fp,"%u,", entry->rx_bytes);
    // fprintf(fp,"%u,", entry->tx_bytes);
    fprintf(fp,"%llu,", entry->first_pkt_time);
    fprintf(fp,"%u\n", entry->flag);
    fclose(fp);
}

int main() {
    int map_fd;
    int i, ret;
    unsigned int a;
    void* next_key = &a;
    void* next_entry;

    // Open the eBPF map
    DIR *dp;
    struct dirent *ep;
    dp = opendir("/sys/fs/bpf/tc/");
    if(dp == NULL) {
        printf("/sys/fs/bpf/tc/ directory does not exist\n");
        return -1;
    }
    printf("Dir opened\n");
    while((ep = readdir(dp))!=NULL) {
        // printf("Am here with str %s\n", ep->d_name);
        if(strcmp(ep->d_name, "globals")==0 || strcmp(ep->d_name, ".")==0 || strcmp(ep->d_name, "..")==0) {
            // printf("Entered\n");
            continue;
        }
        else
            break;
    }
    printf("Exited with %s\n", ep->d_name);
    char map_loc[256];
    int l1=0, l2=0, l3=0, l4=0;
    char str1[] = "/sys/fs/bpf/tc/";
    char str2[] = "/PUC_info";
    for(int i=0 ; str1[i]!='\0' ; i++, l1++) {
        map_loc[l1]=str1[i];
    }
    for(int i=0 ; ep->d_name[i]!='\0' ; i++, l1++) {
        map_loc[l1]=ep->d_name[i];
    }
    for(int i=0 ; str2[i]!='\0' ; i++, l1++) {
        map_loc[l1]=str2[i];
    }
    map_loc[l1] = '\0';
    printf("Full %s\n", map_loc);  
    map_fd = bpf_obj_get(map_loc);
    if (map_fd < 0) {
        perror("Failed to open map");
        return 1;
    }
    printf("Map opened\n");

    // Check if file exists, if not, initialise with column names
    if(access(filename, F_OK)) {
        FILE *fp;
        fp = fopen(filename, "a");
        fprintf(fp,"src_addr,");
        fprintf(fp,"dest_addr,");
        fprintf(fp,"max_pkt_size,");
        fprintf(fp,"min_pkt_size,");
        fprintf(fp,"sec_max_pkt_size,");
        fprintf(fp,"max_iat,");
        fprintf(fp,"latest_time,");
        fprintf(fp,"ip_version,");
        fprintf(fp,"rx_count,");
        // fprintf(fp,"tx_count,");
        // fprintf(fp,"tcp_count,");
        // fprintf(fp,"udp_count,");
        fprintf(fp,"rx_bytes,");
        // fprintf(fp,"tx_bytes,");
        fprintf(fp,"first_pkt_time,");
        fprintf(fp,"flag\n");
        fclose(fp);
    }

    // Read data from the map
    void* prev_key = NULL;
    while(bpf_map_get_next_key(map_fd, prev_key, next_key)==0) {
        unsigned int curr_key = *(unsigned int *)next_key;
        struct PUC_entry entry = {};
        struct in_addr ip_addr = {curr_key};
        printf("Key value %s\n", inet_ntoa(ip_addr));
        ret = bpf_map_lookup_elem(map_fd, &curr_key, &entry);
        if(ret < 0) {
            perror("Failed to lookup map");
            close(map_fd);
            return 1;
        }
        
        // Print data from the map
        write_PUC_info(&entry);
        prev_key = next_key;
        // Close the map
        // close(map_fd);
    }

    return 0;
}
