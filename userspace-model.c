#define _GNU_SOURCE

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
#include <time.h>

#define MAX_ENTRIES 1024

char* filename = "label_contents.csv";

struct label_entry {
	unsigned int src_addr;
	unsigned int pkt_size;
	unsigned long long int start_time;
	unsigned long long int end_time;
	unsigned long long int total_time;
    unsigned int label;
};

static unsigned long get_nsecs(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000000UL + ts.tv_nsec;
}

struct data_t {
    unsigned int key;
    struct label_entry *value;
};

void write_label_info(struct label_entry* entry) {
    FILE *fp;
    fp = fopen(filename, "a");
    struct in_addr src_addr = {entry->src_addr};
    fprintf(fp,"%s,", inet_ntoa(src_addr));
    fprintf(fp,"%u,", entry->pkt_size);
    fprintf(fp,"%llu,", entry->start_time);
    fprintf(fp,"%llu,", entry->end_time);
    fprintf(fp,"%llu,", entry->total_time);
    fprintf(fp,"%u\n", entry->label);
	fclose(fp);
}

int main() {
    int map_fd;
    int i, ret;
    unsigned int a;
    void* next_key = &a;

    // Open the eBPF map
    DIR *dp;
    struct dirent *ep;
    dp = opendir("/sys/fs/bpf/tc/");
    if(dp == NULL) {
        printf("/sys/fs/bpf/tc/ directory does not exist\n");
        return -1;
    }
    // printf("Dir opened\n");
    while((ep = readdir(dp))!=NULL) {
        // printf("Am here with str %s\n", ep->d_name);
        if(strcmp(ep->d_name, "globals")==0 || strcmp(ep->d_name, ".")==0 || strcmp(ep->d_name, "..")==0) {
            // printf("Entered\n");
            continue;
        }
        else
            break;
    }
    printf("Label Reader working\nGot random directory %s\n", ep->d_name);
    char map_loc[256];
    int l1=0, l2=0, l3=0, l4=0;
    char str1[] = "/sys/fs/bpf/tc/";
    char str2[] = "/label_info";
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
    // printf("Full %s\n", map_loc);  
    
    printf("Map opened\n");
	map_fd = bpf_obj_get(map_loc);
	if (map_fd < 0) {
		perror("Failed to open map");
		return 1;
	}

    // Check if file exists, if not, initialise with column names
    // if(access(filename, F_OK)) {
    //     FILE *fp;
    //     fp = fopen(filename, "a");
    //     fprintf(fp,"src_addr,");
    //     fprintf(fp,"pkt_size,");
    //     fprintf(fp,"start time,");
    //     fprintf(fp,"end time,");
    //     fprintf(fp,"total time,");
    //     fprintf(fp,"label\n");
    //     fclose(fp);
    // }

    // Read data from the map
	while(true) {
    	// map_fd = bpf_obj_get(map_loc);
    	// if (map_fd < 0) {
        // 	perror("Failed to open map");
        // 	return 1;
    	// }
		void* prev_key = NULL;
		while(bpf_map_get_next_key(map_fd, prev_key, next_key)==0) {
			// printf("Continuing\n");
			unsigned int curr_key = *(unsigned int *)next_key;
			struct label_entry entry = {};
			struct in_addr ip_addr = {curr_key};
			ret = bpf_map_lookup_elem(map_fd, &curr_key, &entry);
			if(ret < 0) {
				perror("Failed to lookup map");
				close(map_fd);
				return 1;
			}
			if(entry.label!=0) {
				prev_key = next_key;
				continue;
			}
			printf("Updating key value %s\n", inet_ntoa(ip_addr));
			if(entry.pkt_size<=12) {
				entry.label = 1;
			}
			else if(entry.pkt_size<=4 || (entry.pkt_size>=5 && entry.pkt_size<=7)){
				entry.label = 1;
			}
			else {
				entry.label = 2;
			}
			unsigned long long now = get_nsecs();
			entry.end_time = now;
			entry.total_time = entry.end_time - entry.start_time;
			int err = bpf_map_update_elem(map_fd, &curr_key, &entry, BPF_ANY);
			if(err<0) {
				if(err==-12) {
					printf("Memory full\n");
				}
				else {
					printf("Some other error, not inserted\n");
				}
			}
			prev_key = next_key;
		}
	}
	// Print data from the map
	// Close the map
	// close(map_fd);
    return 0;
}
