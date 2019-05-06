#include <nfp/mem_atomic.h>

#include <pif_plugin.h>

//#include <pkt_ops.h>

#include <pif_headers.h>

#include <nfp_override.h>

#include <pif_common.h>

#include <std/hash.h>

#include <nfp/me.h>


#define BUCKET_SIZE 12


#define STATE_TABLE_SIZE 0xF /* 16777200 state table entries available */



typedef struct bucket_entry_info {

    uint32_t hit_count; /* for timeouts */

} bucket_entry_info;



typedef struct bucket_entry {

    uint32_t key[3]; /* ip1, ip2, ports */
    uint32_t test;

    bucket_entry_info bucket_entry_info_value;

}bucket_entry;





typedef struct bucket_list {

    // uint32_t ctl;

    struct bucket_entry entry[BUCKET_SIZE];

}bucket_list;



__shared __export __addr40 __emem bucket_list state_hashtable[STATE_TABLE_SIZE + 1];
__shared __export __addr40 __emem uint32_t update_function_check;

int pif_plugin_state_update(EXTRACTED_HEADERS_T *headers,

                        MATCH_DATA_T *match_data)

{


    
    PIF_PLUGIN_ipv4_T *ipv4;

    PIF_PLUGIN_udp_T *udp;

    volatile uint32_t update_hash_value;

    uint32_t update_hash_key[3];


    __addr40 __emem bucket_entry_info *b_info;

    __xwrite bucket_entry_info tmp_b_info;

    __addr40 uint32_t *key_addr;

    __xrw uint32_t key_val_rw[3];



    uint32_t i = 0;

    

    ipv4 = pif_plugin_hdr_get_ipv4(headers);

    udp = pif_plugin_hdr_get_udp(headers);



    /* TODO: Add another field to indicate direction ?*/

    update_hash_key[0] = ipv4->srcAddr;

    update_hash_key[1] = ipv4->dstAddr;

    update_hash_key[2] = (udp->srcPort << 16) | udp->dstPort;



    key_val_rw[0] = ipv4->srcAddr;

    key_val_rw[1] = ipv4->dstAddr;

    key_val_rw[2] = (udp->srcPort << 16) | udp->dstPort;



    update_hash_value = hash_me_crc32((void *)update_hash_key,sizeof(update_hash_key), 1);

    update_hash_value &= (STATE_TABLE_SIZE);



    for (;i<BUCKET_SIZE;i++) {

        if (state_hashtable[update_hash_value].entry[i].key[0] == 0) {

            b_info = &state_hashtable[update_hash_value].entry[i].bucket_entry_info_value;

            key_addr =(__addr40 uint32_t *) state_hashtable[update_hash_value].entry[i].key;

            break;

        }

    }

    /* If bucket full, drop */

    if (i == BUCKET_SIZE)
	return PIF_PLUGIN_RETURN_FORWARD;


    tmp_b_info.hit_count = 1;



    mem_write_atomic(&tmp_b_info, b_info, sizeof(tmp_b_info));

    mem_write_atomic(key_val_rw,(__addr40 void *)key_addr, sizeof(key_val_rw));
//    mem_write_atomic(&i,&state_hashtable[update_hash_value].entry[i].test, sizeof(i));
    mem_incr32(&update_function_check);

   

    return PIF_PLUGIN_RETURN_FORWARD;

}


int pif_plugin_lookup_state(EXTRACTED_HEADERS_T *headers, MATCH_DATA_T *match_data) {



    PIF_PLUGIN_ipv4_T *ipv4;

    PIF_PLUGIN_udp_T *udp;

    volatile uint32_t hash_value;

    uint32_t  hash_key[3];

    __xread uint32_t hash_key_r[3];

    __addr40 bucket_entry_info *b_info;



    uint32_t i;
    uint32_t hash_entry_full; 
    uint32_t flow_entry_found; 


    ipv4 = pif_plugin_hdr_get_ipv4(headers);

    udp = pif_plugin_hdr_get_udp(headers);



    /* TODO: Add another field to indicate direction ?*/

    hash_key[0] = ipv4->srcAddr;

    hash_key[1] = ipv4->dstAddr;

    hash_key[2] = (udp->srcPort << 16) | udp->dstPort;



    //TODO: Change to toeplitz hash:

    //hash_value = hash_toeplitz(&hash_key,sizeof(hash_key),);

    //hash_value = hash_me_crc32((void *)hash_key,sizeof(hash_key), 10);

    hash_value = hash_me_crc32((void *) hash_key,sizeof(hash_key), 1);

    hash_value &= (STATE_TABLE_SIZE);   

    hash_entry_full = 1;
    flow_entry_found= 0;

    for (i = 0; i < BUCKET_SIZE; i++) {

        mem_read_atomic(hash_key_r, state_hashtable[hash_value].entry[i].key, sizeof(hash_key_r)); /* TODO: Read whole bunch at a time */



        if (hash_key_r[0] == 0) {
	    hash_entry_full = 0;
            continue;

        }

        

        if (hash_key_r[0] == hash_key[0] &&

            hash_key_r[1] == hash_key[1] &&

            hash_key_r[2] == hash_key[2] ) { /* Hit */


            __xrw uint32_t count;

	    flow_entry_found = 1;

            b_info = (__addr40 bucket_entry_info *)&state_hashtable[hash_value].entry[i].bucket_entry_info_value;

            
            count = 1;

            mem_test_add(&count,(__addr40 void *)&b_info->hit_count, 1 << 2);

            if (count == 0xFFFFFFFF-1) { /* Never incr to 0 or 2^32 */

                count = 2;

                mem_add32(&count,(__addr40 void *)&b_info->hit_count, 1 << 2);

            } else if (count == 0xFFFFFFFF) {

                mem_incr32((__addr40 void *)&b_info->hit_count);

            }


//            return PIF_PLUGIN_RETURN_FORWARD;

        }

    }

    if(hash_entry_full == 1 || flow_entry_found == 1){
	return PIF_PLUGIN_RETURN_FORWARD;   
    }


  if (pif_plugin_state_update(headers, match_data) == PIF_PLUGIN_RETURN_DROP) {

        return PIF_PLUGIN_RETURN_DROP;

    }


    return PIF_PLUGIN_RETURN_FORWARD;

}

