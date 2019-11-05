
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <string>
#include <iostream>
#include <string.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

using namespace std;

struct ip{
	unsigned char header_length:4;
	unsigned char version:4;
	unsigned char service_field;
	unsigned short total_length;
	unsigned short identification;
	unsigned short flag;
	unsigned char ttl; //time to live
	unsigned char protocol; //tcp is 0x06
	
};

struct tcp{
	unsigned short src_port;
	unsigned short dst_port;
	unsigned int sequence_number;
	unsigned int acknowledgement_number;
	unsigned char a:1;
	unsigned char b:3;
	unsigned tcp_length:4;
	unsigned char data;
	unsigned short window_size;
	unsigned short checksum;
	unsigned short urgent_pointer;
};
/*static variable*/
bool check_flag=false;
char *host;
int host_size;

bool isTriggerRule(unsigned char *buf,int size){
	int i;
	for(int i=0;i<size;i++){
		if(i%16==0)
			printf("\n");
		printf("%02x ",buf[i]);
	}
	printf("\n");
	/*check ip data*/
	struct ip *ip;
	ip = (struct ip*)buf;
	if(ip->protocol != 0x06){
		printf("packet is not tcp\n");
		return false;
	}
	int ip_header_length = (int)ip->header_length*(int)ip->version;
	buf +=ip_header_length;
	
	/*check tcp data*/	
	struct tcp *tcp;
	tcp = (struct tcp*)buf;
	int tcp_payload_size = size-ip_header_length-(int)tcp->tcp_length*4;
	if(tcp_payload_size==0){
		printf("there is no http data\n");
		return false;
	}
	/*check http method*/
	buf+=(int)tcp->tcp_length*4;

	string s((char*)buf,tcp_payload_size);
	cout<<s<<endl;

	if(buf[0]=='G'||buf[0]=='P'||buf[0]=='D'||buf[0]=='H'||buf[0]=='O'){
		/*check host name*/
		int n1 = s.find("Host");
		if(n1){
			string dst_host = s.substr(n1+6,host_size);
			for(int i=0;i<host_size;i++){
				if(host[i]!=dst_host[i]){
					printf("THe host name is didnt caught at my filter");
					return false;
				}
	
			}
		}
		printf("the packet caught at my filter\n");
		return true;
	}
	printf("the packet doesnt have any http method");
	return false;
}

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark,ifi; 
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen-1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen-1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);

	ret = nfq_get_payload(tb, &data);
	if (ret >= 0)
		printf("payload_len=%d ", ret);
	
	/*print packet*/
	check_flag= isTriggerRule(data,ret);

	fputc('\n', stdout);

	return id;
}
	

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	      struct nfq_data *nfa, void *data)
{
	u_int32_t id = print_pkt(nfa);
	printf("entering callback\n");
	if(!check_flag){
		printf("pass!\n");
		printf("-----------------------------\n");
		return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
	}else{
		printf("drop!\n");
		printf("-----------------------------\n");
		check_flag = false;
		return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);// drop packet
	}
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));
	if(argc!=2){
		printf("usage: netfilter_block <host>\n");
		return -1;
	}else{
		host = argv[1];
		host_size = strlen(argv[1]);
	}
	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		 * are sent from kernel-space, the socket buffer that we use
		 * to enqueue packets may fill up returning ENOBUFS. Depending
		 * on your application, this error may be ignored. Please, see
		 * the doxygen documentation of this library on how to improve
		 * this situation.
		 */
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}
