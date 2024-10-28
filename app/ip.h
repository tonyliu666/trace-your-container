#define AF_INET		PF_INET
#define AF_INET6	PF_INET6
#define PF_INET6	10	/* IP version 6.  */
#define PF_INET		2	/* IP protocol family.  */

struct ip6_hdr
  {
    union
      {
	struct ip6_hdrctl
	  {
	    uint32_t ip6_un1_flow;   /* 4 bits version, 8 bits TC,
					20 bits flow-ID */
	    uint16_t ip6_un1_plen;   /* payload length */
	    u8  ip6_un1_nxt;    /* next header */
	    u8  ip6_un1_hlim;   /* hop limit */
	  } ip6_un1;
	u8 ip6_un2_vfc;       /* 4 bits version, top 4 bits tclass */
      } ip6_ctlun;
    struct in6_addr ip6_src;      /* source address */
    struct in6_addr ip6_dst;      /* destination address */
  };

#define ip6_plen  ip6_ctlun.ip6_un1.ip6_un1_plen
#define __swap16gen(x)							\
    (uint16_t)(((uint16_t)(x) & 0xffU) << 8 | ((uint16_t)(x) & 0xff00U) >> 8)


// static __inline __swap16md(x)
// {
// 	return (__swap16gen(x));
// }
static __inline uint16_t __swap16md(uint16_t x) {
    return __swap16gen(x);
}

#define __swap16(x)							\
	(uint16_t)(__builtin_constant_p(x) ? __swap16gen(x) : __swap16md(x))
#define __htobe16	__swap16
#define ntohs(x)	__htobe16(x)
