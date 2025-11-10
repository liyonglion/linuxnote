#ifndef _ASM_INIT_H
#define _ASM_INIT_H
/*
标识函数放在.text.init seciton中,这要完成初始化后，可以直接释放该内存节区
*/
#define __init __attribute__ ((__section__ (".text.init")))
#define __initdata __attribute__ ((__section__ (".data.init")))
/* For assembly routines */
#define __INIT		.section	".text.init",#alloc,#execinstr
#define __FINIT		.previous
#define __INITDATA	.section	".data.init",#alloc,#write

#endif

