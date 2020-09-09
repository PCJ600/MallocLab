/*
 * mm-naive.c - The fastest, least memory-efficient malloc package.
 * 
 * In this naive approach, a block is allocated by simply incrementing
 * the brk pointer.  A block is pure payload. There are no headers or
 * footers.  Blocks are never coalesced or reused. Realloc is
 * implemented directly using mm_malloc and mm_free.
 *
 * NOTE TO STUDENTS: Replace this header comment with your own header
 * comment that gives a high level description of your solution.
 */
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>
#include "stdarg.h"

#include "mm.h"
#include "memlib.h"

/*********************************************************
 * NOTE TO STUDENTS: Before you do anything else, please
 * provide your team information in the following struct.
 ********************************************************/
team_t team = {
    /* Team name */
    "ateam",
    /* First member's full name */
    "Harry Bovik",
    /* First member's email address */
    "bovik@cs.cmu.edu",
    /* Second member's full name (leave blank if none) */
    "",
    /* Second member's email address (leave blank if none) */
    ""
};

/* single word (4) or double word (8) alignment */
#define ALIGNMENT 8

/* rounds up to the nearest multiple of ALIGNMENT */
#define ALIGN(size) (((size) + (ALIGNMENT-1)) & ~0x7)


#define SIZE_T_SIZE (ALIGN(sizeof(size_t)))

// 隐式空闲链表法, 定义如下宏
#define WSIZE 4
#define DSIZE 8
#define CHUNKSIZE (1 << 12)                                             // 4KB, extend_heap扩展堆的最小单位

#define MAX(x, y) ((x) > (y) ? (x) : (y))

#define PACK(size, alloc)    ((size) | (alloc))                         // 标识块分配位, 低3位为标识信息，其中最低位标识块是否分配; 高29位标识块大小

#define GET(p) (*(unsigned int *)p)
#define PUT(p, val) (*(unsigned int *)(p) = (val))

#define GET_SIZE(p) (GET(p) & ~0x7)
#define GET_ALLOC(p) (GET(p) & 0x1)

#define HDRP(bp) ((char *)(bp) - WSIZE)                                 // bp内存块的头部地址
#define FTRP(bp) ((char *)(bp) + GET_SIZE(HDRP(bp)) - DSIZE)            // bp内存块的脚部地址

#define NEXT_BLKP(bp) ((char *)(bp) + GET_SIZE((HDRP(bp))))               // 下个内存块的地址
#define PREV_BLKP(bp) ((char *)(bp) - GET_SIZE(((char *)(bp) - DSIZE)))   // 上个内存块的地址

static char *heap_listp;        // 总是指向序言块的下一个块，序言块和结尾块作为消除合并时边界的技巧
static char *pre_listp;        

/*
 * coalesce - 合并空闲块, 分四种情况
 *
 */
static void *coalesce(void *p)
{
    // printf("p: %p, heap: %p, prev: %p, hdrp: %p\n", p, heap_listp, PREV_BLKP(p), HDRP(p));

    int prev_flag = GET_ALLOC(FTRP(PREV_BLKP(p)));
    int next_flag = GET_ALLOC(HDRP(NEXT_BLKP(p)));
    int size = GET_SIZE(HDRP(p));

    // 前后两个块都已分配, 不能合并
    if (prev_flag && next_flag) { 
        ;
    } else if (prev_flag && !next_flag) {
        size += GET_SIZE(HDRP(NEXT_BLKP(p)));
        PUT(HDRP(p), PACK(size, 0));
        PUT(FTRP(p), PACK(size, 0));

    } else if (!prev_flag && next_flag) {
        size += GET_SIZE(HDRP(PREV_BLKP(p)));
        PUT(FTRP(p), PACK(size, 0));
        PUT(HDRP(PREV_BLKP(p)), PACK(size, 0));
        p = PREV_BLKP(p);
    } else {
        size += GET_SIZE(HDRP(PREV_BLKP(p))) + GET_SIZE(FTRP(NEXT_BLKP(p)));
        PUT(HDRP(PREV_BLKP(p)), PACK(size, 0));
        PUT(FTRP(NEXT_BLKP(p)), PACK(size, 0));
        p = PREV_BLKP(p);
    }
    return p;
}


/*
 * extend_heap - 用一个新空闲块扩展堆, 出错返回NULL
 * 调用sbrk申请堆空间
 * 设置新空闲块的头部和脚部, 结尾留一个结束块头部0/1
 */
static void *extend_heap(size_t words)
{
    size_t size = (words % 2) ? ((words + 1) * WSIZE) : (words * WSIZE);
    void *p;
    if ((p = mem_sbrk(size)) == (void *)-1) {
        return NULL;
    }
    
    PUT(HDRP(p), PACK(size, 0));             // 设新空闲块头部,取代旧的结尾块头部
    PUT(FTRP(p), PACK(size, 0));             // 设新空闲块脚部
    PUT(HDRP(NEXT_BLKP(p)), PACK(0, 1));     // 设新的结尾块头部

    return coalesce(p);
}


/* 
 * mm_init - initialize the malloc package.
 * 创建一个空的空闲链表，
 * | 非填充字节 | 序言块头部(8/1) | 序言块脚部(8/1) | 结尾块(0/1) | 共4 + 8 + 4 = 16字节
 */
int mm_init(void)
{
    if ((heap_listp = mem_sbrk(4 * WSIZE)) == (void *)-1) {
        return -1;
    }

    PUT(heap_listp, 0);
    PUT(heap_listp + WSIZE, PACK(DSIZE, 1));
    PUT(heap_listp + (2 * WSIZE), PACK(DSIZE, 1));
    PUT(heap_listp + (3 * WSIZE), PACK(0, 1));
    heap_listp += (2 * WSIZE);     // 指向序言块的下一个块
    pre_listp = heap_listp;

    if (extend_heap(CHUNKSIZE / WSIZE) == NULL) {
        return -1;
    }
    return 0;
}


/*
 *  打印链表，用于调试诊断
 */
static void print_list(char *fmt, ...)
{
#if 0
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    fflush(stdout);

    printf("===============print list begin===================\n");
    for (void *ptr = heap_listp; GET_SIZE(HDRP(ptr)) > 0; ptr = NEXT_BLKP(ptr)) {
        printf("ptr: %p, SIZE: %d, ALLOC: %d\n", ptr, GET_SIZE(HDRP(ptr)), GET_ALLOC(HDRP(ptr)));
    }
    printf("===============print list end===================\n");
#endif
}

/*
 * 适配算法，采用首次适配
 */
static void *first_fit(int asize)
{
    // 结尾块大小位0, 分配位为1, 表示已经结束
    for (void *ptr = heap_listp; GET_SIZE(HDRP(ptr)) > 0; ptr = NEXT_BLKP(ptr)) {
        if (!GET_ALLOC(HDRP(ptr)) && asize <= GET_SIZE(HDRP(ptr))) {
            return ptr;
        }
    }
    return NULL;
}


static void *fit(int asize)
{
    return first_fit(asize);
}


/* 
 * 将请求块放在空闲块的位置, 只有剩余部分超出最小块的大小时才进行分割
 * 最小块大小为4 + 4 + 8 = 16字节
 */
static void place(void *p, size_t asize)
{
    int osize = GET_SIZE(HDRP(p));
    if (osize - asize < 2 * DSIZE) {
        PUT(HDRP(p), PACK(osize, 1));
        PUT(FTRP(p), PACK(osize, 1));
        return;
    }

    PUT(HDRP(p), PACK(asize, 1));
    PUT(FTRP(p), PACK(asize, 1));
    p = NEXT_BLKP(p);
    PUT(HDRP(p), PACK(osize - asize, 0));
    PUT(FTRP(p), PACK(osize - asize, 0));
}


/* 
 * mm_malloc - Allocate a block by incrementing the brk pointer.
 *     Always allocate a block whose size is a multiple of the alignment.
 *
 *
 *
 *
 */
void *mm_malloc(size_t size)
{
    if (size == 0) {                // 拒绝这种邪恶的需求
        return NULL;
    }

    int asize;
    if (size <= DSIZE) {
        asize = 2 * DSIZE;
    } else {
        asize = DSIZE * ((size + (DSIZE) + (DSIZE-1)) / DSIZE);
    }

    void *p;
    if ((p = fit(asize)) != NULL) {
        place(p, asize);
        return p;
    }

    if ((p = extend_heap(MAX(CHUNKSIZE, asize) / WSIZE)) == NULL) {
        return NULL;
    }
    place(p, asize);
    return p;
}

/*
 * mm_free - Freeing a block does nothing.
 */
void mm_free(void *ptr)
{
    print_list("mm_free ptr: %p\n", ptr);

    // 头部和脚部分配位清0, 并尽可能合并空闲块
    int size = GET_SIZE(HDRP(ptr));
    PUT(HDRP(ptr), PACK(size, 0));
    PUT(FTRP(ptr), PACK(size, 0));
    coalesce(ptr);
}

/*
 * mm_realloc - Implemented simply in terms of mm_malloc and mm_free
 */
void *mm_realloc(void *ptr, size_t size)
{
    void *oldptr = ptr;
    void *newptr;
    size_t copySize;
    
    newptr = mm_malloc(size);
    if (newptr == NULL)
      return NULL;
    copySize = *(size_t *)((char *)oldptr - SIZE_T_SIZE);
    if (size < copySize)
      copySize = size;
    memcpy(newptr, oldptr, copySize);
    mm_free(oldptr);
    return newptr;
}

