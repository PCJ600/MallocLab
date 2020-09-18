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

#define MAX(x, y) ((x) > (y) ? (x) : (y))

// 定义操作显示空闲链表的常数和宏
#define WSIZE 4                                     // 头部、脚部大小: 4字节
#define DSIZE (2 * WSIZE)                           // 双字: 8字节
#define CHUNKSIZE (1 << 12)                         // 4096字节, 执行extend_heap一次, 堆上扩展的大小
#define PACK(size, alloc)  ((size) | (alloc))

// 32位数据读写
#define GET(p)             (*(unsigned int *)(p))               
#define PUT(p, val)        (*(unsigned int *)(p) = (val))       
#define GET_SIZE(p)        (GET(p) & ~0x7)       // 获取块大小, 这里块大小不会超过2^32字节
#define GET_ALLOC(p)       (GET(p) & 0x1)        // 判断这个块是否已分配              

// 指针类型读写，使用intptr_t保证不同机器字长(32位、64位)之间的通用性
#define GET_P(p)           (*(intptr_t *)(p))                          
#define PUT_P(p, val)      (*(intptr_t *)(p) = (intptr_t)(val)) 

// 显式空闲链表法初始形式: | free list指针数组(20*8字节) | 对齐块(4字节) | 序言块头部+脚部(8字节) | 结尾块(4字节) |
// 空闲块: | 头部(4字节) | prev指针(8字节) | next指针(8字节) | payload | 脚部(4字节) |
// 已分配块: | 头部(4字节) | payload | 脚部(4字节) |
// 以上可以看出，初始对齐块4字节的目的，在于访问空闲块prev, next时只需一次访问
// 分离链表: |(16-31)|(32-63)|(64-127)|(128-255)| ..... |(2^23,2^24-1)|
#define MAX_LIST_NUM 20                             // 分离链表最大数
#define MIN_INDEX 4                                 // 最小块为16字节, 即2^4。这里MIN_INDEX表示分离链表中第一条链表的最小块大小

// 根据8字节对齐要求, 计算一个块最小需要的字节数:
// 32位系统，块最小为 4 + 2 * 4 + 4 = 16字节
// 64位系统, 块最小为 4 + 2 * 8 + 4 = 24字节
#define MIN_BLOCK_SIZE (DSIZE + 2 * sizeof(intptr_t)) 
#define PTR(bp)     ((char *)(bp))

#define HDRP(bp)    ((char *)(bp) - WSIZE)
#define FTRP(bp)    ((char *)(bp) + GET_SIZE(HDRP(bp)) - DSIZE)

#define NEXT_BLKP(bp) ((char *)(bp) + GET_SIZE(((char *)(bp) - WSIZE)))
#define PREV_BLKP(bp) ((char *)(bp) - GET_SIZE(((char *)(bp) - DSIZE)))

// 显示空闲链表法, 表示前驱和后继指针
#define PREV(bp)    ((char *)(bp))
#define SUCC(bp)    ((char *)(bp) + DSIZE) 

// 获取前驱或后继指针的内容, 转化为指针
#define GET_PREV(bp) ((char *)(GET_P(PREV(bp))))
#define GET_SUCC(bp) ((char *)(GET_P(SUCC(bp))))


static void print_list(int i)
{
    int print_flag = 0;
    int size;
    char *p = mem_heap_lo() + i * sizeof(intptr_t);
    p = PTR(GET_P(p));
    while (p != NULL) {
        print_flag = 1;
        printf("(%p, %d) -> ", p, GET_SIZE(HDRP(p)));
        p = GET_SUCC(p);
    }

    if (print_flag) {
        printf("end\n");
    }
}

static int mm_check(char *func)
{
    printf("func: %s\n=============free list============\n", func);
    for (int i = 0; i < MAX_LIST_NUM; ++i) {
        print_list(i);
    }
    return 1;
}

static void insert_node(void *p, size_t size)
{
    /*
    int list_size;
    for (int i = 0; i < MAX_LIST_NUM; ++i) {
        list_size = (1 << (MIN_INDEX + i));
        if (size > list_size) {
            continue;
        }
    
        



    }
    */

    return;
}

static void delete_node(void *p)
{
    return;
}

static void *coalesce(void *p)
{
    return p;
}


// 根据8字节对齐要求, 计算一个块最小需要的字节数:
// 32位系统，块最小为 4 + 2 * 4 + 4 = 16字节
// 64位系统, 块最小为 4 + 2 * 8 + 4 = 24字节
static void *place(void *p, size_t size)
{
    int max_size = GET_SIZE(HDRP(p));
    int delta_size = max_size - size;

    delete_node(p);     
    
    // 如剩余大小少于最小块大小, 不做分割
    if (delta_size < MIN_BLOCK_SIZE) {
        PUT(HDRP(p), PACK(max_size, 1));
        PUT(FTRP(p), PACK(max_size, 1));
        return p;
    } 

    // 否则需要分割，并将分割后的空闲块加到空闲链表
    PUT(HDRP(p), PACK(size, 1));
    PUT(FTRP(p), PACK(max_size, 1));
    PUT(HDRP(NEXT_BLKP(p)), PACK(delta_size, 0));
    PUT(HDRP(NEXT_BLKP(p)), PACK(delta_size, 0));
    insert_node(NEXT_BLKP(p), delta_size);

    return p;
}



// 向8字节对齐
static void *extend_heap(size_t size)
{
    size = ALIGN(size);
    void *p;
    if ((p = mem_sbrk(size)) == (void *)-1) {
        printf("extend_heap failed! mem_sbrk return -1!\n");
        return NULL;
    }

    PUT(HDRP(p), PACK(size, 0));
    PUT(FTRP(p), PACK(size, 0));
    PUT(HDRP(NEXT_BLKP(p)), PACK(0, 1));
    insert_node(p, size);
    return coalesce(p);
}

/* 
 * mm_init - initialize the malloc package.
 */
int mm_init(void)
{
    // 8字节对齐块 + MAX_LIST_NUM * DSIZE字节的空闲链表头指针 + 2个4字节序言块 + 4字节结尾块
    char *p = mem_sbrk(MAX_LIST_NUM * sizeof(intptr_t) + 4 * WSIZE);
    if ((void *)p == (void *)(-1)) {
        return -1;
    }

    // 空闲链表头指针，64为环境指针大小为8字节, 初始链表为空, 置为NULL
    for (int i = 0; i < MAX_LIST_NUM; ++i) {
        PUT_P(p + i * sizeof(intptr_t), NULL);
    }
    p += MAX_LIST_NUM * DSIZE;

    // 4字节对齐块，填0; 设置两个4字节序言块和1个结尾块
    // 对齐目的是为了加快访问8字节指针的速度
    PUT(p + WSIZE, PACK(DSIZE, 1));
    PUT(p + 2 * WSIZE, PACK(DSIZE, 1));
    PUT(p + 3 * WSIZE, PACK(0, 1));

    if ((p = extend_heap(CHUNKSIZE)) == NULL) {
        return -1;
    }
    return 0;
}

/* 
 * mm_malloc - Allocate a block by incrementing the brk pointer.
 *     Always allocate a block whose size is a multiple of the alignment.
 */

// helper func, 从空闲链表寻找合适的空闲块
static void *find_free_block_from_lists(size_t size)
{
    return NULL;
}


void *mm_malloc(size_t size)
{
    mm_check("mm_malloc");
    size = (size < MIN_BLOCK_SIZE) ? MIN_BLOCK_SIZE: ALIGN(MIN_BLOCK_SIZE + DSIZE);

    // 首先，寻找空闲链表是否有合适的空闲块。如果没找到合适的空闲块, 需要扩展堆
    void *p = find_free_block_from_lists(size);
    if (p == NULL) {
        if ((p = extend_heap(MAX(size, CHUNKSIZE))) == NULL) {
            printf("mm_malloc, extend_heap failed!\n");
            return NULL;
        }
    }

    p = place(p, size);
    return p;
}

/*
 * mm_free - Freeing a block does nothing.
 */
void mm_free(void *ptr)
{
    mm_check("mm_free");
    int size = GET_SIZE(HDRP(ptr));
    PUT(HDRP(ptr), PACK(size, 0));
    PUT(FTRP(ptr), PACK(size, 0));

    // 注意将释放后的空闲块重新插入到分离链表中
    insert_node(ptr, size);
    
    coalesce(ptr);
}

/*
 * mm_realloc - Implemented simply in terms of mm_malloc and mm_free
 */
void *mm_realloc(void *ptr, size_t size)
{
    mm_check("mm_realloc");
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














