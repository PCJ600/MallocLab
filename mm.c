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

#define TRUE 1
#define FALSE 0

/* single word (4) or double word (8) alignment */
#define ALIGNMENT (sizeof(size_t)) 

/* rounds up to the nearest multiple of ALIGNMENT */
#define ALIGN(size) (((size) + (ALIGNMENT-1)) & ~(ALIGNMENT-1))

#define SIZE_T_SIZE (ALIGN(sizeof(size_t)))

#define MAX(x, y) ((x) > (y) ? (x) : (y))

// 定义操作显示空闲链表的常数和宏
#define WSIZE 4                                     // 头部、脚部大小: 4字节
#define DSIZE 8                                     // 双字: 8字节
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
#define SUCC(bp)    ((char *)(bp) + sizeof(intptr_t)) 

// 获取前驱或后继指针的内容, 转化为指针
#define GET_PREV(bp) ((char *)(GET_P(PREV(bp))))
#define GET_SUCC(bp) ((char *)(GET_P(SUCC(bp))))

// helper func, 获取第idx个分离链表的头指针
static char *get_list_head(int idx) {
    return PTR(GET_P((char *)mem_heap_lo() + idx * sizeof(intptr_t)));
}


// ===================================================调试堆相关API开始================================
enum ERRCODE {
    OK = 0, ERR1, ERR2, ERR3, ERR4, ERR5, ERR6, ERR7, ERR8, ERR9
};

static void print_list(int i)
{
    int print_flag = 0;
    int size;
    char *p = get_list_head(i);

    while (p != NULL) {
        print_flag = 1;
        printf("(%p, %d) -> ", p, GET_SIZE(HDRP(p)));
        p = GET_SUCC(p);
    }
    if (print_flag) {
        printf("end. list [%d]\n", i);
    }
}



static enum ERRCODE check_ptr_in_heap(char *p)
{
    char *ptr = (char *)mem_heap_lo() + MAX_LIST_NUM * sizeof(intptr_t) + 2 * WSIZE;
    for( ; GET_SIZE(HDRP(ptr)) != 0; ptr = NEXT_BLKP(ptr)) {
        if(ptr != p) {
            continue;
        }
        if (GET_ALLOC(HDRP(p)) == 1) {
            return ERR6;
        }
        return OK;
    }
    return ERR7;
}


// 在分离链表中寻找指针p, 找到返回1，找不到返回0
static int find_ptr_in_free_lists(char *p)
{
    char *ptr;
    for (int i = 0; i < MAX_LIST_NUM; ++i) {
        ptr = get_list_head(i);
        while (ptr != NULL) {
            if (p == ptr) {
                return 1;
            }
            ptr = GET_SUCC(ptr);
        }
    }
    return 0;
}


// 检查堆数组
static enum ERRCODE check_heap_arr()
{
    // 检查堆
    char *ptr = (char *)mem_heap_lo() + MAX_LIST_NUM * sizeof(intptr_t);
    // 检查序言块大小和分配位
    if (GET(ptr + WSIZE) != PACK(DSIZE, 1)) {
        return ERR1;
    }
    if (GET(ptr + 2 * WSIZE) != PACK(DSIZE, 1)) {
        return ERR2;
    }

    ptr += DSIZE;
    for( ; GET_SIZE(HDRP(ptr)) != 0; ptr = NEXT_BLKP(ptr)) {
        if ((long)ptr % sizeof(intptr_t)) {     // 检查每个块是否对齐
            return ERR3;
        }
        if (GET(HDRP(ptr)) != GET(FTRP(ptr))) { // 检查头部和脚部一致性
            return ERR4;
        }
        if (ptr < (char *)mem_heap_lo() || ptr > (char *)mem_heap_hi()) {
            return ERR5;
        }
    }
    return OK;
}

// 检查分离链表
static enum ERRCODE check_free_lists()
{
    char *ptr;
    enum ERRCODE ret = OK;

    // 检查分离链表中所有空闲块是否都在堆中
    for (int i = 0; i < MAX_LIST_NUM; ++i) {
        ptr = get_list_head(i);
        while (ptr != NULL) {
            if ((ret = check_ptr_in_heap(ptr)) != OK) {
                return ret;
            }
            ptr = GET_SUCC(ptr);
        }
    }

    // 检查数组中每个空闲块是否在链表中找到, 每个已占用块是否都不在链表里
    ptr = (char *)mem_heap_lo() + MAX_LIST_NUM * sizeof(intptr_t) + 2 * WSIZE;

    for( ; GET_SIZE(HDRP(ptr)) != 0; ptr = NEXT_BLKP(ptr)) {
        int alloc = GET_ALLOC(HDRP(ptr));
        if (alloc) {
            if (find_ptr_in_free_lists(ptr)) {
                return ERR8;
            }
        } else {
            if (!find_ptr_in_free_lists(ptr)) {
                printf("ERR9: ptr: %p\n", ptr);
                return ERR9;
            }
        }
    }
    return OK;
}

// 检查堆, 正确返回OK，否则返回错误吗
static enum ERRCODE check_heap()
{
    enum ERRCODE ret = OK;
    if ((ret = check_heap_arr()) != OK) {
        return ret;
    }

    if ((ret = check_free_lists()) != OK) {
        return ret;
    }
    return OK;
}

// 打印分离链表
static void print_free_lists()
{
    printf("==============================FREE LIST BEGIN===============================\n");
    for (int i = 0; i < MAX_LIST_NUM; ++i) {
        print_list(i);
    }
    printf("==============================FREE LIST END=================================\n");

}

// 打印堆数组
static void print_heap_arr()
{
    char *head;
    char *ptr = (char *)mem_heap_lo();
    printf("=================================ARRAY BEGIN====================================\n");
    for (int i = 0; i < MAX_LIST_NUM; ++i) {
        head = PTR(GET_P(ptr + i * sizeof(intptr_t)));
        printf("|%p|", head);
    }
    printf("|\n");

    ptr += (MAX_LIST_NUM * sizeof(intptr_t)) + WSIZE + WSIZE;
    for ( ; GET_SIZE(HDRP(ptr)) != 0; ptr = NEXT_BLKP(ptr)) {
        printf("(%p, %d, %d) ->", ptr, GET_SIZE(HDRP(ptr)), GET_ALLOC(HDRP(ptr)));
    }
    printf("end\n");
    printf("===============================ARRAY END====================================\n\n");
}


static void mm_print(char *func)
{
    printf("\n\n===FUNC: %s\n", func);
    print_free_lists();
    print_heap_arr();
}

// 每次调用mm_init, mm_malloc, mm_free, mm_realloc后，使用mm_check检查堆区是否错误
static int mm_check(char *func)
{
    /*
    mm_print(func);
    enum ERRCODE errCode;
    if ((errCode = check_heap()) != OK) {
        printf("*********************************check_heap failed! errCode: %d***************************************\n", errCode);
        exit(1);
    }*/
    return 1;
}
// ======================================================调试堆相关API结束================================


// 辅助函数: 在第i条分离链表上插入节点
static void insert_node_by_list_index(void *p, size_t size, int idx)
{
    // 首先考虑链表为空场景，只需添加该节点即可
    char *listp = (char *)mem_heap_lo() + idx * sizeof(intptr_t);
    char *cur = PTR(GET_P(listp));
    char *pre = NULL;

    if (cur == NULL) {
        PUT_P(listp, p);
        PUT_P(PREV(p), NULL);
        PUT_P(SUCC(p), NULL);
        return;
    }

    while (cur != NULL) {
        if (size > GET_SIZE(HDRP(cur))) {
            pre = cur;
            cur = GET_SUCC(cur);
            continue;
        }
        break;   
    }
    
    // cur等于NULL, 只能将节点插入链表末尾
    if (cur == NULL) {
        PUT_P(SUCC(pre), p);
        PUT_P(PREV(p), pre);
        PUT_P(SUCC(p), NULL);
        return;
    }

    // cur等于head, 在链表最开头插入
    if (pre == NULL) {
        PUT_P(listp, p);
        PUT_P(PREV(p), NULL);
        PUT_P(SUCC(p), cur);
        PUT_P(PREV(cur), p);       
        return;
    }
    
    // 在链表中间插入
    PUT_P(SUCC(pre), p);
    PUT_P(PREV(p), pre);
    PUT_P(SUCC(p), cur);
    PUT_P(PREV(cur), p);
}

// 功能：将空闲块插入空闲链表
// 1. 需要根据块大小，选择合适的链表插入空闲块
// 2. 按照从小到大的顺序插入空闲块
static void insert_node(void *p, size_t size)
{
    int list_size;
    for (int i = 0; i < MAX_LIST_NUM; ++i) {
        list_size = (1 << (MIN_INDEX + i));
        if (size > list_size) {
            continue;
        }
        insert_node_by_list_index(p, size, i);
        // printf("insert_node success: %p, size: %d\n", p, size);
        return;
    }
}

// 辅助函数, 删除第i条分离链表上的指定节点p, 成功返回TRUE, 失败返回FALSE
static int delete_node_by_list_index(void *p, int size, int idx)
{
    char *listp = (char *)mem_heap_lo() + idx * sizeof(intptr_t);
    char *cur = PTR(GET_P(listp));
    char *pre = NULL;

    while ((cur != NULL) && (cur != PTR(p))) {
        pre = cur;
        cur = GET_SUCC(cur);   
    }
    // 链表为空，直接返回FALSE
    if (cur == NULL) {
        return FALSE;
    }

    // 链表只有1个节点
    if (GET_SUCC(cur) == NULL && GET_PREV(cur) == NULL) {
        PUT_P(listp, NULL);
        return TRUE;
    }

    // 删除的节点在链表头部
    if (pre == NULL) {
        PUT_P(listp, GET_SUCC(cur));
        PUT_P(GET_SUCC(cur), NULL);
        return TRUE;
    }

    // 删除的节点在链表结尾
    if (GET_SUCC(cur) == NULL) {
        PUT_P(SUCC(pre), NULL);
        return TRUE;
    }

    // 删除的节点在链表中间

    PUT_P(SUCC(pre), GET_SUCC(cur));
    PUT_P(GET_SUCC(cur), GET_PREV(cur));
    return TRUE;
}


// 功能：将p从分离链表中删除
static void delete_node(void *p)
{
    int i;
    int list_size;
    int size = GET_SIZE(HDRP(p));

    for (i = 0; i < MAX_LIST_NUM; ++i) {
        list_size = (1 << (MIN_INDEX + i));
        if (size <= list_size) {
            break;
        }
    }

    for ( ; i < MAX_LIST_NUM; ++i) {
        if (delete_node_by_list_index(p, size, i)) {
            // printf("delete_node success: %p, %d: size, listid: %d\n", p, size, i);
            return;
        }
    }
}

// 合并, 分四种场景，详细见CSAPP原书
static void *coalesce(void *p)
{
    int prev_alloc = GET_ALLOC(HDRP(PREV_BLKP(p)));  
    int next_alloc = GET_ALLOC(HDRP(NEXT_BLKP(p)));
    int size = GET_SIZE(HDRP(p));

    if (prev_alloc && next_alloc) {             // 前后块均已分配，不可合并
        return p;
    }

    if (prev_alloc && !next_alloc) {
        delete_node(p);
        delete_node(NEXT_BLKP(p));
        size += GET_SIZE(HDRP(NEXT_BLKP(p)));
        PUT(HDRP(p), PACK(size, 0));
        PUT(FTRP(p), PACK(size, 0));
    } else if (!prev_alloc && next_alloc) {
        delete_node(PREV_BLKP(p));
        delete_node(p);
        size += GET_SIZE(HDRP(PREV_BLKP(p)));
        PUT(FTRP(p), PACK(size, 0));
        PUT(HDRP(PREV_BLKP(p)), PACK(size, 0));
        p = PREV_BLKP(p);
    } else {                                     // 前后两个块都空闲，一次性合并三个块
        delete_node(PREV_BLKP(p));
        delete_node(p);
        delete_node(NEXT_BLKP(p));
        size += GET_SIZE(HDRP(PREV_BLKP(p))) + GET_SIZE(HDRP(NEXT_BLKP(p)));
        PUT(FTRP(NEXT_BLKP(p)), PACK(size, 0));
        PUT(HDRP(PREV_BLKP(p)), PACK(size, 0));
        p = PREV_BLKP(p);
    }

    insert_node(p, size);
    
    return p;
}


// 根据字节对齐要求, 计算一个块最小需要的字节数:
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
    PUT(FTRP(p), PACK(size, 1));
    PUT(HDRP(NEXT_BLKP(p)), PACK(delta_size, 0));
    PUT(FTRP(NEXT_BLKP(p)), PACK(delta_size, 0));
    insert_node(NEXT_BLKP(p), delta_size);

    return p;
}


// 扩展堆
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
    p += MAX_LIST_NUM * sizeof(intptr_t);

    // 4字节对齐块，填0; 设置两个4字节序言块和1个结尾块
    // 对齐目的是为了加快访问8字节指针的速度
    PUT(p, 0);
    PUT(p + WSIZE, PACK(DSIZE, 1));
    PUT(p + 2 * WSIZE, PACK(DSIZE, 1));
    PUT(p + 3 * WSIZE, PACK(0, 1));

    if ((p = extend_heap(CHUNKSIZE)) == NULL) {
        return -1;
    }
    mm_check("mm_init");
    return 0;
}

/* 
 * mm_malloc - Allocate a block by incrementing the brk pointer.
 *     Always allocate a block whose size is a multiple of the alignment.
 */


// 在第i条链表上寻找合适空闲块, 成功返回空闲块指针bp(prev), 失败返回NULL
static void *find_free_block_by_list_index(size_t size, int idx)
{
    char *p = get_list_head(idx);
    while (p != NULL) {
        if (GET_SIZE(HDRP(p)) >= size) {
            return p;
        }
        p = GET_SUCC(p);
    }
    return NULL;
}

static void *find_free_block(size_t size)
{
    void *p = NULL;
    int list_size;
    for (int i = 0; i < MAX_LIST_NUM; ++i) {
        list_size = (1 << (MIN_INDEX + i));
        if (size > list_size) {
            continue;
        }
     
        if ((p = find_free_block_by_list_index(size, i)) != NULL) {
            // printf("find_free_block success! p: %p, size: %d, listid: %d\n", p, size, i);
            return p;
        }
    }
    // printf("find_free_block failed! p: %p, size: %d\n", p, size);
    return p;
}


void *mm_malloc(size_t size)
{
    char logstr[256] = "0";
    size = (size < MIN_BLOCK_SIZE) ? MIN_BLOCK_SIZE: ALIGN(MIN_BLOCK_SIZE + size);

    // 首先，寻找空闲链表是否有合适的空闲块。如果没找到合适的空闲块, 需要扩展堆
    void *p = find_free_block(size);
    if (p == NULL) {
        if ((p = extend_heap(MAX(size, CHUNKSIZE))) == NULL) {
            printf("mm_malloc, extend_heap failed!\n");
            return NULL;
        }
    }

    p = place(p, size);
    sprintf(logstr, "mm_malloc, size: %d, ptr: %p", size, p);
    mm_check(logstr);
    return p;
}

/*
 * mm_free - Freeing a block does nothing.
 */
void mm_free(void *ptr)
{
    char logstr[256];
    sprintf(logstr, "mm_free ptr: %p\n", ptr);
    int size = GET_SIZE(HDRP(ptr));
    PUT(HDRP(ptr), PACK(size, 0));
    PUT(FTRP(ptr), PACK(size, 0));

    // 注意将释放后的空闲块重新插入到分离链表中
    insert_node(ptr, size);
    coalesce(ptr);

    mm_check(logstr);
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

