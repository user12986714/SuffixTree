#define _GNU_SOURCE

/* Precompilcation checks */
#ifndef __linux__
#warning "Only linux is currently supported. Random issues may occur."
#endif

#ifndef __GNUC__
#warning "Only gcc is currently supported. Random issues may occur."
#endif

/* Note:
 * Content of multiple files are merged into this file for performance
 * reasons, especially pointer dereferencing overhead. This decision is made
 * according to profiling results; please do not "fix" it */

#include <ruby.h>
#include <ruby/thread.h>
#include <pthread.h>

#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>

/* Part 0 - Macros */
#ifdef DEBUG_BUILD
#define _assert(x) if (_unlikely(!(x))){ \
    *(uint32_t *)(0) = 0xABADCAFE; \
}
#elif USE_UNREACHABLE_AS_ASSERT
#warning "__builtin_unreachable() enabled for assertions"
#define _assert(x) if (!(x)){__builtin_unreachable();}
#else
#define _assert(x)
#endif

/* Please use likely/unlikely macros only for error handling, performance
 * critical code and/or to show intent that makes the code more readable */
#define _likely(x) __builtin_expect(!!(x), 1)
#define _unlikely(x) __builtin_expect(!!(x), 0)

#define _err_if(x, _return_value) if (_unlikely(x)){ \
    return _return_value; \
}


/* Part 1 - Use disk as main memory */
typedef uint64_t rptr_t;

typedef struct{
    char *map_addr;
    rptr_t map_size;
    int fd;
} diskmap_t;

#ifdef __x86_64__
/* Align to (1 << 3) (i.e. 8) bytes */
#define _alloc_align 3
#else
#define _alloc_align 2
#endif

#ifndef _diskmap_align
#define _diskmap_align 32
#endif

#define _create_flags (O_RDWR | O_NOFOLLOW | O_CREAT | O_TRUNC)
#define _create_mode (S_IRUSR | S_IWUSR)
#define _open_flags (O_RDWR | O_NOFOLLOW)
#define _mmap_prot (PROT_READ | PROT_WRITE)
#define _mmap_flags (MAP_SHARED)

#define _calc_disk_align(x) \
    (((((x) - 1) >> _diskmap_align) + 1) << _diskmap_align)
#define _calc_alloc_align(x) \
    (((((x) - 1) >> _alloc_align) + 1) << _alloc_align)

/* Create new diskmap */
static inline int diskmap_create(char *path){
    int fd = open(path, _create_flags, _create_mode);
    if (_unlikely(fd == -1)){
        return -1;
    }

    rptr_t init_size = _calc_alloc_align(sizeof(rptr_t));
    if (_unlikely(ftruncate(fd, init_size) == -1)){
        close(fd);
        return -1;
    }

    init_size = _calc_alloc_align(sizeof(rptr_t));
    if (_unlikely((lseek(fd, 0, SEEK_SET) == (off_t)(-1)) ||
                (write(fd, &init_size, sizeof(rptr_t)) == -1))){
        close(fd);
        return -1;
    }

    close(fd);
    return 0;
}

/* Open a diskmap */
static inline int diskmap_open(diskmap_t *diskmap, char *path){
    diskmap -> fd = open(path, _open_flags);
    if (_unlikely(diskmap -> fd == -1)){
        close(diskmap -> fd);
        return -1;
    }

    struct stat file_stat;
    fstat(diskmap -> fd, &file_stat);
    diskmap -> map_size = file_stat.st_size;

    diskmap -> map_addr = mmap(NULL, diskmap -> map_size,
            _mmap_prot, _mmap_flags, diskmap -> fd, 0);
    if (_unlikely(diskmap -> map_addr == MAP_FAILED)){
        close(diskmap -> fd);
        return -1;
    }

    return 0;
}

/* Sync a diskmap with its underlying file */
static inline void diskmap_sync(diskmap_t *diskmap){
    msync(diskmap -> map_addr, diskmap -> map_size, MS_SYNC);
    return;
}

/* Sync a diskmap asynchronously */
static inline void diskmap_sync_async(diskmap_t *diskmap){
    msync(diskmap -> map_addr, diskmap -> map_size, MS_ASYNC);
    return;
}

/* Allocate memory from diskmap */
static inline __attribute__((hot)) rptr_t diskmap_alloc(diskmap_t *diskmap, \
        rptr_t size){
    /* This function is performance critical */
    size = _calc_alloc_align(size);
    rptr_t old_tail = *((rptr_t *)(diskmap -> map_addr));
    rptr_t new_tail = old_tail + size;

    if (_unlikely(new_tail > diskmap -> map_size)){
        diskmap_sync(diskmap);
        new_tail = _calc_disk_align(new_tail);
        char *new_map_addr;
        if (_unlikely(ftruncate(diskmap -> fd, new_tail) == -1)){
            return 0;
        }
        new_map_addr = mremap(diskmap -> map_addr,
                diskmap -> map_size, new_tail, MREMAP_MAYMOVE);
        if (_unlikely(new_map_addr == MAP_FAILED)){
            return 0;
        }
        diskmap -> map_addr = new_map_addr;
        diskmap -> map_size = new_tail;
        new_tail = old_tail + size;
    }

    *((rptr_t *)(diskmap -> map_addr)) = new_tail;
    return old_tail;
}

/* Close a diskmap */
static inline void diskmap_close(diskmap_t *diskmap){
    /* To be extra careful, we sync the map before unmapping it. Hence, if the
     * munmap() call fails, which this function does not check, the content is
     * still synchronized to the disk, and we can just pretend the map has been
     * closed as program termination will automatically unmap it */
    diskmap_sync(diskmap);
    munmap(diskmap -> map_addr, diskmap -> map_size);
    close(diskmap -> fd);
    return;
}

/* Convenience macro for resolving relative pointers.
 *
 * When using this macro, or resolving to absolute addresses in general, please
 * taken into consideration that the base address may change if diskmap_alloc()
 * is called, in which case the absolute addresses resolved before may become
 * invalid. */
#define _r(_type, _rptr, _diskmap) ((_type *)((_diskmap) -> map_addr + (_rptr)))

#undef _create_flags
#undef _create_mode
#undef _open_flags
#undef _mmap_prot
#undef _mmap_flags
#undef _calc_disk_align
#undef _calc_alloc_align


/* Part 2 - String
 *
 * We treat a utf-8 encoded string as a binary blob and index on a byte, rather
 * than on a codepoint, level */

#ifndef _char_shift
#define _char_shift 16
#define _char_mask 65535
#endif

#ifndef _idx_shift
#define _idx_shift 16
#define _idx_mask 65535
#endif

#ifndef _metaidx_default_size
#define _metaidx_default_size 4
#endif

#define _out_of_range 0xFF

struct u8core_s{
    char txt[1 << _char_shift];
    uint32_t tail;
    rptr_t next;
};

struct u8idx_s{
    rptr_t idx[1 << _idx_shift];
    uint64_t tail;
};

typedef struct{
    rptr_t metaidx;
    uint64_t metaidx_tail;
    uint64_t metaidx_end;
    uint64_t str_tail;
} u8str_t;

typedef struct{
    rptr_t at_block;
    uint32_t block_idx;
} u8seek_t;

/* The _r* macros are defined to keep the code short. This may not necessarily
 * be a good style, but the line length and readability after macro expansion
 * is unacceptable.
 *
 * The letter after _r represents the data type. Here, c is for core, i for
 * idx, r for rptr and s for str.
 *
 * These macros should be undefined after each section */
#define _rc(x) (_r(struct u8core_s, (x), diskmap))
#define _ri(x) (_r(struct u8idx_s, (x), diskmap))
#define _rr(x) (_r(rptr_t, (x), diskmap))
#define _rs(x) (_r(u8str_t, (x), diskmap))

/* WARNING: pointer magic ahead */
#define _rrs(x) \
    (_rr(_rs(x) -> metaidx))
#define _rirs(x, _idx) \
    (_ri(_rrs(x)[(_idx >> _char_shift) >> _idx_shift]))
#define _rcirs(x, _idx) \
    (_rc((_rirs(x, _idx) -> idx)[(_idx >> _char_shift) & _idx_mask]))
#define _rtcirs(x, _idx) \
    ((_rcirs(x, _idx) -> txt)[_idx & _char_mask])

#define _rirst(x) (_ri(_rrs(x)[_rs(x) -> metaidx_tail]))
#define _rcirst(x) (_rc((_rirst(x) -> idx)[_rirst(x) -> tail]))
#define _rtcirst(x) ((_rcirst(x) -> txt)[_rcirst(x) -> tail])

#define _addr_diff(x, y) ((char *)(x) - (char *)(y))

/* Create a new utf-8 string */
static inline rptr_t u8str_create(diskmap_t *diskmap){
    rptr_t new_str = diskmap_alloc(diskmap, sizeof(u8str_t));
    _err_if(!new_str, 0);

    rptr_t new_metaidx = diskmap_alloc(diskmap, _metaidx_default_size * \
            sizeof(rptr_t));
    _err_if(!new_metaidx, 0);

    rptr_t new_core = diskmap_alloc(diskmap, sizeof(struct u8core_s));
    _err_if(!new_core, 0);

    rptr_t new_idx = diskmap_alloc(diskmap, sizeof(struct u8idx_s));
    _err_if(!new_idx, 0);

    /* (_rc(new_core) -> txt)[0] intentionally left unused */
    _rc(new_core) -> tail = 0;
    _rc(new_core) -> next = 0;

    (_ri(new_idx) -> idx)[0] = new_core;
    _ri(new_idx) -> tail = 0;

    _rr(new_metaidx)[0] = new_idx;

    _rs(new_str) -> metaidx = new_metaidx;
    _rs(new_str) -> metaidx_tail = 0;
    _rs(new_str) -> metaidx_end = _metaidx_default_size - 1;
    _rs(new_str) -> str_tail = 0;

    return new_str;
}

/* Append to a utf-8 string; assumes utf-8 encoding */
static inline int u8str_append(diskmap_t *diskmap, rptr_t u8str, \
        char *u8_addr, uint64_t u8_size){
    uint32_t free_in_tail = _char_mask - _rcirst(u8str) -> tail;
    if (u8_size <= free_in_tail){
        memcpy((&_rtcirst(u8str)) + 1, u8_addr, u8_size);
        _rcirst(u8str) -> tail += u8_size;
        _rs(u8str) -> str_tail += u8_size;
    }
    else{
        memcpy((&_rtcirst(u8str)) + 1, u8_addr, free_in_tail);
        _rcirst(u8str) -> tail = _char_mask;
        _rs(u8str) -> str_tail |= _char_mask;
        u8_size -= free_in_tail;

        for (uint64_t i = 0; i < (u8_size >> _char_shift); i++){
            rptr_t new_core = diskmap_alloc(diskmap, sizeof(struct u8core_s));
            _err_if(!new_core, -1);

            if (_unlikely(_rirst(u8str) -> tail == _idx_mask)){
                rptr_t new_idx = diskmap_alloc(diskmap, \
                        sizeof(struct u8idx_s));
                _err_if(!new_idx, -1);

                if (_unlikely(_rs(u8str) -> metaidx_tail == \
                            _rs(u8str) -> metaidx_end)){
                    uint64_t old_end = (_rs(u8str) -> metaidx_end);
                    uint64_t new_end = ((old_end + 1) << 1) - 1;
                    rptr_t new_metaidx = diskmap_alloc(diskmap, \
                            (new_end + 1) * sizeof(rptr_t));
                    _err_if(!new_metaidx, -1);

                    memcpy(_rr(new_metaidx), _rrs(u8str), \
                            (old_end + 1) * sizeof(rptr_t));

                    _rs(u8str) -> metaidx_end = new_end;
                    _rs(u8str) -> metaidx = new_metaidx;
                }

                _ri(new_idx) -> tail = -1;  /* Autowrap */
                _rrs(u8str)[++(_rs(u8str) -> metaidx_tail)] = new_idx;
            }

            memcpy(_rc(new_core) -> txt, u8_addr, (1 << _char_shift));
            _rc(new_core) -> tail = _char_mask;
            _rc(new_core) -> next = 0;

            _rcirst(u8str) -> next = new_core;
            (_rirst(u8str) -> idx)[++(_rirst(u8str) -> tail)] = new_core;
            u8_addr += (1 << _char_shift);
        }
        rptr_t new_core = diskmap_alloc(diskmap, sizeof(struct u8core_s));
        _err_if(!new_core, -1);

        if (_unlikely(_rirst(u8str) -> tail == _idx_mask)){
            rptr_t new_idx = diskmap_alloc(diskmap, \
                    sizeof(struct u8idx_s));
            _err_if(!new_idx, -1);

            if (_unlikely(_rs(u8str) -> metaidx_tail == \
                        _rs(u8str) -> metaidx_end)){
                uint64_t new_end = (_rs(u8str) -> metaidx_end) << 1;
                rptr_t new_metaidx = diskmap_alloc(diskmap, \
                        sizeof(new_end * sizeof(rptr_t)));
                _err_if(!new_metaidx, -1);

                memcpy(_rr(new_metaidx), _rrs(u8str), \
                        _rs(u8str) -> metaidx_end);

                _rs(u8str) -> metaidx_end = new_end;
                _rs(u8str) -> metaidx = new_metaidx;
            }

            _ri(new_idx) -> tail = -1;  /* Autowrap */
            _rrs(u8str)[++(_rs(u8str) -> metaidx_tail)] = new_idx;
        }

        memcpy(_rc(new_core) -> txt, u8_addr, (u8_size & _char_mask));
        _rc(new_core) -> tail = (u8_size & _char_mask) - 1;
        _rc(new_core) -> next = 0;

        _rcirst(u8str) -> next = new_core;
        (_rirst(u8str) -> idx)[++(_rirst(u8str) -> tail)] = new_core;
        _rs(u8str) -> str_tail += u8_size;
    }

    return 0;
}

/* Read char at a specific index of a utf-8 string */
static inline __attribute__((hot)) char u8str_read_at(diskmap_t *diskmap, \
                          rptr_t u8str, uint64_t idx){
    /* This function is performance critical */
    _err_if(idx > _rs(u8str) -> str_tail, _out_of_range);
    return _rtcirs(u8str, idx);
}

/* Seek to a given position of a utf-8 string; assumes index in range */
static inline void u8str_seek(diskmap_t *diskmap, \
        rptr_t u8str, uint64_t idx, u8seek_t *seek){
    idx--;
    seek -> at_block = (_rirs(u8str, idx) -> idx)[(idx >> _char_shift) & \
                       _idx_mask];
    seek -> block_idx = (idx & _char_mask);

    return;
}

/* Read the char at the seeked location and move forward 1 char */
static inline __attribute__((hot)) char u8str_read(diskmap_t *diskmap, \
        u8seek_t *seek){
    /* This function is performance critical */
    if (_unlikely(seek -> block_idx == _rc(seek -> at_block) -> tail)){
        _err_if(!(_rc(seek -> at_block) -> next), _out_of_range);
        seek -> at_block = _rc(seek -> at_block) -> next;
        seek -> block_idx = 0;
    }
    else{
        (seek -> block_idx)++;
    }

    return (_rc(seek -> at_block) -> txt)[seek -> block_idx];
}

#undef _rc
#undef _ri
#undef _rr
#undef _rs
#undef _rrs
#undef _rirs
#undef _rcirs
#undef _rtcirs
#undef _rirst
#undef _rcirst
#undef _rtcirst
#undef _addr_diff


/* Part 3 - AVL tree
 *
 * AVL trees are used to store char-child pairs in the next part. As Unicode
 * alphabet is huge, it is impractical to store such pairs with a naive array
 * as one can do with ASCII. Simple linked list (i.e. alist) has been tried,
 * but was shown as a major performance overhead.
 * We opt to use AVL tree instead of red-black tree as we are not deleting any
 * keys, and are more focused on lookup efficiency */
struct avlnode_s{
    char ch;  /* Key */
    rptr_t data;  /* Value */
    rptr_t lchild;
    rptr_t rchild;
    rptr_t parent;
};

#define _ra(x) (_r(struct avlnode_s, (x), diskmap))

/* Here we will use a similar trick as used for red-black trees in Linux
 * kernel; since our diskmap_alloc() returns aligned addresses, the lower
 * 2 bits are always 0, and hence can be used to store the balance factor.
 *
 * The field parent is used to store that information */
#define _left_heavy 1
#define _right_heavy 2
#define _is_left_heavy(x) ((_ra(x) -> parent) & _left_heavy)
#define _is_right_heavy(x) ((_ra(x) -> parent) & _right_heavy)
#define _get_parent(x) ((_ra(x) -> parent) & ~(_left_heavy | _right_heavy))

#define _rot_child(_from, _from_field, _to, _to_field) \
    if (_ra(_from) -> _from_field){ \
        _ra(_to) -> _to_field = _ra(_from) -> _from_field; \
        _ra(_ra(_from) -> _from_field) -> parent &= \
                (_left_heavy | _right_heavy); \
        _ra(_ra(_from) -> _from_field) -> parent |= _to; \
    } \
    else{ \
        _ra(_to) -> _to_field = 0; \
    }

/* Left rotate */
static inline void avl_lrot(diskmap_t *diskmap, rptr_t pivot, rptr_t *root){
    rptr_t orig_root = _get_parent(pivot);

    _rot_child(pivot, lchild, orig_root, rchild);
    _ra(pivot) -> lchild = orig_root;
    _ra(pivot) -> parent = _get_parent(orig_root);

    if (_likely(_ra(pivot) -> parent)){
        /* orig_root is not the root of the tree. Let pivot replace
         * orig_root in orig_root's parent's children */
        if (_ra(_ra(pivot) -> parent) -> lchild == orig_root){
            _ra(_ra(pivot) -> parent) -> lchild = pivot;
        }
        else{
            _ra(_ra(pivot) -> parent) -> rchild = pivot;
        }
    }
    else{
        *root = pivot;
    }
    _ra(orig_root) -> parent = pivot;
    /* At this point, all balance factors are cleared, and we are done;
     * left/right rotation during insertion always results in 0 in balance
     * factors, and we never delete keys. */

    return;
}

/* Right rotate */
static inline void avl_rrot(diskmap_t *diskmap, rptr_t pivot, rptr_t *root){
    rptr_t orig_root = _get_parent(pivot);

    _rot_child(pivot, rchild, orig_root, lchild);
    _ra(pivot) -> rchild = orig_root;
    _ra(pivot) -> parent = _get_parent(orig_root);

    if (_likely(_ra(pivot) -> parent)){
        if (_ra(_ra(pivot) -> parent) -> lchild == orig_root){
            _ra(_ra(pivot) -> parent) -> lchild = pivot;
        }
        else{
            _ra(_ra(pivot) -> parent) -> rchild = pivot;
        }
    }
    else{
        *root = pivot;
    }
    _ra(orig_root) -> parent = pivot;

    return;
}

/* Left-right rotate */
static inline void avl_lrrot(diskmap_t *diskmap, rptr_t pivot, rptr_t *root){
    rptr_t rchild = _ra(pivot) -> rchild;
    rptr_t orig_root = _get_parent(pivot);

    _rot_child(rchild, lchild, pivot, rchild);
    _ra(rchild) -> lchild = pivot;
    _rot_child(rchild, rchild, orig_root, lchild);
    _ra(rchild) -> rchild = orig_root;

    /* Re-assign balance factors */
    if _is_left_heavy(rchild){
        _ra(rchild) -> parent = _get_parent(orig_root);
        _ra(pivot) -> parent = rchild;
        _ra(orig_root) -> parent = rchild | _right_heavy;
    }
    else if _is_right_heavy(rchild){
        _ra(rchild) -> parent = _get_parent(orig_root);
        _ra(pivot) -> parent = rchild | _left_heavy;
        _ra(orig_root) -> parent = rchild;
    }
    else{
        _ra(rchild) -> parent = _get_parent(orig_root);
        _ra(pivot) -> parent = rchild;
        _ra(orig_root) -> parent = rchild;
    }

    if (_likely(_ra(rchild) -> parent)){
        /* orig_root is not the root of the tree. Let pivot replace
         * orig_root in orig_root's parent's children */
        if (_ra(_ra(rchild) -> parent) -> lchild == orig_root){
            _ra(_ra(rchild) -> parent) -> lchild = rchild;
        }
        else{
            _ra(_ra(rchild) -> parent) -> rchild = rchild;
        }
    }
    else{
        *root = rchild;
    }

    return;
}

/* Right-left rotate */
static inline void avl_rlrot(diskmap_t *diskmap, rptr_t pivot, rptr_t *root){
    rptr_t lchild = _ra(pivot) -> lchild;
    rptr_t orig_root = _get_parent(pivot);

    _rot_child(lchild, rchild, pivot, lchild);
    _ra(lchild) -> rchild = pivot;
    _rot_child(lchild, lchild, orig_root, rchild);
    _ra(lchild) -> lchild = orig_root;

    /* Re-assign balance factors */
    if _is_left_heavy(lchild){
        _ra(lchild) -> parent = _get_parent(orig_root);
        _ra(pivot) -> parent = lchild | _right_heavy;
        _ra(orig_root) -> parent = lchild;
    }
    else if _is_right_heavy(lchild){
        _ra(lchild) -> parent = _get_parent(orig_root);
        _ra(pivot) -> parent = lchild;
        _ra(orig_root) -> parent = lchild | _left_heavy;
    }
    else{
        _ra(lchild) -> parent = _get_parent(orig_root);
        _ra(pivot) -> parent = lchild;
        _ra(orig_root) -> parent = lchild;
    }

    if (_likely(_ra(lchild) -> parent)){
        /* orig_root is not the root of the tree. Let pivot replace
         * orig_root in orig_root's parent's children */
        if (_ra(_ra(lchild) -> parent) -> lchild == orig_root){
            _ra(_ra(lchild) -> parent) -> lchild = lchild;
        }
        else{
            _ra(_ra(lchild) -> parent) -> rchild = lchild;
        }
    }
    else{
        *root = lchild;
    }

    return;
}

/* Search for a key in an AVL tree */
static inline __attribute__((hot)) rptr_t avl_search(diskmap_t *diskmap, \
        rptr_t root, char ch){
    /* This function is performance critical */
    rptr_t current_node = root;
    while (current_node){
        if (_unlikely(ch == _ra(current_node) -> ch)){
            /* Mark this as unlikely because if entered this branch the
             * function returns, hence marking it likely is likely nonsense */
            return _ra(current_node) -> data;
        }

        if (ch < _ra(current_node) -> ch){
            current_node = _ra(current_node) -> lchild;
        }
        else{
            current_node = _ra(current_node) -> rchild;
        }
    }

    return 0;  /* Not found */
}

/* Search for a key, and set its data. The key must already be present.
 * This function is mainly used for splitting edge in the next part */
static inline __attribute__((hot)) void avl_set(diskmap_t *diskmap, \
        rptr_t root, char ch, rptr_t data){
    /* This function is performance critical */
    /* This function is mostly copied from avl_search() with minor
     * modification on behaviours when the key is found */
    rptr_t current_node = root;
    while (1){
        if (_unlikely(ch == _ra(current_node) -> ch)){
            _ra(current_node) -> data = data;
            return;
        }

        if (ch < _ra(current_node) -> ch){
            current_node = _ra(current_node) -> lchild;
        }
        else{
            current_node = _ra(current_node) -> rchild;
        }
    }
}

/* Insert a key value pair to an ALV tree */
static inline __attribute__((hot)) int avl_insert(diskmap_t *diskmap, \
        rptr_t *root, char ch, rptr_t data){
    /* This function is performance critical */
    rptr_t new_node = diskmap_alloc(diskmap, sizeof(struct avlnode_s));
    _err_if(!new_node, -1);

    _ra(new_node) -> ch = ch;
    _ra(new_node) -> data = data;
    _ra(new_node) -> lchild = 0;
    _ra(new_node) -> rchild = 0;

    if (_unlikely(!(*root))){
        _ra(new_node) -> parent = 0;
        *root = new_node;
        return 0;
    }

    rptr_t current_node = *root;
    while (1){
        _assert(ch != _ra(current_node) -> ch);

        if (ch < _ra(current_node) -> ch){
            if (_ra(current_node) -> lchild){
                /* Search left subtree */
                current_node = _ra(current_node) -> lchild;
                continue;
            }
            else{
                /* Insert as left child */
                _ra(new_node) -> parent = current_node;
                _ra(current_node) -> lchild = new_node;
                break;
            }
        }
        else{
            if (_ra(current_node) -> rchild){
                /* Search right subtree */
                current_node = _ra(current_node) -> rchild;
                continue;
            }
            else{
                /* Insert as right child */
                _ra(new_node) -> parent = current_node;
                _ra(current_node) -> rchild = new_node;
                break;
            }
        }
    }

    rptr_t parent_node = current_node;
    current_node = new_node;
    while (parent_node){
        if (_ra(parent_node) -> lchild == current_node){
            if _is_left_heavy(parent_node){
                /* Need rotation */
                if _is_right_heavy(current_node){
                    avl_lrrot(diskmap, current_node, root);
                }
                else{
                    avl_rrot(diskmap, current_node, root);
                }

                break;
            }
            else if _is_right_heavy(parent_node){
                /* Absorbed */
                _ra(parent_node) -> parent &= ~_right_heavy;
                break;
            }

            /* Disturbed but no rotation needed... yet */
             _ra(parent_node) -> parent |= _left_heavy;
        }
        else{
            if _is_left_heavy(parent_node){
                _ra(parent_node) -> parent &= ~_left_heavy;
                break;
            }
            else if _is_right_heavy(parent_node){
                if _is_left_heavy(current_node){
                    avl_rlrot(diskmap, current_node, root);
                }
                else{
                    avl_lrot(diskmap, current_node, root);
                }

                break;
            }

            _ra(parent_node) -> parent |= _right_heavy;
        }
        current_node = parent_node;
        parent_node = _get_parent(current_node);
    }

    return 0;
}

#undef _ra
#undef _left_heavy
#undef _right_heavy
#undef _is_left_heavy
#undef _is_right_heavy
#undef _get_parent
#undef _rot_child


/* Part 4 - Suffix tree
 *
 * Here we implemented Ukkonen's algorithm with active point. This is not the
 * same as the canonization method originally presented in the paper, but it
 * can be shown that they are equivalent. The suffix tree here is
 * generalized */
struct stnode_s{
    rptr_t parent;
    rptr_t children;  /* An AVL tree */
    rptr_t link;
    uint64_t start_idx;
    uint64_t end_idx;
    rptr_t tags;
};

typedef struct{
    uint64_t id;
    uint64_t type;
    rptr_t next;
} sttag_t;

typedef struct{
    rptr_t txt;
    rptr_t root;
} stcore_t;

typedef struct{
    /* This is the expanded data structure that can be constructed by stcore_t.
     * Initialize active_node to root, active_len to 0, other active_* to any,
     * last_node to 0 and implicit_suffix to 0; and copy in txt and root. */
    rptr_t txt;
    rptr_t root;
    rptr_t active_node;
    uint64_t active_len;
    uint64_t active_edge;
    char active_char;
    rptr_t last_node;
    uint64_t implicit_suffix;
} sttree_t;

#define _rn(x) _r(struct stnode_s, (x), diskmap)
#define _rt(x) _r(sttag_t, (x), diskmap)

#define _len_edge(_node) (_rn(_node) -> end_idx - _rn(_node) -> start_idx + 1)
#define _stridx(_idx) u8str_read_at(diskmap, tree -> txt, _idx)

#define _an (tree -> active_node)
#define _al (tree -> active_len)
#define _ae (tree -> active_edge)
#define _ac (tree -> active_char)

__attribute__((cold)) int st_create(char *path){
    _err_if(diskmap_create(path) == -1, -1);

    diskmap_t diskmap;
    _err_if(diskmap_open(&diskmap, path) == -1, -1);

    rptr_t core_tree = diskmap_alloc(&diskmap, sizeof(stcore_t));
    /* If allocation failed or not allocating to a correct relative address,
     * hard fail. This means no two trees may share a diskmap */
    _err_if(core_tree != sizeof(rptr_t), -1);

    rptr_t txt = u8str_create(&diskmap);
    _err_if(!txt, -1);

    rptr_t root = diskmap_alloc(&diskmap, sizeof(struct stnode_s));
    _err_if(!root, -1);

    _r(struct stnode_s, root, &diskmap) -> parent = 0;
    _r(struct stnode_s, root, &diskmap) -> children = 0;
    _r(struct stnode_s, root, &diskmap) -> link = 0;
    _r(struct stnode_s, root, &diskmap) -> start_idx = 0;
    _r(struct stnode_s, root, &diskmap) -> end_idx = 0;
    _r(struct stnode_s, root, &diskmap) -> tags = 0;

    _r(stcore_t, core_tree, &diskmap) -> txt = txt;
    _r(stcore_t, core_tree, &diskmap) -> root = root;

    diskmap_close(&diskmap);
    return 0;
}

__attribute__((cold)) int st_open(diskmap_t *diskmap, \
        sttree_t *tree, char *path){
    _err_if(diskmap_open(diskmap, path) == -1, -1);
    rptr_t core_tree = sizeof(rptr_t);

    tree -> txt = _r(stcore_t, core_tree, diskmap) -> txt;
    tree -> root = _r(stcore_t, core_tree, diskmap) -> root;
    tree -> active_node = tree -> root;
    tree -> active_len = 0;
    tree -> active_edge = 0;
    tree -> active_char = 0;
    tree -> last_node = 0;
    tree -> implicit_suffix = 0;

    return 0;
}

__attribute__((flatten)) void st_sync(diskmap_t *diskmap){
    diskmap_sync(diskmap);
    return;
}

__attribute__((flatten)) void st_sync_async(diskmap_t *diskmap){
    diskmap_sync_async(diskmap);
    return;
}

__attribute__((cold,flatten)) void st_close(diskmap_t *diskmap){
    diskmap_close(diskmap);
    return;
}

/* Create a new node */
static inline rptr_t st_create_node(diskmap_t *diskmap, sttree_t *tree, \
        rptr_t parent, uint64_t start_idx, uint64_t end_idx){
    rptr_t new_node = diskmap_alloc(diskmap, sizeof(struct stnode_s));
    _err_if(!new_node, 0);

    _rn(new_node) -> parent = parent;
    _rn(new_node) -> children = 0;
    _rn(new_node) -> link = tree -> root;

    _rn(new_node) -> start_idx = start_idx;
    _rn(new_node) -> end_idx = end_idx;
    _rn(new_node) -> tags = 0;

    return new_node;
}

/* Add a new tag to a node */
static inline __attribute__((hot)) int st_add_tag(diskmap_t *diskmap, \
        sttree_t *tree, rptr_t node, uint64_t type, uint64_t id){
    /* This function is performance critical, and is the major hotspot due
     * to the tight loop. We would like to have a better algorithm here but
     * currently we cannot figure out yet */
    rptr_t on_node = node;
    while (on_node != tree -> root){
        rptr_t current_tag = _rn(on_node) -> tags;
        rptr_t previous_tag = 0;

        /* As you are reading this, you may think that the authors are stupid
         * and should have also used an AVL tree, so a tag can be added in
         * O(log(n)) time rather than O(n) time.
         * However, since most of the time strings, and hence tags, are added
         * sequentially with an increasing id, this is effectively O(1). The
         * issue with AVL trees (or red-black trees or whatsoever) is that they
         * occupies a lot of space, which can be a problem as tags explodes
         * (you may be unable to see that for now, because we have not yet
         * reached there).
         * Hence, we opt to use just a singly linked list */
        while (_unlikely(current_tag && (_rt(current_tag) -> id > id))){
            /* Please do not "fix" the unlikely annotation; if you still think
             * that it is a mistake, read the comment above again */
            /* XXX Note: the (_rt(current_tag) -> id > id) clause, although
             * is unlikely (and impossible if strings are added sequentially),
             * is a major overhead in this function */
            previous_tag = current_tag;
            current_tag = _rt(current_tag) -> next;
        }

        if (current_tag && (id == _rt(current_tag) -> id)){
            /* Field type is a bitmap */
            if (type & _rt(current_tag) -> type){
                /* Tag already present; all parents will also have the tag */
                break;
            }
            _rt(current_tag) -> type |= type;
        }
        else{
            rptr_t new_tag = diskmap_alloc(diskmap, sizeof(sttag_t));
            _err_if(!new_tag, -1);

            _rt(new_tag) -> id = id;
            _rt(new_tag) -> type = type;
            _rt(new_tag) -> next = current_tag;

            if (_unlikely(previous_tag)){
                _rt(previous_tag) -> next = new_tag;
            }
            else{
                _rn(on_node) -> tags = new_tag;
            }
        }

        on_node = _rn(on_node) -> parent;
    }

    return 0;
}

/* Walkdown from the active point */
static inline int st_walkdown(diskmap_t *diskmap, sttree_t *tree, rptr_t node){
    /* Do NOT walkdown if this is a former leaf node. Note that for (not
     * former and currently active) leaf node, it is impossible for active
     * length to be greater than edge length, so it will never walkdown to
     * them anyway.
     * See st_split_edge() for more information why we are doing this. */
    if (_rn(node) -> children && (_len_edge(node) <= _al)){
        _al -= _len_edge(node);
        _ae += _len_edge(node);
        _ac = _stridx(_ae);
        _an = node;

        return 1;
    }

    return 0;
}

/* Find a child; this is a wrapper */
static inline __attribute__((hot,flatten)) \
                  rptr_t st_find_child(diskmap_t *diskmap, \
                          rptr_t node, char ch){
    return avl_search(diskmap, _rn(node) -> children, ch);
}

/* Set a child; this is a wrapper */
static inline __attribute__((flatten)) \
                  void st_set_child(diskmap_t *diskmap, rptr_t node, \
                          char ch, rptr_t child){
    avl_set(diskmap, _rn(node) -> children, ch, child);
    return;
}

/* Add a child; this is a wrapper */
static inline __attribute__((hot,flatten)) \
                  int st_add_child(diskmap_t *diskmap, rptr_t node, \
                          char ch, rptr_t child){
    rptr_t children = _rn(node) -> children;
    _err_if(avl_insert(diskmap, &children, ch, child) == -1, -1);

    if (_unlikely(children != _rn(node) -> children)){
        _rn(node) -> children = children;
    }
    return 0;
}

/* Split an edge */
static inline rptr_t st_split_edge(diskmap_t *diskmap, sttree_t *tree, \
        rptr_t orig_node, rptr_t split_len, char split_next_ch, \
        rptr_t parent_node, char parent_ch){
    uint64_t split_idx = _rn(orig_node) -> start_idx + split_len;
    rptr_t split_node;
    if (split_idx == _rn(orig_node) -> end_idx){
        /* This is not a real split; it is imaginary.
         * To generalize the suffix tree to index multiple strings, one
         * typically append a unique char to the end of a string, and another
         * unique char to the end of another string, ...
         * However, by doing so, we can run out of unique chars, and such
         * method is not efficient storage- and time- wise.
         * Hence, we would pretend that we added a unique char, but not to
         * actually add it; therefore, an extension to a former leaf node is
         * interpreted as an imaginary split (between the last actual char and
         * the imaginary unique char). */
        split_node = orig_node;
    }
    else{
        split_node = st_create_node(diskmap, tree, parent_node, \
                _rn(orig_node) -> start_idx, split_idx);
        _err_if(!split_node, 0);

        if (_likely(_rn(orig_node) -> tags)){
            /* Propagate (i.e. copy) all tags from child node to parent node.
             * Here split_node will become the parent of orig_node */
            rptr_t new_tag = diskmap_alloc(diskmap, sizeof(sttag_t));
            _err_if(!new_tag, 0);

            rptr_t current_tag = _rn(orig_node) -> tags;

            _rt(new_tag) -> id = _rt(current_tag) -> id;
            _rt(new_tag) -> type = _rt(current_tag) -> type;

            _rn(split_node) -> tags = new_tag;

            rptr_t previous_tag = new_tag;
            current_tag = _rt(current_tag) -> next;
            while (current_tag){
                new_tag = diskmap_alloc(diskmap, sizeof(sttag_t));
                _err_if(!new_tag, 0);

                _rt(new_tag) -> id = _rt(current_tag) -> id;
                _rt(new_tag) -> type = _rt(current_tag) -> type;

                _rt(previous_tag) -> next = new_tag;
                previous_tag = new_tag;
                current_tag = _rt(current_tag) -> next;
            }
            _rt(previous_tag) -> next = 0;
        }

        st_set_child(diskmap, parent_node, parent_ch, split_node);
        _rn(orig_node) -> parent = split_node;
        _rn(orig_node) -> start_idx = split_idx + 1;
        st_add_child(diskmap, split_node, split_next_ch, orig_node);
    }

    if (tree -> last_node){
        _rn(tree -> last_node) -> link = split_node;
    }
    tree -> last_node = split_node;

    return split_node;
}

/* Add a char to the suffix tree */
static inline __attribute__((hot)) int st_add_char(diskmap_t *diskmap, \
        sttree_t *tree, uint64_t idx, char ch, uint64_t tail, \
        uint64_t type, uint64_t id){
    (tree -> implicit_suffix)++;
    tree -> last_node = 0;

    while (tree -> implicit_suffix){
        rptr_t next_node;
        while (_al && (next_node = st_find_child(diskmap, _an, _ac)) && \
                st_walkdown(diskmap, tree, next_node));

        if (!_al){
            _ae = idx;
            _ac = ch;
            next_node = st_find_child(diskmap, _an, ch);

            if (!next_node){
                /* No edge starting with ch; create it */
                next_node = st_create_node(diskmap, tree, _an, idx, tail);
                _err_if(!next_node, -1);

                if (tree -> last_node){
                    _rn(tree -> last_node) -> link = _an;
                    tree -> last_node = 0;
                }

                _err_if(st_add_child(diskmap, _an, ch, next_node) == -1, -1);
                _err_if(st_add_tag(diskmap, tree, \
                            next_node, type, id) == -1, -1);
            }
            else{
                /* Found an implicit suffix */
                if (tree -> last_node && (_an != tree -> root)){
                    _rn(tree -> last_node) -> link = _an;
                    tree -> last_node = 0;
                }

                _al++;
                break;
            }
        }
        else{
            _assert(next_node);
            char next_ch = _stridx(_rn(next_node) -> start_idx + _al);
            if (ch == next_ch){
                /* Found an implicit suffix */
                if (tree -> last_node && (_an != tree -> root)){
                    _rn(tree -> last_node) -> link = _an;
                    tree -> last_node = 0;
                }

                _al++;
                break;
            }
            else{
                /* Split the edge */
                rptr_t split_node = st_split_edge(diskmap, tree, \
                        next_node, _al - 1, next_ch, _an, _ac);
                _err_if(!split_node, -1);

                rptr_t new_node = st_create_node(diskmap, tree, split_node, \
                        idx, tail);
                _err_if(!new_node, -1);
                _err_if(st_add_child(diskmap, split_node, \
                            ch, new_node) == -1, -1);
                _err_if(st_add_tag(diskmap, tree, \
                            new_node, type, id) == -1, -1);
            }
        }

        (tree -> implicit_suffix)--;
        if (_an == tree -> root){
            if (_al){
                _al--;
                _ae = idx - tree -> implicit_suffix + 1;
                _ac = _stridx(_ae);
            }
        }
        else{
            _an = _rn(_an) -> link;
        }
    }

    return 0;
}

/* Add a string to the suffix tree. Assumes utf-8 encoding */
__attribute__((hot)) int st_add_string(diskmap_t *diskmap, sttree_t *tree, \
        uint64_t start_idx, uint64_t end_idx, uint64_t type, uint64_t id){
    u8seek_t seek;
    u8str_seek(diskmap, tree -> txt, start_idx, &seek);

    /* Add each char to tree */
    while (start_idx <= end_idx){
        char ch = u8str_read(diskmap, &seek);
        _err_if(st_add_char(diskmap, tree, start_idx, ch, end_idx, \
                    type, id) == -1, -1);
        start_idx++;
    }

    while (tree -> implicit_suffix){
        rptr_t next_node;
        while (_al && (next_node = st_find_child(diskmap, _an, _ac)) && \
                st_walkdown(diskmap, tree, next_node));

        if (!_al){
            if (tree -> last_node){
                _rn(tree -> last_node) -> link = _an;
                tree -> last_node = 0;
            }
            _err_if(st_add_tag(diskmap, tree, _an, type, id) == -1, -1);
        }
        else{
            _assert(next_node);
            char next_ch = _stridx(_rn(next_node) -> start_idx + _al);
            rptr_t split_node = st_split_edge(diskmap, tree, \
                    next_node, _al - 1, next_ch, _an, _ac);
            _err_if(!split_node, -1);
            _err_if(st_add_tag(diskmap, tree, \
                        split_node, type, id) == -1, -1);
        }

        (tree -> implicit_suffix)--;
        if (_an == tree -> root){
            if (_al){
                _al--;
                _ae = end_idx - tree -> implicit_suffix + 1;
                _ac = _stridx(_ae);
            }
        }
        else{
            _an = _rn(_an) -> link;
        }
    }

    _assert(!(tree -> implicit_suffix));
    _assert(_an == tree -> root);
    _assert(!_al);

    return 0;
}

/* Search for a exact substring; assumes utf-8 encoding */
__attribute__((hot)) rptr_t st_basic_search(diskmap_t *diskmap, \
        sttree_t *tree, char *pattern, uint64_t size){
    rptr_t current_node = tree -> root;
    char *current_char = pattern;

    while (current_char - pattern < size){
        char ch = *(current_char++);
        if (!(current_node = st_find_child(diskmap, current_node, ch))){
            /* No match */
            return 0;
        }

        uint64_t current_idx = _rn(current_node) -> start_idx + 1;
        u8seek_t seek;
        u8str_seek(diskmap, tree -> txt, current_idx, &seek);

        while ((current_idx++ <= _rn(current_node) -> end_idx) && \
                (current_char - pattern < size)){
            if (*(current_char++) != u8str_read(diskmap, &seek)){
                /* No match */
                return 0;
            }
        }
    }

    return _rn(current_node) -> tags;
}

#undef _rn
#undef _rt
#undef _len_edge
#undef _stridx
#undef _an
#undef _al
#undef _ae
#undef _ac


/* Part 5 - RWLock */
typedef struct{
    pthread_mutex_t counter_mutex;
    pthread_mutex_t resource_mutex;
    uint64_t reader_counter;
} rwlock_t;

/* Initialize a rwlock */
int rwlock_init(rwlock_t *rwlock){
    if (_unlikely(pthread_mutex_init(&(rwlock -> counter_mutex), \
                    NULL) == -1)){
        return -1;
    }
    if (_unlikely(pthread_mutex_init(&(rwlock -> resource_mutex), \
                    NULL) == -1)){
        pthread_mutex_destroy(&(rwlock -> counter_mutex));
        return -1;
    }
    rwlock -> reader_counter = 0;
    return 0;
}

/* Lock for read */
void rwlock_rdlock(rwlock_t *rwlock){
    pthread_mutex_lock(&(rwlock -> counter_mutex));
    if (!(rwlock -> reader_counter)){
        pthread_mutex_lock(&(rwlock -> resource_mutex));
    }
    (rwlock -> reader_counter)++;
    return;
}

/* Unlock read locking */
void rwlock_rdunlock(rwlock_t *rwlock){
    pthread_mutex_lock(&(rwlock -> counter_mutex));
    (rwlock -> reader_counter)--;
    if (!(rwlock -> reader_counter)){
        pthread_mutex_unlock(&(rwlock -> resource_mutex));
    }
    return;
}

/* Lock for write */
void rwlock_wrlock(rwlock_t *rwlock){
    pthread_mutex_lock(&(rwlock -> resource_mutex));
    return;
}

/* Unlock write locking */
void rwlock_wrunlock(rwlock_t *rwlock){
    pthread_mutex_unlock(&(rwlock -> resource_mutex));
    return;
}

/* Destroy a rwlock */
void rwlock_destroy(rwlock_t *rwlock){
    pthread_mutex_destroy(&(rwlock -> counter_mutex));
    pthread_mutex_destroy(&(rwlock -> resource_mutex));
    return;
}


/* Part 6 - Ruby glueware */
typedef struct{
    diskmap_t diskmap;
    sttree_t tree;
    rwlock_t rw_lock;
} suffix_tree_t;

void suffix_tree_t_free(void *data){
    suffix_tree_t *typed_data = data;
    st_close(&(typed_data -> diskmap));
    rwlock_destroy(&(typed_data -> rw_lock));
    free(typed_data);
    return;
}

static const rb_data_type_t suffix_tree_t_type = {
    .wrap_struct_name = "suffix_tree_t",
    .function = {
        .dfree = &suffix_tree_t_free,
    }
};

VALUE suffix_tree_create(VALUE self, VALUE path){
    if (_unlikely(st_create(StringValueCStr(path)) == -1)){
        rb_raise(rb_eRuntimeError, "Creation failure");
    }
    return Qnil;
}

VALUE suffix_tree_t_alloc(VALUE self){
    suffix_tree_t *data = malloc(sizeof(suffix_tree_t));
    if (_unlikely(!data)){
        rb_raise(rb_eRuntimeError, "Allocation failure");
    }
    return TypedData_Wrap_Struct(self, &suffix_tree_t_type, data);
}

VALUE suffix_tree_t_initialize(VALUE self, VALUE path){
    suffix_tree_t *data;
    TypedData_Get_Struct(self, suffix_tree_t, &suffix_tree_t_type, data);

    if (_unlikely(rwlock_init(&(data -> rw_lock)) == -1)){
        rb_raise(rb_eRuntimeError, "RWLock initailization failure");
    }
    if (_unlikely(st_open(&(data -> diskmap), &(data -> tree), \
                    StringValueCStr(path)))){
        rwlock_destroy(&(data -> rw_lock));
        rb_raise(rb_eRuntimeError, "Open failure");
    }
    return self;
}

void *get_rdlock(void *args){
    suffix_tree_t *typed_args = args;
    rwlock_rdlock(&(typed_args -> rw_lock));
    return NULL;
}

void *get_wrlock(void *args){
    suffix_tree_t *typed_args = args;
    rwlock_wrlock(&(typed_args -> rw_lock));
    return NULL;
}

void *release_rdlock(void *args){
    suffix_tree_t *typed_args = args;
    rwlock_rdunlock(&(typed_args -> rw_lock));
    return NULL;
}

void *release_wrlock(void *args){
    suffix_tree_t *typed_args = args;
    rwlock_wrunlock(&(typed_args -> rw_lock));
    return NULL;
}

typedef struct{
    diskmap_t *diskmap;
    sttree_t *tree;
    uint64_t start_idx;
    uint64_t end_idx;
    uint64_t type;
    uint64_t id;
} insert_string_args_t;

typedef struct{
    diskmap_t *diskmap;
    sttree_t *tree;
    char *pattern_addr;
    uint64_t pattern_size;
    rptr_t result;
} basic_search_args_t;

void *gvl_free_insert_string(void *args){
    insert_string_args_t *typed_args = args;
    if (_unlikely(st_add_string(typed_args -> diskmap, typed_args -> tree, \
                    typed_args -> start_idx, typed_args -> end_idx, \
                    typed_args -> type, typed_args -> id) == -1)){
        return (void *)(0xABADCAFE);
    }
    return NULL;
}

void *gvl_free_basic_search(void *args){
    basic_search_args_t *typed_args = args;
    typed_args -> result = st_basic_search(typed_args -> diskmap, \
            typed_args -> tree, \
            typed_args -> pattern_addr, typed_args -> pattern_size);
    return NULL;
}

VALUE suffix_tree_sync(VALUE self){
    suffix_tree_t *data;
    TypedData_Get_Struct(self, suffix_tree_t, &suffix_tree_t_type, data);

    rb_thread_call_without_gvl(&get_rdlock, data, NULL, NULL);
    st_sync(&(data -> diskmap));
    rb_thread_call_without_gvl(&release_rdlock, data, NULL, NULL);

    return Qnil;
}

VALUE suffix_tree_sync_async(VALUE self){
    suffix_tree_t *data;
    TypedData_Get_Struct(self, suffix_tree_t, &suffix_tree_t_type, data);
    st_sync_async(&(data -> diskmap));
    return Qnil;
}

VALUE suffix_tree_insert_string(VALUE self, VALUE u8string, \
        VALUE type, VALUE id){
    suffix_tree_t *data;
    TypedData_Get_Struct(self, suffix_tree_t, &suffix_tree_t_type, data);

    rb_thread_call_without_gvl(&get_wrlock, data, NULL, NULL);

    char *u8_addr = StringValuePtr(u8string);
    uint64_t u8_size = RSTRING_LEN(u8string);

    uint64_t start_idx = _r(u8str_t, (data -> tree).txt, \
            &(data -> diskmap)) -> str_tail + 1;
    if (_unlikely(u8str_append(&(data -> diskmap), \
                    (data -> tree).txt, u8_addr, u8_size) == -1)){
        rb_thread_call_without_gvl(&release_wrlock, data, NULL, NULL);
        rb_raise(rb_eRuntimeError, "String appending failure");
    }
    uint64_t end_idx = _r(u8str_t, (data -> tree).txt, \
            &(data -> diskmap)) -> str_tail;

    insert_string_args_t insert_string_args = {
        .diskmap = &(data -> diskmap),
        .tree = &(data -> tree),
        .start_idx = start_idx,
        .end_idx = end_idx,
        .type = NUM2ULL(type),
        .id = NUM2ULL(id)
    };

    void *ret = rb_thread_call_without_gvl(&gvl_free_insert_string, \
            &insert_string_args, NULL, NULL);
    rb_thread_call_without_gvl(&release_wrlock, data, NULL, NULL);

    if (ret){
        rb_raise(rb_eRuntimeError, "String insertion failure");
    }

    return self;
}

VALUE suffix_tree_basic_search(VALUE self, VALUE u8pattern, VALUE type){
    suffix_tree_t *data;
    TypedData_Get_Struct(self, suffix_tree_t, &suffix_tree_t_type, data);

    rb_thread_call_without_gvl(&get_rdlock, data, NULL, NULL);

    rptr_t result_ptr;
    uint64_t pattern_size = RSTRING_LEN(u8pattern);
    char *pattern_addr = malloc(pattern_size);

    if (_likely(pattern_addr)){
        memcpy(pattern_addr, StringValuePtr(u8pattern), pattern_size);

        basic_search_args_t basic_search_args = {
            .diskmap = &(data -> diskmap),
            .tree = &(data -> tree),
            .pattern_addr = pattern_addr,
            .pattern_size = pattern_size,
        };
        rb_thread_call_without_gvl(&gvl_free_basic_search, \
                &basic_search_args, NULL, NULL);
        result_ptr = basic_search_args.result;

        free(pattern_addr);
    }
    else{
        /* Fall back to non-concurrent version */
        result_ptr = st_basic_search(&(data -> diskmap), &(data -> tree), \
                StringValuePtr(u8pattern), pattern_size);
    }

    uint64_t type_mask = NUM2ULL(type);
    /* If some exceptions happen here due to memory allocation failure, we
     * probably no longer care about that rw_lock anymore, as this is highly
     * abnormal */
    VALUE result_arr = rb_ary_new();
    while (result_ptr){
        if (type_mask & _r(sttag_t, result_ptr, &(data -> diskmap)) -> type){
            rb_ary_push(result_arr, \
                    ULL2NUM(_r(sttag_t, result_ptr, &(data -> diskmap)) -> id));
        }
        result_ptr = _r(sttag_t, result_ptr, &(data -> diskmap)) -> next;
    }

    rb_thread_call_without_gvl(&release_rdlock, data, NULL, NULL);
    return result_arr;
}

void Init_suffix_tree(){
    rb_define_global_function("__suffix_tree_create!", &suffix_tree_create, 1);
    VALUE cSuffixTree = rb_define_class("SuffixTree", rb_cObject);
    rb_define_alloc_func(cSuffixTree, &suffix_tree_t_alloc);
    rb_define_method(cSuffixTree, "initialize", &suffix_tree_t_initialize, 1);
    rb_define_method(cSuffixTree, "sync!", &suffix_tree_sync, 0);
    rb_define_method(cSuffixTree, "sync_async", &suffix_tree_sync_async, 0);
    rb_define_method(cSuffixTree, "insert", &suffix_tree_insert_string, 3);
    rb_define_method(cSuffixTree, "basic_search", &suffix_tree_basic_search, 2);
    return;
}
