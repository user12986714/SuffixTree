#define _GNU_SOURCE

/* Precompilcation checks */
#ifndef __linux__
#warning "Only linux is currently supported. Random issues may occur."
#endif

#ifndef __GNUC__
#warning "Only gcc is currently supported. Random issues may occur."
#endif

#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>


/* Part 0 - Macros */
#define _likely(x) __builtin_expect(!!(x), 1)
#define _unlikely(x) __builtin_expect(!!(x), 0)

#define _err_if(x, _return_value) if (_unlikely(x)){ \
    return _return_value; \
}

#define DEBUG_BUILD

#ifdef DEBUG_BUILD
#define _assert(x) if (_unlikely(!(x))){*(uint64_t *)(0) = 0xABADCAFE;}
#define _composable
#else
#define _assert(x)

/* Marking a function composable inlines the function on release builds.
 * Composable functions are cheap. It is encouraged to declare many composable
 * functions, each doing one thing and does it well. They make the code much
 * more readable and easier to debug/review, with zero overhead */
#define _composable static inline __attribute__((always_inline))
#endif


/* Storage pools */
#define _create_flags (O_RDWR | O_NOFOLLOW | O_CREAT | O_TRUNC)
#define _create_mode (S_IRUSR | S_IWUSR)
#define _open_flags (O_RDWR | O_NOFOLLOW)
#define _mmap_flags (MAP_SHARED)
#define _mmap_prot (PROT_READ | PROT_WRITE)

#define _align (24)  /* 16 MiB */
#define _calc_align(x) (((((x) - 1) >> _align) + 1) << _align)

typedef struct pool_s{
    int fd;
    char *addr;
    uint64_t size;
} pool_t;

static inline int pool_create(char *path){
    int fd = open(path, _create_flags, _create_mode);
    _err_if(fd == -1, -1);

    uint64_t size = sizeof(uint64_t);
    if (_unlikely(ftruncate(fd, _calc_align(size)) == -1)){
        close(fd);
        return -1;
    }
    if (_unlikely((lseek(fd, 0, SEEK_SET) == (off_t)(-1)) || \
                (write(fd, &size, sizeof(uint64_t)) == -1))){
        close(fd);
        return -1;
    }

    close(fd);
    return 0;
}

static inline int pool_open(pool_t *pool, char *path){
    pool -> fd = open(path, _open_flags);
    _err_if(pool -> fd == -1, -1);

    struct stat file_stat;
    fstat(pool -> fd, &file_stat);
    pool -> size = file_stat.st_size;

    pool -> addr = mmap(NULL, pool -> size, \
            _mmap_prot, _mmap_flags, pool -> fd, 0);
    if (_unlikely(pool -> addr == MAP_FAILED)){
        close(pool -> fd);
        return -1;
    }

    return 0;
}

_composable void pool_sync(pool_t *pool){
    msync(pool -> addr, pool -> size, MS_SYNC);
    return;
}

_composable int pool_maybe_expand(pool_t *pool, uint64_t size){
    if (_unlikely(size > pool -> size)){
        pool_sync(pool);

        uint64_t new_size = _calc_align(size);
        _err_if(ftruncate(pool -> fd, new_size) == -1, -1);

        char *new_addr = mremap(pool -> addr, pool -> size, \
                new_size, MREMAP_MAYMOVE);
        _err_if(new_addr == MAP_FAILED, -1);

        pool -> addr = new_addr;
        pool -> size = new_size;
    }

    return 0;
}

static inline void pool_close(pool_t *pool){
    pool_sync(pool);
    munmap(pool -> addr, pool -> size);
    close(pool -> fd);
    return;
}

/* Metaprogramming macros for generating generic pool functions */
#define _mk_alloc_func(_name, _pool_type, _element_type, _id_type) \
    static inline _id_type _name (_pool_type *pool){ \
        uint64_t used_size = *((uint64_t *)(pool -> addr)); \
        uint64_t new_used_size = used_size + sizeof(_element_type); \
        _err_if(new_used_size < used_size, 0); \
        _err_if(pool_maybe_expand(pool, new_used_size) == -1, 0); \
        *((uint64_t *)(pool -> addr)) = new_used_size; \
        return used_size; \
    }

#define _mk_resolve_func(_name, _pool_type, _element_type, _id_type) \
    _composable _element_type * _name (_pool_type *pool, _id_type id){ \
        return (_element_type *)(pool -> addr + id); \
    }


/* Data structures */
typedef uint64_t str_idx_t;
typedef pool_t str_pool_t;

typedef uint64_t tag_id_t;
typedef tag_id_t tag_list_head_t;

typedef uint64_t child_id_t;
typedef child_id_t child_root_t;

typedef uint64_t node_id_t;

/* Tags */
typedef pool_t tag_pool_t;
typedef struct tag_s{
    uint64_t id;
    uint64_t type;
    tag_id_t next;
} tag_t;
_mk_alloc_func(alloc_tag, tag_pool_t, tag_t, tag_id_t);
_mk_resolve_func(resolve_tag, tag_pool_t, tag_t, tag_id_t);

/* Children (AVL trees to implement dictionaries) */
typedef pool_t child_pool_t;
typedef struct child_s{
    char ch;
    node_id_t node;
    child_id_t parent;
    child_id_t lchild;
    child_id_t rchild;
} child_t;
_mk_alloc_func(alloc_child, child_pool_t, child_t, child_id_t);
_mk_resolve_func(resolve_child, child_pool_t, child_t, child_id_t);
#define _left_heavy (1)
#define _right_heavy (2)

/* Suffix tree node */
typedef pool_t node_pool_t;
typedef struct node_s{
    node_id_t link;
    node_id_t parent;
    child_root_t children;
    str_idx_t start_idx;
    str_idx_t end_idx;
    tag_list_head_t tags;
} node_t;
_mk_alloc_func(alloc_node, node_pool_t, node_t, node_id_t);
_mk_resolve_func(resolve_node, node_pool_t, node_t, node_id_t);

/* Suffix tree */
typedef struct active_point_s{
    node_id_t node;
    uint64_t len;
    str_idx_t edge;
    char ch;
} active_point_t;

typedef struct tree_s{
    struct{
        str_pool_t str_pool;
        tag_pool_t tag_pool;
        child_pool_t child_pool;
        node_pool_t node_pool;
    } pools;
    active_point_t active_point;
    node_id_t root;
    node_id_t last_node;
    uint64_t implicit_suffix;
} tree_t;


/* String */
static inline uint64_t add_string(str_pool_t *pool, char *src, uint64_t len){
    uint64_t used_size = *((uint64_t *)(pool -> addr));
    uint64_t new_used_size = used_size + len;
    _err_if(new_used_size < used_size, -1);  /* Overflow */

    _err_if(pool_maybe_expand(pool, new_used_size) == -1, -1);

    memcpy(pool -> addr + used_size, src, len);
    *((uint64_t *)(pool -> addr)) = new_used_size;
    return used_size;
}

_composable char str_idx(str_pool_t *pool, str_idx_t idx){
    if (_likely(idx < pool -> size)){
        return *(pool -> addr + idx);
    }
    else{
        return 0xFF;
    }
}

_composable uint64_t str_size(str_pool_t *pool){
    return *((uint64_t *)(pool -> addr));
}


/* Tags */
static inline tag_id_t create_tag(tag_pool_t *pool, uint64_t type, uint64_t id){
    tag_id_t tag = alloc_tag(pool);
    _err_if(!tag, 0);

    resolve_tag(pool, tag) -> id = id;
    resolve_tag(pool, tag) -> type = type;
    resolve_tag(pool, tag) -> next = 0;

    return tag;
}

static inline int add_tag_to_node(tag_pool_t *tag_pool, node_pool_t *node_pool, \
        node_id_t root, node_id_t node, uint64_t type, uint64_t id){
    node_id_t on_node = node;
    while (on_node != root){
        tag_id_t current_tag = resolve_node(node_pool, on_node) -> tags;
        tag_id_t previous_tag = 0;

        while (_unlikely(current_tag && \
                    (resolve_tag(tag_pool, current_tag) -> id > id))){
            previous_tag = current_tag;
            current_tag = resolve_tag(tag_pool, current_tag) -> next;
        }

        if (current_tag && (id == resolve_tag(tag_pool, current_tag) -> id)){
            resolve_tag(tag_pool, current_tag) -> type |= type;
        }
        else{
            tag_id_t new_tag = create_tag(tag_pool, type, id);
            _err_if(!new_tag, -1);
            resolve_tag(tag_pool, new_tag) -> next = current_tag;

            if (_unlikely(previous_tag)){
                resolve_tag(tag_pool, previous_tag) -> next = new_tag;
            }
            else{
                resolve_node(node_pool, on_node) -> tags = new_tag;
            }
        }

        on_node = resolve_node(node_pool, on_node) -> parent;
    }

    return 0;
}


/* Children */
_composable child_id_t get_parent_id(child_pool_t *pool, child_id_t child){
    return ((~(_left_heavy | _right_heavy)) & \
            resolve_child(pool, child) -> parent);
}

_composable child_id_t is_left_heavy(child_pool_t *pool, child_id_t child){
    return (_left_heavy & resolve_child(pool, child) -> parent);
}

_composable child_id_t is_right_heavy(child_pool_t *pool, child_id_t child){
    return (_right_heavy & resolve_child(pool, child) -> parent);
}

_composable void change_parent(child_pool_t *pool, \
        child_id_t child, child_id_t new_parent){
    resolve_child(pool, child) -> parent &= (_left_heavy | _right_heavy);
    resolve_child(pool, child) -> parent |= new_parent;
    return;
}

_composable void set_left_heavy(child_pool_t *pool, child_id_t child){
    resolve_child(pool, child) -> parent |= _left_heavy;
    return;
}

_composable void set_right_heavy(child_pool_t *pool, child_id_t child){
    resolve_child(pool, child) -> parent |= _right_heavy;
    return;
}

_composable void set_balanced(child_pool_t *pool, child_id_t child){
    resolve_child(pool, child) -> parent &= ~(_left_heavy | _right_heavy);
    return;
}

_composable int is_left_child(child_pool_t *pool, \
        child_id_t child, child_id_t parent){
    return (resolve_child(pool, parent) -> lchild == child);
}

_composable int is_right_child(child_pool_t *pool, \
        child_id_t child, child_id_t parent){
    return (resolve_child(pool, parent) -> rchild == child);
}

_composable void avl_update_child(child_pool_t *pool, \
        child_id_t parent, child_id_t orig_child, child_id_t new_child){
    if (is_left_child(pool, orig_child, parent)){
        resolve_child(pool, parent) -> lchild = new_child;
    }
    else{
        _assert(is_right_child(pool, orig_child, parent));
        resolve_child(pool, parent) -> rchild = new_child;
    }
    return;
}

_composable void avl_update_child_or_root(child_pool_t *pool, \
        child_id_t parent, child_root_t *root, \
        child_id_t orig_child, child_id_t new_child){
    if (_likely(parent)){
        avl_update_child(pool, parent, orig_child, new_child);
    }
    else{
        *root = new_child;
    }

    return;
}

#define _rot_child(_pool, _from, _from_field, _to, _to_field) \
    if (resolve_child(_pool, _from) -> _from_field){ \
        resolve_child(_pool, _to) -> _to_field = \
                resolve_child(_pool, _from) -> _from_field; \
        change_parent(_pool, \
                resolve_child(_pool, _from) -> _from_field, _to); \
    } \
    else{ \
        resolve_child(_pool, _to) -> _to_field = 0; \
    }

static inline void avl_lrot(child_pool_t *pool, \
        child_id_t pivot, child_root_t *root){
    child_id_t orig_root = get_parent_id(pool, pivot);

    _rot_child(pool, pivot, lchild, orig_root, rchild);
    resolve_child(pool, pivot) -> lchild = orig_root;

    child_id_t hyper_parent = get_parent_id(pool, orig_root);
    resolve_child(pool, orig_root) -> parent = pivot;
    resolve_child(pool, pivot) -> parent = hyper_parent;

    avl_update_child_or_root(pool, hyper_parent, root, orig_root, pivot);
    return;
}

static inline void avl_rrot(child_pool_t *pool, \
        child_id_t pivot, child_root_t *root){
    child_id_t orig_root = get_parent_id(pool, pivot);

    _rot_child(pool, pivot, rchild, orig_root, lchild);
    resolve_child(pool, pivot) -> rchild = orig_root;

    child_id_t hyper_parent = get_parent_id(pool, orig_root);
    resolve_child(pool, orig_root) -> parent = pivot;
    resolve_child(pool, pivot) -> parent = hyper_parent;

    avl_update_child_or_root(pool, hyper_parent, root, orig_root, pivot);
    return;
}

/* Left-right rotate */
static inline void avl_lrrot(child_pool_t *pool, \
        child_id_t pivot, child_root_t *root){
    child_id_t rchild = resolve_child(pool, pivot) -> rchild;
    child_id_t orig_root = get_parent_id(pool, pivot);

    _rot_child(pool, rchild, lchild, pivot, rchild);
    resolve_child(pool, rchild) -> lchild = pivot;
    _rot_child(pool, rchild, rchild, orig_root, lchild);
    resolve_child(pool, rchild) -> rchild = orig_root;

    child_id_t hyper_parent = get_parent_id(pool, orig_root);
    resolve_child(pool, pivot) -> parent = rchild;
    resolve_child(pool, orig_root) -> parent = rchild;

    if (is_left_heavy(pool, rchild)){
        set_right_heavy(pool, orig_root);
    }
    else if (is_right_heavy(pool, rchild)){
        set_left_heavy(pool, pivot);
    }
    resolve_child(pool, rchild) -> parent = hyper_parent;

    avl_update_child_or_root(pool, hyper_parent, root, orig_root, rchild);
    return;
}

/* Right-left rotate */
static inline void avl_rlrot(child_pool_t *pool, \
        child_id_t pivot, child_root_t *root){
    child_id_t lchild = resolve_child(pool, pivot) -> lchild;
    child_id_t orig_root = get_parent_id(pool, pivot);

    _rot_child(pool, lchild, rchild, pivot, lchild);
    resolve_child(pool, lchild) -> rchild = pivot;
    _rot_child(pool, lchild, lchild, orig_root, rchild);
    resolve_child(pool, lchild) -> lchild = orig_root;

    child_id_t hyper_parent = get_parent_id(pool, orig_root);
    resolve_child(pool, pivot) -> parent = lchild;
    resolve_child(pool, orig_root) -> parent = lchild;

    if (is_left_heavy(pool, lchild)){
        set_right_heavy(pool, pivot);
    }
    else if (is_right_heavy(pool, lchild)){
        set_left_heavy(pool, orig_root);
    }
    resolve_child(pool, lchild) -> parent = hyper_parent;

    avl_update_child_or_root(pool, hyper_parent, root, orig_root, lchild);
    return;
}

static inline node_id_t find_child(child_pool_t *child_pool, \
        node_pool_t *node_pool, node_id_t node, char ch){
    child_id_t current_child = resolve_node(node_pool, node) -> children;
    while (current_child){
        if (_unlikely(ch == resolve_child(child_pool, current_child) -> ch)){
            /* Found */
            return resolve_child(child_pool, current_child) -> node;
        }

        if (ch < resolve_child(child_pool, current_child) -> ch){
            current_child = resolve_child(child_pool, current_child) -> lchild;
        }
        else{
            current_child = resolve_child(child_pool, current_child) -> rchild;
        }
    }

    /* Not found */
    return 0;
}

static inline void change_child(child_pool_t *child_pool, \
        node_pool_t *node_pool, node_id_t node, char ch, node_id_t new_child){
    child_id_t current_child = resolve_node(node_pool, node) -> children;
    while (1){
        _assert(current_child);
        if (_unlikely(ch == resolve_child(child_pool, current_child) -> ch)){
            resolve_child(child_pool, current_child) -> node = new_child;
            return;
        }

        if (ch < resolve_child(child_pool, current_child) -> ch){
            current_child = resolve_child(child_pool, current_child) -> lchild;
        }
        else{
            current_child = resolve_child(child_pool, current_child) -> rchild;
        }
    }
}

static inline int add_child(child_pool_t *child_pool, \
        node_pool_t *node_pool, node_id_t node, char ch, node_id_t child){
    child_id_t new_child = alloc_child(child_pool);
    _err_if(!new_child, -1);

    resolve_child(child_pool, new_child) -> ch = ch;
    resolve_child(child_pool, new_child) -> node = child;
    resolve_child(child_pool, new_child) -> lchild = 0;
    resolve_child(child_pool, new_child) -> rchild = 0;

    if (_unlikely(!(resolve_node(node_pool, node) -> children))){
        resolve_child(child_pool, new_child) -> parent = 0;
        resolve_node(node_pool, node) -> children = new_child;
        return 0;
    }

    child_id_t current_child = resolve_node(node_pool, node) -> children;
    while (1){
        _assert(ch != resolve_child(child_pool, current_child) -> ch);
        if (ch < resolve_child(child_pool, current_child) -> ch){
            if (resolve_child(child_pool, current_child) -> lchild){
                current_child = \
                        resolve_child(child_pool, current_child) -> lchild;
            }
            else{
                resolve_child(child_pool, new_child) -> parent = current_child;
                resolve_child(child_pool, current_child) -> lchild = new_child;
                break;
            }
        }
        else{
            if (resolve_child(child_pool, current_child) -> rchild){
                current_child = \
                       resolve_child(child_pool, current_child) -> rchild;
            }
            else{
                resolve_child(child_pool, new_child) -> parent = current_child;
                resolve_child(child_pool, current_child) -> rchild = new_child;
                break;
            }
        }
    }

    child_root_t *root_ptr = &(resolve_node(node_pool, node) -> children);
    child_id_t parent_child = current_child;
    current_child = new_child;
    while (parent_child){
        if (is_left_child(child_pool, current_child, parent_child)){
            if (is_left_heavy(child_pool, parent_child)){
                if (is_right_heavy(child_pool, current_child)){
                    avl_lrrot(child_pool, current_child, root_ptr);
                }
                else{
                    avl_rrot(child_pool, current_child, root_ptr);
                }

                break;
            }
            else if (is_right_heavy(child_pool, parent_child)){
                set_balanced(child_pool, parent_child);
                break;
            }
            else{
                set_left_heavy(child_pool, parent_child);
            }
        }
        else{
            _assert(is_right_child(child_pool, current_child, parent_child));
            if (is_right_heavy(child_pool, parent_child)){
                if (is_left_heavy(child_pool, current_child)){
                    avl_rlrot(child_pool, current_child, root_ptr);
                }
                else{
                    avl_lrot(child_pool, current_child, root_ptr);
                }

                break;
            }
            else if (is_left_heavy(child_pool, parent_child)){
                set_balanced(child_pool, parent_child);
                break;
            }
            else{
                set_right_heavy(child_pool, parent_child);
            }
        }

        current_child = parent_child;
        parent_child = get_parent_id(child_pool, parent_child);
    }

    return 0;
}


/* Suffix tree nodes */
static inline node_id_t create_node(node_pool_t *pool, \
        node_id_t root, node_id_t parent, \
        str_idx_t start_idx, str_idx_t end_idx){
    node_id_t node = alloc_node(pool);
    _err_if(!node, 0);

    resolve_node(pool, node) -> link = root;
    resolve_node(pool, node) -> parent = parent;
    resolve_node(pool, node) -> children = 0;
    resolve_node(pool, node) -> start_idx = start_idx;
    resolve_node(pool, node) -> end_idx = end_idx;
    resolve_node(pool, node) -> tags = 0;

    return node;
}

_composable uint64_t len_edge(node_pool_t *pool, node_id_t node){
    return (resolve_node(pool, node) -> end_idx + 1 - \
            resolve_node(pool, node) -> start_idx);
}

_composable int is_leaf_node(node_pool_t *pool, node_id_t node){
    return !(resolve_node(pool, node) -> children);
}


/* Suffix tree */
_composable str_pool_t *sp_of(tree_t *tree){
    return &((tree -> pools).str_pool);
}

_composable tag_pool_t *tp_of(tree_t *tree){
   return &((tree -> pools).tag_pool);
}

_composable child_pool_t *cp_of(tree_t *tree){
    return &((tree -> pools).child_pool);
}

_composable node_pool_t *np_of(tree_t *tree){
    return &((tree -> pools).node_pool);
}

_composable active_point_t *ap_of(tree_t *tree){
    return &(tree -> active_point);
}

_composable node_id_t an_of(tree_t *tree){
    return ap_of(tree) -> node;
}

_composable uint64_t al_of(tree_t *tree){
    return ap_of(tree) -> len;
}

_composable str_idx_t ae_of(tree_t *tree){
    return ap_of(tree) -> edge;
}

_composable char ac_of(tree_t *tree){
    return ap_of(tree) -> ch;
}

_composable char t_str_idx(tree_t *tree, str_idx_t idx){
    return str_idx(sp_of(tree), idx);
}

_composable tag_t *t_resolve_tag(tree_t *tree, tag_id_t id){
    return resolve_tag(tp_of(tree), id);
}

_composable child_t *t_resolve_child(tree_t *tree, child_id_t id){
    return resolve_child(cp_of(tree), id);
}

_composable node_t *t_resolve_node(tree_t *tree, node_id_t id){
    return resolve_node(np_of(tree), id);
}

_composable tag_id_t t_create_tag(tree_t *tree, uint64_t type, uint64_t id){
    return create_tag(tp_of(tree), type, id);
}

_composable node_id_t t_create_node(tree_t *tree, node_id_t parent, \
        str_idx_t start_idx, str_idx_t end_idx){
    return create_node(np_of(tree), tree -> root, parent, start_idx, end_idx);
}

_composable int t_add_tag_to_node(tree_t *tree, node_id_t node, \
        uint64_t type, uint64_t id){
    return add_tag_to_node(tp_of(tree), np_of(tree), tree -> root, \
            node, type, id);
}

_composable node_id_t t_find_child(tree_t *tree, node_id_t node, char ch){
    return find_child(cp_of(tree), np_of(tree), node, ch);
}

_composable void t_change_child(tree_t *tree, node_id_t parent, \
        char ch, node_id_t new_child){
    change_child(cp_of(tree), np_of(tree), parent, ch, new_child);
    return;
}

_composable int t_add_child(tree_t *tree, node_id_t parent, \
        char ch, node_id_t child){
    return add_child(cp_of(tree), np_of(tree), parent, ch, child);
}

_composable node_id_t find_active_node_child(tree_t *tree, char ch){
    return t_find_child(tree, ap_of(tree) -> node, ch);
}

_composable uint64_t t_len_edge(tree_t *tree, node_id_t node){
    return len_edge(np_of(tree), node);
}

_composable int t_is_leaf_node(tree_t *tree, node_id_t node){
    return is_leaf_node(np_of(tree), node);
}

_composable void maybe_update_link(tree_t *tree, node_id_t target){
    if (tree -> last_node){
        t_resolve_node(tree, tree -> last_node) -> link = target;
        tree -> last_node = 0;
    }
    return;
}

_composable int walkdown(tree_t *tree, node_id_t node){
    if ((t_is_leaf_node(tree, node)) && \
            (t_len_edge(tree, node) <= al_of(tree))){
        ap_of(tree) -> len -= t_len_edge(tree, node);
        ap_of(tree) -> edge += t_len_edge(tree, node);
        ap_of(tree) -> ch = t_str_idx(tree, ae_of(tree));
        ap_of(tree) -> node = node;

        return 1;
    }

    return 0;
}

static inline node_id_t split_edge(tree_t *tree, \
        node_id_t orig_node, uint64_t split_len, char split_next_ch, \
        node_id_t parent_node, char parent_ch){
    str_idx_t split_idx = t_resolve_node(tree, orig_node) -> start_idx + \
                          split_len;
    node_id_t split_node;

    if (split_idx == t_resolve_node(tree, orig_node) -> end_idx){
        split_node = orig_node;
    }
    else{
        split_node = t_create_node(tree, parent_node, \
                t_resolve_node(tree, orig_node) -> start_idx, split_idx);
        _err_if(!split_node, 0);

        if (_likely(t_resolve_node(tree, orig_node) -> tags)){
            tag_id_t current_tag = t_resolve_node(tree, orig_node) -> tags;
            uint64_t id = t_resolve_tag(tree, current_tag) -> id;
            uint64_t type = t_resolve_tag(tree, current_tag) -> type;

            tag_id_t new_tag = t_create_tag(tree, type, id);
            _err_if(!new_tag, 0);

            t_resolve_node(tree, split_node) -> tags = new_tag;

            tag_id_t previous_tag = new_tag;
            current_tag = t_resolve_tag(tree, current_tag) -> next;
            while (current_tag){
                id = t_resolve_tag(tree, current_tag) -> id;
                type = t_resolve_tag(tree, current_tag) -> type;

                new_tag = t_create_tag(tree, type, id);
                _err_if(!new_tag, 0);

                t_resolve_tag(tree, previous_tag) -> next = new_tag;
                previous_tag = new_tag;
                current_tag = t_resolve_tag(tree, current_tag) -> next;
            }
        }

        t_change_child(tree, parent_node, parent_ch, split_node);
        t_resolve_node(tree, orig_node) -> parent = split_node;
        t_resolve_node(tree, orig_node) -> start_idx = split_idx + 1;
        _err_if(t_add_child(tree, \
                    split_node, split_next_ch, orig_node) == -1, 0);
    }

    maybe_update_link(tree, split_node);
    tree -> last_node = split_node;

    return split_node;
}

static inline int add_char_to_tree(tree_t *tree, str_idx_t idx, char ch, \
        str_idx_t tail_idx, uint64_t type, uint64_t id){
    (tree -> implicit_suffix)++;
    tree -> last_node = 0;

    while (tree -> implicit_suffix){
        node_id_t next_node;
        while (al_of(tree) && \
                (next_node = find_active_node_child(tree, ac_of(tree))) && \
                walkdown(tree, next_node));

        if (!al_of(tree)){
            ap_of(tree) -> edge = idx;
            ap_of(tree) -> ch = ch;
            next_node = find_active_node_child(tree, ch);

            if (!next_node){
                next_node = t_create_node(tree, an_of(tree), idx, tail_idx);
                _err_if(!next_node, -1);

                maybe_update_link(tree, an_of(tree));

                _err_if(t_add_child(tree, an_of(tree), \
                            ch, next_node) == -1, -1);
                _err_if(t_add_tag_to_node(tree, next_node, type, id) == -1, -1);
            }
            else{
                if (an_of(tree) != tree -> root){
                    maybe_update_link(tree, an_of(tree));
                }

                (ap_of(tree) -> len)++;
                break;
            }
        }
        else{
            _assert(next_node);
            char next_ch = t_str_idx(tree, \
                    t_resolve_node(tree, next_node) -> start_idx + al_of(tree));
            if (ch == next_ch){
                if (an_of(tree) != tree -> root){
                    maybe_update_link(tree, an_of(tree));
                }

                (ap_of(tree) -> len)++;
                break;
            }
            else{
                node_id_t split_node = split_edge(tree, next_node, \
                        al_of(tree) - 1, next_ch, an_of(tree), ac_of(tree));
                _err_if(!split_node, -1);

                node_id_t new_node = t_create_node(tree, \
                        split_node, idx, tail_idx);
                _err_if(!new_node, -1);
                _err_if(t_add_child(tree, split_node, ch, new_node) == -1, -1);
                _err_if(t_add_tag_to_node(tree, new_node, type, id) == -1, -1);
            }
        }

        (tree -> implicit_suffix)--;
        if (an_of(tree) == tree -> root){
            if (al_of(tree)){
                (ap_of(tree) -> len)--;
                ap_of(tree) -> edge = idx - tree -> implicit_suffix + 1;
                ap_of(tree) -> ch = t_str_idx(tree, ae_of(tree));
            }
        }
        else{
            ap_of(tree) -> node = t_resolve_node(tree, an_of(tree)) -> link;
        }
    }

    return 0;
}
