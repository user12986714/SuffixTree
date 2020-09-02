#define _GNU_SOURCE

/* Precompilcation checks */
#ifndef __linux__
#warning "Only linux is currently supported. Random issues may occur."
#endif

#ifndef __GNUC__
#warning "Only gcc is currently supported. Random issues may occur."
#endif

#include <ruby.h>
#include <ruby/thread.h>
#include <pthread.h>
#include <stdlib.h>

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

#define _err_if(x) if (_unlikely(x)){ \
    goto error_handling; \
}

#ifdef DEBUG_BUILD
#define _assert(x) if (_unlikely(!(x))){*(uint64_t *)(0) = 0xABADCAFE;}
#define _unreachable() _assert(0)
#define _composable
#else
#define _assert(x)
#define _unreachable() __builtin_unreachable()
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

#define _align (28)  /* 256 MiB */
#define _calc_align(x) (((((x) - 1) >> _align) + 1) << _align)

typedef struct pool_s{
    int fd;
    char *addr;
    uint64_t size;
} pool_t;

/* Create a pool */
static inline int pool_create(char *path){
    int fd = open(path, _create_flags, _create_mode);
    _err_if(fd == -1);

    uint64_t size = sizeof(uint64_t);
    _err_if(ftruncate(fd, _calc_align(size)) == -1);
    _err_if(lseek(fd, 0, SEEK_SET) == (off_t)(-1));
    _err_if(write(fd, &size, sizeof(uint64_t)) == -1);

    close(fd);
    return 0;

error_handling:
    if (fd != -1){
        close(fd);
    }
    return -1;
}

/* Open a pool */
static inline int pool_open(pool_t *pool, char *path){
    pool -> fd = open(path, _open_flags);
    _err_if(pool -> fd == -1);

    struct stat file_stat;
    fstat(pool -> fd, &file_stat);
    pool -> size = file_stat.st_size;

    pool -> addr = mmap(NULL, pool -> size, \
            _mmap_prot, _mmap_flags, pool -> fd, 0);
    _err_if(pool -> addr == MAP_FAILED);

    return 0;

error_handling:
    if (pool -> fd != -1){
        close(pool -> fd);
    }
    return -1;
}

/* Sync a pool with backend file */
_composable void pool_sync(pool_t *pool){
    msync(pool -> addr, pool -> size, MS_SYNC);
    return;
}

/* See if the pool is large enough, and expand it if not */
_composable int pool_maybe_expand(pool_t *pool, uint64_t size){
    if (_unlikely(size > pool -> size)){
        /* Need expansion */
        pool_sync(pool);

        uint64_t new_size = _calc_align(size);
        _err_if(ftruncate(pool -> fd, new_size) == -1);

        char *new_addr = mremap(pool -> addr, pool -> size, \
                new_size, MREMAP_MAYMOVE);
        _err_if(new_addr == MAP_FAILED);

        pool -> addr = new_addr;
        pool -> size = new_size;
    }

    return 0;

error_handling:
    return -1;
}

/* Close a pool */
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
        _err_if(new_used_size < used_size); \
        _err_if(pool_maybe_expand(pool, new_used_size) == -1); \
        *((uint64_t *)(pool -> addr)) = new_used_size; \
        return used_size; \
    error_handling: \
        return 0; \
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

#define _start_of_string (0xFF)
#define _end_of_string (0xFE)

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
typedef struct all_pools_s{
    str_pool_t str_pool;
    tag_pool_t tag_pool;
    child_pool_t child_pool;
    node_pool_t node_pool;
} all_pools_t;

typedef struct active_point_s{
    node_id_t node;
    uint64_t len;
    str_idx_t edge;
    char ch;
} active_point_t;

typedef struct tree_s{
    all_pools_t pools;
    active_point_t active_point;
    node_id_t root;
    node_id_t last_node;
    uint64_t implicit_suffix;
} tree_t;

/* Set */
typedef struct set_node_s{
    char bf;
    uint64_t data;
    struct set_node_s *lchild;
    struct set_node_s *rchild;
} set_node_t;
typedef set_node_t set_t;

typedef struct rec_state_s{
    set_node_t *node;
    char stage;
} rec_state_t;
#define _newly_visit (0)
#define _visit_left (1)
#define _visit_right (2)

/* Tree traversal */
typedef struct stack_frame_s{
    uint64_t node_or_child;
    uint64_t idx;
    char stage;
} stack_frame_t;
#define _init_stack_size (256)
#define _done_funcall (3)
#define _first_visit (4)
#define _second_visit (5)


/* String */
/* Add a new string to the string pool (i.e. append it to the giant string */
static inline str_idx_t add_string(str_pool_t *pool, char *src, uint64_t len){
    uint64_t used_size = *((uint64_t *)(pool -> addr));
    uint64_t new_used_size = used_size + len + 2; /* Start and end of string */
    _err_if(new_used_size < used_size);  /* Overflow */

    _err_if(pool_maybe_expand(pool, new_used_size) == -1);

    *((char *)(pool -> addr + used_size)) = _start_of_string;
    memcpy(pool -> addr + used_size + 1, src, len);
    *((char *)(pool -> addr + new_used_size - 1)) = _end_of_string;
    *((uint64_t *)(pool -> addr)) = new_used_size;
    return used_size;

error_handling:
    return -1;
}

/* Get the char at the given index */
_composable char str_idx(str_pool_t *pool, str_idx_t idx){
    if (_likely(idx < pool -> size)){
        return *(pool -> addr + idx);
    }
    else{
        return 0xFF;
    }
}

/* Size of the entire giant string */
_composable uint64_t str_size(str_pool_t *pool){
    return *((uint64_t *)(pool -> addr));
}


/* Tags */
/* Create a new tag with given type and id */
static inline tag_id_t create_tag(tag_pool_t *pool, uint64_t type, uint64_t id){
    tag_id_t tag = alloc_tag(pool);
    _err_if(!tag);

    resolve_tag(pool, tag) -> id = id;
    resolve_tag(pool, tag) -> type = type;
    resolve_tag(pool, tag) -> next = 0;

    return tag;

error_handling:
    return 0;
}

/* Add a tag of given type and id to a node; propagate upward until root */
static inline int add_tag_to_node(tag_pool_t *tag_pool, \
        node_pool_t *node_pool, node_id_t root, node_id_t node, \
        uint64_t type, uint64_t id){
    tag_id_t current_tag = resolve_node(node_pool, node) -> tags;
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
        _err_if(!new_tag);
        resolve_tag(tag_pool, new_tag) -> next = current_tag;

        if (_unlikely(previous_tag)){
            resolve_tag(tag_pool, previous_tag) -> next = new_tag;
        }
        else{
            resolve_node(node_pool, node) -> tags = new_tag;
        }
    }

    return 0;

error_handling:
    return -1;
}

/* Given a type bitmask, decide if the given tag is wanted */
_composable uint64_t is_wanted_tag(tag_pool_t *pool, \
        tag_id_t tag, uint64_t type){
    return (type & resolve_tag(pool, tag) -> type);
}


/* Children
 *
 * This is an AVL tree, to implement a dictionary of with ch as the key and
 * node as the value. Since id is always aligned, we use the lower 2 bits of
 * parent field to store the balance factor */

/* Get the parent id of a child node */
_composable child_id_t get_parent_id(child_pool_t *pool, child_id_t child){
    return ((~(_left_heavy | _right_heavy)) & \
            resolve_child(pool, child) -> parent);
}

/* Decide if the node is left heavy */
_composable child_id_t is_left_heavy(child_pool_t *pool, child_id_t child){
    return (_left_heavy & resolve_child(pool, child) -> parent);
}

/* Decide if the node is right heavy */
_composable child_id_t is_right_heavy(child_pool_t *pool, child_id_t child){
    return (_right_heavy & resolve_child(pool, child) -> parent);
}

/* Change the parent of the node preserving the balance factor */
_composable void change_parent(child_pool_t *pool, \
        child_id_t child, child_id_t new_parent){
    resolve_child(pool, child) -> parent &= (_left_heavy | _right_heavy);
    resolve_child(pool, child) -> parent |= new_parent;
    return;
}

/* Set a node as left heavy, assuming the node is originally balanced */
_composable void set_left_heavy(child_pool_t *pool, child_id_t child){
    resolve_child(pool, child) -> parent |= _left_heavy;
    return;
}

/* Set a node as right heavy, assuming the node is originally balanced */
_composable void set_right_heavy(child_pool_t *pool, child_id_t child){
    resolve_child(pool, child) -> parent |= _right_heavy;
    return;
}

/* Set a node as balanced */
_composable void set_balanced(child_pool_t *pool, child_id_t child){
    resolve_child(pool, child) -> parent &= ~(_left_heavy | _right_heavy);
    return;
}

/* Decide if child is a left child of parent */
_composable int is_left_child(child_pool_t *pool, \
        child_id_t child, child_id_t parent){
    return (resolve_child(pool, parent) -> lchild == child);
}

/* Decide if child is a right child of parent */
_composable int is_right_child(child_pool_t *pool, \
        child_id_t child, child_id_t parent){
    return (resolve_child(pool, parent) -> rchild == child);
}

/* Update the child of parent from orig_child to new_child (i.e. replace
 * orig_child with new_child) */
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

/* Decide if parent is root. If yes, update root. Otherwise update child as
 * specified in avl_update_child() */
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

/* Left rotate */
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

/* Right rotate */
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

/* Find child (i.e. data) given ch (i.e. key) */
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

/* Change the child at ch to new_child, assuming that a child is already present
 * at ch */
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

/* Add a child child under key ch, assuming that there is no child under ch */
static inline int add_child(child_pool_t *child_pool, \
        node_pool_t *node_pool, node_id_t node, char ch, node_id_t child){
    child_id_t new_child = alloc_child(child_pool);
    _err_if(!new_child);

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

error_handling:
    return -1;
}


/* Suffix tree nodes */
static inline node_id_t create_node(node_pool_t *pool, \
        node_id_t root, node_id_t parent, \
        str_idx_t start_idx, str_idx_t end_idx){
    node_id_t node = alloc_node(pool);
    _err_if(!node);

    resolve_node(pool, node) -> link = root;
    resolve_node(pool, node) -> parent = parent;
    resolve_node(pool, node) -> children = 0;
    resolve_node(pool, node) -> start_idx = start_idx;
    resolve_node(pool, node) -> end_idx = end_idx;
    resolve_node(pool, node) -> tags = 0;

    return node;

error_handling:
    return 0;
}

/* Calculate the edge length of the edge attached to the node */
_composable uint64_t len_edge(node_pool_t *pool, node_id_t node){
    return (resolve_node(pool, node) -> end_idx + 1 - \
            resolve_node(pool, node) -> start_idx);
}

/* Decide if the node is a leaf */
_composable int is_leaf_node(node_pool_t *pool, node_id_t node){
    return !(resolve_node(pool, node) -> children);
}


/* Suffix tree */
/* Get the string pool of the tree */
_composable str_pool_t *sp_of(tree_t *tree){
    return &((tree -> pools).str_pool);
}

/* Get the tag pool of the tree */
_composable tag_pool_t *tp_of(tree_t *tree){
   return &((tree -> pools).tag_pool);
}

/* Get the child pool of the tree */
_composable child_pool_t *cp_of(tree_t *tree){
    return &((tree -> pools).child_pool);
}

/* Get the node pool of the tree */
_composable node_pool_t *np_of(tree_t *tree){
    return &((tree -> pools).node_pool);
}

/* Get the active point of the tree */
_composable active_point_t *ap_of(tree_t *tree){
    return &(tree -> active_point);
}

/* Get the active node of the tree */
_composable node_id_t an_of(tree_t *tree){
    return ap_of(tree) -> node;
}

/* Get the active length of the tree */
_composable uint64_t al_of(tree_t *tree){
    return ap_of(tree) -> len;
}

/* Get the active edge of the tree */
_composable str_idx_t ae_of(tree_t *tree){
    return ap_of(tree) -> edge;
}

/* Get the active edge, in char, of the tree */
_composable char ac_of(tree_t *tree){
    return ap_of(tree) -> ch;
}

/* Wrappers around various functions */
_composable str_idx_t t_add_string(tree_t *tree, char *src, uint64_t len){
    return add_string(sp_of(tree), src, len);
}

_composable char t_str_idx(tree_t *tree, str_idx_t idx){
    return str_idx(sp_of(tree), idx);
}

_composable uint64_t t_str_size(tree_t *tree){
    return str_size(sp_of(tree));
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

_composable uint64_t t_is_wanted_tag(tree_t *tree, tag_id_t tag, uint64_t type){
    return is_wanted_tag(tp_of(tree), tag, type);
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

_composable uint64_t t_len_edge(tree_t *tree, node_id_t node){
    return len_edge(np_of(tree), node);
}

_composable int t_is_leaf_node(tree_t *tree, node_id_t node){
    return is_leaf_node(np_of(tree), node);
}

/* Update suffix link if needed (i.e. last_node is present) */
_composable void maybe_update_link(tree_t *tree, node_id_t target){
    if (tree -> last_node){
        t_resolve_node(tree, tree -> last_node) -> link = target;
        tree -> last_node = 0;
    }
    return;
}

/* Walkdown the tree */
_composable int walkdown(tree_t *tree, node_id_t node){
    if ((!t_is_leaf_node(tree, node)) && \
            (t_len_edge(tree, node) <= al_of(tree))){
        ap_of(tree) -> len -= t_len_edge(tree, node);
        ap_of(tree) -> edge += t_len_edge(tree, node);
        ap_of(tree) -> ch = t_str_idx(tree, ae_of(tree));
        ap_of(tree) -> node = node;

        return 1;
    }

    return 0;
}

/* Split an edge */
static inline node_id_t split_edge(tree_t *tree, \
        node_id_t orig_node, uint64_t split_len, char split_next_ch, \
        node_id_t parent_node, char parent_ch){
    str_idx_t split_idx = t_resolve_node(tree, orig_node) -> start_idx + \
                          split_len;
    node_id_t split_node;

    if (split_idx == t_resolve_node(tree, orig_node) -> end_idx){
        /* Imaginary split of former leaf node */
        split_node = orig_node;
    }
    else{
        /* Real split */
        split_node = t_create_node(tree, parent_node, \
                t_resolve_node(tree, orig_node) -> start_idx, split_idx);
        _err_if(!split_node);

        t_change_child(tree, parent_node, parent_ch, split_node);
        t_resolve_node(tree, orig_node) -> parent = split_node;
        t_resolve_node(tree, orig_node) -> start_idx = split_idx + 1;
        _err_if(t_add_child(tree, split_node, split_next_ch, orig_node) == -1);
    }

    maybe_update_link(tree, split_node);
    tree -> last_node = split_node;

    return split_node;

error_handling:
    return 0;
}

/* Add a new char to the tree */
static inline int add_char_to_tree(tree_t *tree, str_idx_t idx, char ch, \
        str_idx_t tail_idx, uint64_t type, uint64_t id){
    (tree -> implicit_suffix)++;
    tree -> last_node = 0;

    while (tree -> implicit_suffix){
        node_id_t next_node;
        while (al_of(tree) && \
                (next_node = t_find_child(tree, an_of(tree), ac_of(tree))) && \
                walkdown(tree, next_node));

        if (!al_of(tree)){
            ap_of(tree) -> edge = idx;
            ap_of(tree) -> ch = ch;
            next_node = t_find_child(tree, an_of(tree), ch);

            if (!next_node){
                next_node = t_create_node(tree, an_of(tree), idx, tail_idx);
                _err_if(!next_node);

                maybe_update_link(tree, an_of(tree));

                _err_if(t_add_child(tree, an_of(tree), ch, next_node) == -1);
                _err_if(t_add_tag_to_node(tree, next_node, type, id) == -1);
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
                _err_if(!split_node);

                node_id_t new_node = t_create_node(tree, \
                        split_node, idx, tail_idx);
                _err_if(!new_node);
                _err_if(t_add_child(tree, split_node, ch, new_node) == -1);
                _err_if(t_add_tag_to_node(tree, new_node, type, id) == -1);
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

error_handling:
    return -1;
}

/* Add a new string to the tree */
int add_string_to_tree(tree_t *tree, str_idx_t start_idx, str_idx_t end_idx, \
        uint64_t type, uint64_t id){
    while (start_idx <= end_idx){
        char ch = t_str_idx(tree, start_idx);
        _err_if(add_char_to_tree(tree, start_idx, ch, end_idx, type, id) == -1);
        start_idx++;
    }

    while (tree -> implicit_suffix){
        node_id_t next_node;
        while (al_of(tree) && \
                (next_node = t_find_child(tree, an_of(tree), ac_of(tree))) && \
                walkdown(tree, next_node));

        if(!al_of(tree)){
            maybe_update_link(tree, an_of(tree));
            _err_if(t_add_tag_to_node(tree, an_of(tree), type, id) == -1);
        }
        else{
            _assert(next_node);
            char next_ch = t_str_idx(tree, \
                    t_resolve_node(tree, next_node) -> start_idx + al_of(tree));
            node_id_t split_node = split_edge(tree, next_node, \
                    al_of(tree) - 1, next_ch, an_of(tree), ac_of(tree));
            _err_if(!split_node);
            _err_if(t_add_tag_to_node(tree, split_node, type, id) == -1);
        }

        (tree -> implicit_suffix)--;
        if (an_of(tree) == tree -> root){
            if (al_of(tree)){
                (ap_of(tree) -> len)--;
                ap_of(tree) -> edge = end_idx - tree -> implicit_suffix + 1;
                ap_of(tree) -> ch = t_str_idx(tree, ae_of(tree));
            }
        }
        else{
            ap_of(tree) -> node = t_resolve_node(tree, an_of(tree)) -> link;
        }
    }

    _assert(!(tree -> implicit_suffix));
    _assert(an_of(tree) == tree -> root);
    _assert(!al_of(tree));

    return 0;

error_handling:
    return -1;
}

/* Find exact matches of pattern in the tree */
node_id_t basic_search(tree_t *tree, char *pattern, uint64_t size){
    node_id_t current_node = tree -> root;
    char *current_char = pattern;

    while (current_char - pattern < size){
        char ch = *(current_char++);
        if (!(current_node = t_find_child(tree, current_node, ch))){
            return 0;  /* No match */
        }

        str_idx_t current_idx = t_resolve_node(tree, \
                current_node) -> start_idx;
        while ((current_idx++ < \
                    t_resolve_node(tree, current_node) -> end_idx) && \
                (current_char - pattern < size)){
            if (*(current_char++) != t_str_idx(tree, current_idx)){
                return 0;
            }
        }
    }

    return current_node;
}


/* Set */
/* Create new set node */
set_node_t *new_set_node(uint64_t data){
    set_node_t *node = malloc(sizeof(set_node_t));
    _err_if(!node);

    node -> bf = 0;
    node -> data = data;
    node -> lchild = NULL;
    node -> rchild = NULL;

    return node;

error_handling:
    return NULL;
}

/* Similar to avl_update_child_or_root() */
_composable void set_update_child_or_root(set_t **set, set_node_t *parent, \
        set_node_t *orig_child, set_node_t *new_child){
    if (parent){
        if (parent -> lchild == orig_child){
            parent -> lchild = new_child;
        }
        else{
            parent -> rchild = new_child;
        }
    }
    else{
        *set = new_child;
    }

    return;
}

/* Insert a value into the set */
int set_insert(set_t **set, uint64_t data){
    set_node_t *node = *set;
    set_node_t *new_node;
    if (_unlikely(!node)){
        new_node = new_set_node(data);
        _err_if(!new_node);
        *set = new_node;
        return 0;
    }

    set_node_t *stack[96];  /* Enough stack for all uint64_t */
    int stack_ptr = 0;
    while (1){
        stack[stack_ptr++] = node;
        if (data == node -> data){
            return 0;
        }

        if (data < node -> data){
            if (node -> lchild){
                node = node -> lchild;
            }
            else{
                new_node = new_set_node(data);
                _err_if(!new_node);
                node -> lchild = new_node;
                break;
            }
        }
        else{
            if (node -> rchild){
                node = node -> rchild;
            }
            else{
                new_node = new_set_node(data);
                _err_if(!new_node);
                node -> rchild = new_node;
                break;
            }
        }
    }

    stack_ptr--;
    set_node_t *parent = node;
    set_node_t *hyper_parent;
    node = new_node;
    while (parent){
        if (stack_ptr){
            hyper_parent = stack[--stack_ptr];
        }
        else{
            hyper_parent = NULL;
        }

        if (parent -> lchild == node){
            if (parent -> bf == _left_heavy){
                if (node -> bf == _right_heavy){
                    /* Left-right rotate */
                    set_node_t *rchild = node -> rchild;
                    node -> rchild = rchild -> lchild;
                    parent -> lchild = rchild -> rchild;

                    rchild -> lchild = node;
                    rchild -> rchild = parent;

                    if (rchild -> bf == _left_heavy){
                        node -> bf = 0;
                        parent -> bf = _right_heavy;
                    }
                    else if (rchild -> bf == _right_heavy){
                        node -> bf = _left_heavy;
                        parent -> bf = 0;
                    }
                    rchild -> bf = 0;

                    set_update_child_or_root(set, hyper_parent, \
                            parent, rchild);
                }
                else{
                    /* Right rotate */
                    parent -> lchild = node -> rchild;
                    node -> rchild = parent;

                    parent -> bf = 0;
                    node -> bf = 0;

                    set_update_child_or_root(set, hyper_parent, \
                            parent, node);
                }

                break;
            }
            else if (parent -> bf == _right_heavy){
                parent -> bf = 0;
                break;
            }
            else{
                parent -> bf = _left_heavy;
            }
        }
        else{
            if (parent -> bf == _right_heavy){
                if (node -> bf == _left_heavy){
                    /* Right-left rotate */
                    set_node_t *lchild = node -> lchild;
                    node -> lchild = lchild -> rchild;
                    parent -> rchild = lchild -> lchild;

                    lchild -> rchild = node;
                    lchild -> lchild = parent;

                    if (lchild -> bf == _left_heavy){
                        node -> bf = _right_heavy;
                        parent -> bf = 0;
                    }
                    else if (lchild -> bf == _right_heavy){
                        node -> bf = 0;
                        parent -> bf = _left_heavy;
                    }
                    lchild -> bf = 0;

                    set_update_child_or_root(set, hyper_parent, \
                            parent, lchild);
                }
                else{
                    /* Left rotate */
                    parent -> rchild = node -> lchild;
                    node -> lchild = parent;

                    parent -> bf = 0;
                    node -> bf = 0;
                    set_update_child_or_root(set, hyper_parent, \
                            parent, node);
                }

                break;
            }
            else if (parent -> bf == _left_heavy){
                parent -> bf = 0;
                break;
            }
            else{
                parent -> bf = _right_heavy;
            }
        }

        node = parent;
        parent = hyper_parent;
    }

    return 0;

error_handling:
    return -1;
}

/* Destroy the set */
void set_destroy(set_t *set){
    rec_state_t stack[96];
    int stack_ptr = 0;

    /* Simulate recusion */
    set_node_t *node = set;
    char stage = _newly_visit;
set_destroy_rec:
    switch (stage){
        case _newly_visit:
            if (!node){
                stage = _visit_right;
                goto set_destroy_rec;
            }
            stack[stack_ptr].node = node;
            stack[stack_ptr].stage = _visit_left;
            stack_ptr++;

            node = node -> lchild;
            stage = _newly_visit;
            goto set_destroy_rec;

        case _visit_left:
            stack[stack_ptr].node = node;
            stack[stack_ptr].stage = _visit_right;
            stack_ptr++;

            node = node -> rchild;
            stage = _newly_visit;
            goto set_destroy_rec;

        case _visit_right:
            if (node){
                free(node);
            }
            if (_unlikely(!stack_ptr)){
                goto end_set_destroy_rec;
            }

            stack_ptr--;
            node = stack[stack_ptr].node;
            stage = stack[stack_ptr].stage;
            goto set_destroy_rec;
    }
    _unreachable();

end_set_destroy_rec:
    return;
}

/* Construct ruby array from set and destroy the set */
void arr_from_set(set_t *set, VALUE arr){
    rec_state_t stack[96];
    int stack_ptr = 0;

    /* Simulate recusion */
    set_node_t *node = set;
    char stage = _newly_visit;
set_destroy_rec:
    switch (stage){
        case _newly_visit:
            if (!node){
                stage = _visit_right;
                goto set_destroy_rec;
            }
            stack[stack_ptr].node = node;
            stack[stack_ptr].stage = _visit_left;
            stack_ptr++;

            node = node -> lchild;
            stage = _newly_visit;
            goto set_destroy_rec;

        case _visit_left:
            rb_ary_push(arr, ULL2NUM(node -> data));
            stack[stack_ptr].node = node;
            stack[stack_ptr].stage = _visit_right;
            stack_ptr++;

            node = node -> rchild;
            stage = _newly_visit;
            goto set_destroy_rec;

        case _visit_right:
            if (node){
                free(node);
            }
            if (_unlikely(!stack_ptr)){
                goto end_set_destroy_rec;
            }

            stack_ptr--;
            node = stack[stack_ptr].node;
            stage = stack[stack_ptr].stage;
            goto set_destroy_rec;
    }
    _unreachable();

end_set_destroy_rec:
    return;
}


/* Tree traversal */
/* Push a stack frame to the stack */
_composable int push_stack_frame(stack_frame_t **stack, \
        uint64_t *stack_ptr, uint64_t *stack_size, \
        uint64_t idx, uint64_t node_or_child, char stage){
    (*stack)[*stack_ptr].node_or_child = node_or_child;
    (*stack)[*stack_ptr].idx = idx;
    (*stack)[*stack_ptr].stage = stage;

    (*stack_ptr)++;
    if (*stack_ptr == *stack_size){
        (*stack_size) <<= 1;
        stack_frame_t *new_stack = realloc((*stack), \
                (*stack_size) * sizeof(stack_frame_t));
        _err_if(!new_stack);
        (*stack) = new_stack;
    }

    return 0;

error_handling:
    return -1;
}

/* Traverse tree and add all tags to the set */
int traverse_tree(tree_t *tree, node_id_t root, char *pattern, uint64_t size, \
        uint64_t mask, set_t **set){
   /* Branch pruning:
     *
     * An ID attached to the suffix <A><B><A><C> is also attached to <A><C>.
     * Hence, if we encounter <A> while traversing the tree, we prune that
     * branch as all tags under it will be present elsewhere too.
     *
     * KMP algorithm is used to find <A> during the traversal */
    uint64_t lps_idx = 0;
    uint64_t lps[size];
    _assert(size);
    uint64_t idx = 1;
    lps[0] = 0;
    while (idx < size){
        if (pattern[idx] == pattern[lps_idx]){
            lps_idx++;
            lps[idx] = lps_idx;
        }
        else if (lps_idx){
            lps_idx = lps[lps_idx - 1];
            continue;
        }
        else{
            lps[lps_idx] = 0;
        }
        idx++;
    }

    uint64_t stack_ptr = 0;
    uint64_t stack_size = _init_stack_size;
    stack_frame_t *stack = malloc(stack_size * sizeof(stack_frame_t));
    _err_if(!stack);

    tag_list_head_t tags;
    idx = 0;
    uint64_t node_or_child = root;
    char stage = _first_visit;
traverse_tree_rec:
    switch (stage){
        case _first_visit:
            if (_unlikely(idx == size)){
                /* Prune */
                stage = _second_visit;
                goto traverse_tree_rec;
            }

            /* Copy tags */
            tags = t_resolve_node(tree, node_or_child) -> tags;
            while (tags){
                if (t_is_wanted_tag(tree, tags, mask)){
                    _err_if(set_insert(set, \
                                t_resolve_tag(tree, tags) -> id) == -1);
                }
                tags = t_resolve_tag(tree, tags) -> next;
            }

            /* Traverse children */
            _err_if(push_stack_frame(&stack, &stack_ptr, &stack_size, \
                    idx, node_or_child, _second_visit) == -1);
            node_or_child = t_resolve_node(tree, node_or_child) -> children;
            stage = _newly_visit;
            goto traverse_child_rec;

        case _second_visit:
            if (_unlikely(!stack_ptr)){
                goto end_traverse_tree;
            }
            stack_ptr--;
            node_or_child = stack[stack_ptr].node_or_child;
            idx = stack[stack_ptr].idx;
            stage = stack[stack_ptr].stage;
            goto traverse_child_rec;
    }
    _unreachable();

traverse_child_rec:
    switch (stage){
        case _newly_visit:
            if (!node_or_child){
                stage = _visit_right;
                goto traverse_child_rec;
            }
            _err_if(push_stack_frame(&stack, &stack_ptr, &stack_size, \
                    idx, node_or_child, _done_funcall) == -1);
            while (idx){
                if (t_resolve_child(tree, node_or_child) -> ch == pattern[idx]){
                    idx++;
                    break;
                }
                idx = lps[idx - 1];
            }
            node_or_child = t_resolve_child(tree, node_or_child) -> node;
            stage = _first_visit;
            goto traverse_tree_rec;

        case _done_funcall:
            _err_if(push_stack_frame(&stack, &stack_ptr, &stack_size, \
                    idx, node_or_child, _visit_left) == -1);
            node_or_child = t_resolve_child(tree, node_or_child) -> lchild;
            stage = _newly_visit;
            goto traverse_child_rec;

        case _visit_left:
            _err_if(push_stack_frame(&stack, &stack_ptr, &stack_size, \
                    idx, node_or_child, _visit_right) == -1);
            node_or_child = t_resolve_child(tree, node_or_child) -> rchild;
            stage = _newly_visit;
            goto traverse_child_rec;

        case _visit_right:
            _assert(stack_ptr);
            stack_ptr--;
            node_or_child = stack[stack_ptr].node_or_child;
            idx = stack[stack_ptr].idx;
            stage = stack[stack_ptr].stage;
            if (stage == _second_visit){
                goto traverse_tree_rec;
            }
            else{
                goto traverse_child_rec;
            }
    }
    _unreachable();

end_traverse_tree:
    free(stack);
    return 0;

error_handling:
    free(stack);
    return -1;
}


/* Open all pools */
_composable int open_all_pools(tree_t *tree, \
        char *str_path, char *tag_path, char *child_path, char *node_path){
    if (_unlikely(pool_open(sp_of(tree), str_path) == -1)){
        return -1;
    }
    if (_unlikely(pool_open(tp_of(tree), tag_path) == -1)){
        pool_close(sp_of(tree));
        return -1;
    }
    if (_unlikely(pool_open(cp_of(tree), child_path) == -1)){
        pool_close(sp_of(tree));
        pool_close(tp_of(tree));
        return -1;
    }
    if (_unlikely(pool_open(np_of(tree), node_path) == -1)){
        pool_close(sp_of(tree));
        pool_close(tp_of(tree));
        pool_close(cp_of(tree));
        return -1;
    }
    return 0;
}

/* Sync all pools with backend files */
_composable void sync_all_pools(tree_t *tree){
    pool_sync(sp_of(tree));
    pool_sync(tp_of(tree));
    pool_sync(cp_of(tree));
    pool_sync(np_of(tree));

    return;
}

/* Close all pools */
_composable void close_all_pools(tree_t *tree){
    pool_close(sp_of(tree));
    pool_close(tp_of(tree));
    pool_close(cp_of(tree));
    pool_close(np_of(tree));

    return;
}

/* Create a blank suffix tree */
int create_tree(char *str_path, char *tag_path, \
        char *child_path, char *node_path){
    _err_if(pool_create(str_path) == -1);
    _err_if(pool_create(tag_path) == -1);
    _err_if(pool_create(child_path) == -1);
    _err_if(pool_create(node_path) == -1);

    tree_t tree;
    _err_if(open_all_pools(&tree, \
                str_path, tag_path, child_path, node_path) == -1);
    node_id_t root = create_node(np_of(&tree), 0, 0, 0, 0);
    _err_if(root != sizeof(uint64_t));

    close_all_pools(&tree);
    return 0;

error_handling:
    return -1;
}

/* Open a suffix tree */
int open_tree(tree_t *tree, \
        char *str_path, char *tag_path, char *child_path, char *node_path){
    _err_if(open_all_pools(tree, \
                str_path, tag_path, child_path, node_path) == -1);
    tree -> root = sizeof(uint64_t);
    tree -> last_node = 0;
    tree -> implicit_suffix = 0;

    ap_of(tree) -> node = tree -> root;
    ap_of(tree) -> len = 0;
    ap_of(tree) -> edge = 0;
    ap_of(tree) -> ch = 0xFF;

    return 0;

error_handling:
    return -1;
}

/* Sync the suffix tree with backend files */
void sync_tree(tree_t *tree){
    sync_all_pools(tree);
    return;
}

/* Close the suffix tree */
void close_tree(tree_t *tree){
    close_all_pools(tree);
    return;
}


/* RWLock */
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
    pthread_mutex_unlock(&(rwlock -> counter_mutex));
    return;
}

/* Unlock read locking */
void rwlock_rdunlock(rwlock_t *rwlock){
    pthread_mutex_lock(&(rwlock -> counter_mutex));
    (rwlock -> reader_counter)--;
    if (!(rwlock -> reader_counter)){
        pthread_mutex_unlock(&(rwlock -> resource_mutex));
    }
    pthread_mutex_unlock(&(rwlock -> counter_mutex));
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


/* Ruby glueware */
typedef struct suffix_tree_s{
    tree_t tree;
    rwlock_t rw_lock;
} suffix_tree_t;

void suffix_tree_t_free(void *data){
    suffix_tree_t *typed_data = data;
    close_tree(&(typed_data -> tree));
    rwlock_destroy(&(typed_data -> rw_lock));
    free(typed_data);
    return;
}

static const rb_data_type_t suffix_tree_t_type = {
    .wrap_struct_name = "suffix_tree_t",
    .function = {
        .dfree = &suffix_tree_t_free
    }
};

VALUE suffix_tree_create(VALUE self, VALUE str_path, VALUE tag_path, \
        VALUE child_path, VALUE node_path){
    if (_unlikely(create_tree(StringValueCStr(str_path), \
                    StringValueCStr(tag_path), \
                    StringValueCStr(child_path), \
                    StringValueCStr(node_path)) == -1)){
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

VALUE suffix_tree_initialize(VALUE self, VALUE str_path, VALUE tag_path, \
        VALUE child_path, VALUE node_path){
    suffix_tree_t *data;
    TypedData_Get_Struct(self, suffix_tree_t, &suffix_tree_t_type, data);

    if (_unlikely(rwlock_init(&(data -> rw_lock)) == -1)){
        rb_raise(rb_eRuntimeError, "RWLock initialization failure");
    }

    if (_unlikely(open_tree(&(data -> tree), StringValueCStr(str_path), \
                    StringValueCStr(tag_path), \
                    StringValueCStr(child_path), \
                    StringValueCStr(node_path)) == -1)){
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
    tree_t *tree;
    str_idx_t start_idx;
    str_idx_t end_idx;
    uint64_t type;
    uint64_t id;
} insert_string_args_t;

typedef struct{
    tree_t *tree;
    char *pattern_addr;
    uint64_t pattern_size;
    uint64_t mask;
    set_t *result;
} basic_search_args_t;

void *gvl_free_insert_string(void *args){
    insert_string_args_t *typed_args = args;
    _err_if(add_string_to_tree(typed_args -> tree, \
                typed_args -> start_idx, typed_args -> end_idx, \
                typed_args -> type, typed_args -> id) == -1);
    return NULL;

error_handling:
    return (void *)(0xABADCAFE);
}

void *gvl_free_basic_search(void *args){
    basic_search_args_t *typed_args = args;
    set_t *set = NULL;

    node_id_t result = basic_search(typed_args -> tree, \
            typed_args -> pattern_addr, typed_args -> pattern_size);
    _err_if(traverse_tree(typed_args -> tree, result, \
                typed_args -> pattern_addr, typed_args -> pattern_size, \
                typed_args -> mask, &set) == -1);
    typed_args -> result = set;
    return NULL;

error_handling:
    set_destroy(set);
    return (void *)(0xABADCAFE);
}

VALUE suffix_tree_sync(VALUE self){
    suffix_tree_t *data;
    TypedData_Get_Struct(self, suffix_tree_t, &suffix_tree_t_type, data);

    rb_thread_call_without_gvl(&get_rdlock, data, NULL, NULL);
    sync_tree(&(data -> tree));
    rb_thread_call_without_gvl(&release_rdlock, data, NULL, NULL);

    return Qnil;
}

VALUE suffix_tree_insert_string(VALUE self, VALUE u8string, \
        VALUE type, VALUE id){
    suffix_tree_t *data;
    TypedData_Get_Struct(self, suffix_tree_t, &suffix_tree_t_type, data);

    rb_thread_call_without_gvl(&get_wrlock, data, NULL, NULL);

    char *u8_addr = StringValuePtr(u8string);
    uint64_t u8_size = RSTRING_LEN(u8string);

    str_idx_t start_idx = t_add_string(&(data -> tree), u8_addr, u8_size);
    if (_unlikely(start_idx == -1)){
        rb_thread_call_without_gvl(&release_wrlock, data, NULL, NULL);
        rb_raise(rb_eRuntimeError, "String appending failure");
    }
    str_idx_t end_idx = t_str_size(&(data -> tree)) - 1;

    insert_string_args_t insert_string_args = {
        .tree = &(data -> tree),
        .start_idx = start_idx,
        .end_idx = end_idx,
        .type = NUM2ULL(type),
        .id = NUM2ULL(id)
    };
    void *ret = rb_thread_call_without_gvl(&gvl_free_insert_string, \
            &insert_string_args, NULL, NULL);
    rb_thread_call_without_gvl(&release_wrlock, data, NULL, NULL);

    if (_unlikely(ret)){
        rb_raise(rb_eRuntimeError, "String insertion failure");
    }

    return self;
}

VALUE suffix_tree_basic_search(VALUE self, VALUE u8pattern, VALUE type){
    suffix_tree_t *data;
    TypedData_Get_Struct(self, suffix_tree_t, &suffix_tree_t_type, data);

    uint64_t pattern_size = RSTRING_LEN(u8pattern);
    if (!pattern_size){
        return Qnil;
    }
    char *pattern_addr = malloc(pattern_size);

    if (_unlikely(!pattern_addr)){
        rb_raise(rb_eRuntimeError, "Memory allocation failure");
    }

    memcpy(pattern_addr, StringValuePtr(u8pattern), pattern_size);
    basic_search_args_t basic_search_args = {
        .tree = &(data -> tree),
        .pattern_addr = pattern_addr,
        .pattern_size = pattern_size,
        .mask = NUM2ULL(type)
    };

    rb_thread_call_without_gvl(&get_rdlock, data, NULL, NULL);
    void *ret = rb_thread_call_without_gvl(&gvl_free_basic_search, \
            &basic_search_args, NULL, NULL);
    rb_thread_call_without_gvl(&release_rdlock, data, NULL, NULL);

    free(pattern_addr);
    if (_unlikely(ret)){
        rb_raise(rb_eRuntimeError, "Search failure");
    }

    VALUE result_arr = rb_ary_new();
    arr_from_set(basic_search_args.result, result_arr);

    return result_arr;
}

void Init_suffix_tree(){
    rb_define_global_function("__suffix_tree_create!", &suffix_tree_create, 4);
    VALUE cSuffixTree = rb_define_class("SuffixTree", rb_cObject);
    rb_define_alloc_func(cSuffixTree, &suffix_tree_t_alloc);
    rb_define_method(cSuffixTree, "initialize", &suffix_tree_initialize, 4);
    rb_define_method(cSuffixTree, "sync!", &suffix_tree_sync, 0);
    rb_define_method(cSuffixTree, "insert", &suffix_tree_insert_string, 3);
    rb_define_method(cSuffixTree, "basic_search", &suffix_tree_basic_search, 2);
    return;
}
