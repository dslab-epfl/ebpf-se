#ifndef __BPF_MAP_HELPERS__
#define __BPF_MAP_HELPERS__

#include "klee/klee.h"
#include <assert.h>
#include <malloc.h>
#include <string.h>

#define NUM_ELEMS 4
/* This is a totally random 32 bit number used as a hack to check if the key used to lookup maps 
    is the same as the one returned by bpf_get_smp_processor_id. 
    TODO: Check symbolic expression correctly. I'm worried it will need LLVM includes, which will dirty the structure */
#define RANDOM_NUM 3 

/* Array Stub */

struct ArrayStub {
  char *name;
  char *key_type;
  char *data_type;
  char *data;
  unsigned int value_size;
  unsigned int capacity;
};

void *array_allocate(char* name, char* data_type, unsigned int value_size, unsigned int max_entries) {
  struct ArrayStub *array = malloc(sizeof(struct ArrayStub));
  klee_assert(array != 0);
  array->name = malloc(strlen(name) + 1);
  strcpy(array->name, name);
  array->data_type = malloc(strlen(data_type) + 1);
  strcpy(array->data_type, data_type);
  array->data = calloc(max_entries,value_size);
  klee_assert(array->data);
  array->capacity = max_entries;
  array->value_size = value_size;
  return array;
}

void *array_lookup_elem(struct ArrayStub *array, const void *key) {
  unsigned int index = *(unsigned int *)key;
  if (index >= array->capacity)
    return NULL;
  void *val_ptr = array->data + index * array->value_size;
  return val_ptr;
}

long array_update_elem(struct ArrayStub *array, const void *key,
                       const void *value, unsigned long flags) {
  klee_assert(flags == 0);
  unsigned int index = *(unsigned int *)key;
  klee_assume(index < array->capacity);
  void *val_ptr = array->data + index * array->value_size;
  memcpy(val_ptr, value, array->value_size);
  return 0;
}

void array_reset(struct ArrayStub *array){
  klee_make_symbolic(array->data,(array->capacity * array->value_size), array->data_type);
}

/* Map Stub */

struct MapStub {
  char *name;
  char *key_type;
  char *val_type;
  /* Storing keys, values */
  char* keys_present;   /* Array storing all keys map has seen */
  char* values_present; /* Value for each key */
  unsigned int key_deleted[NUM_ELEMS]; /* 1 in nth position implies nth key has been
                                 deleted */
  unsigned int keys_cached[NUM_ELEMS]; /* 1 in nth position implies nth key is cached */
  unsigned int
      keys_seen; /* Number of unique keys seen by the map at any point in time*/

  /* Map config */
  unsigned int key_size;
  unsigned int value_size;
};

void *map_allocate(char* name, char* key_type, char* val_type, unsigned int key_size, unsigned int value_size,
                   unsigned int max_entries) {
  struct MapStub *map = malloc(sizeof(struct MapStub));
  klee_assert(map != 0);
  map->name = malloc(strlen(name) + 1);
  strcpy(map->name, name);
  map->key_type = malloc(strlen(key_type) + 1);
  strcpy(map->key_type, key_type);
  map->val_type = malloc(strlen(val_type) + 1);
  strcpy(map->val_type, val_type);
  map->key_size = key_size;
  map->value_size = value_size;
  map->keys_seen = 0;

  map->keys_present = calloc(max_entries, key_size);
  map->values_present = calloc(max_entries, value_size);
  klee_assert(map->keys_present && map->values_present);
  klee_make_symbolic(map->values_present, max_entries*value_size, map->val_type);
  for (int n = 0; n < NUM_ELEMS; ++n) {
    map->key_deleted[n] = 0;
    // To speed up symbex when prototyping stuff unrelated to exec cycles, make
    // caching concrete
    // map->keys_cached[n] = klee_int("map_keys_cached");
    map->keys_cached[n] = 0;
  }
  return map;
}

void *map_lookup_elem(struct MapStub *map, const void *key) {
  for (int n = 0; n < map->keys_seen; ++n) {
    void *key_ptr = map->keys_present + n * map->key_size;
    if (memcmp(key_ptr, key, map->key_size)) {
      if (map->key_deleted[n])
        return NULL;
      else {
        void *val_ptr = map->values_present + n * map->value_size;
        if (!(map->keys_cached[n]))
          map->keys_cached[n] = 1;
        return val_ptr;
      }
    }
  }
  klee_assert(map->keys_seen < NUM_ELEMS && "No space left in the map stub");
  
  /* Generating symbol name */
  char *sym_name = "_in_";
  char *final_sym_name = (char *)malloc(1 + strlen(map->key_type) +
                                        strlen(sym_name) + strlen(map->name));
  strcpy(final_sym_name, map->key_type);
  strcat(final_sym_name, sym_name);
  strcat(final_sym_name, map->name);
  int map_has_this_key = klee_int(final_sym_name);

  void *key_ptr = map->keys_present + map->keys_seen * map->key_size;
  memcpy(key_ptr, key, map->key_size);
  void *val_ptr = map->values_present + map->keys_seen * map->value_size;

  if (map_has_this_key) {
    map->key_deleted[map->keys_seen] = 0;
    map->keys_seen++;
    return val_ptr;
  } else {
    map->key_deleted[map->keys_seen] = 1;
    map->keys_seen++;
    return NULL;
  }
}

long map_update_elem(struct MapStub *map, const void *key, const void *value,
                     unsigned long flags) {
  if (flags > 0) {
    for (int n = 0; n < map->keys_seen; ++n) {
      void *key_ptr = map->keys_present + n * map->key_size;
      if (memcmp(key_ptr, key, map->key_size)) {
        klee_assert(map->key_deleted[n] &&
                    "Trying to insert already present key");
        map->key_deleted[n] = 0;
        void *val_ptr = map->values_present + n * map->value_size;
        memcpy(val_ptr, value, map->value_size);
        if (!(map->keys_cached[n])) { /* Branching for Symbex */
          map->keys_cached[n] = 1;
        }
        return 0;
      }
    }
  }
  klee_assert(map->keys_seen < NUM_ELEMS && "No space left in the map stub");
  void *key_ptr = map->keys_present + map->keys_seen * map->key_size;
  memcpy(key_ptr, key, map->key_size);
  void *val_ptr = map->values_present + map->keys_seen * map->value_size;
  memcpy(val_ptr, value, map->value_size);
  map->key_deleted[map->keys_seen] = 0;
  map->keys_seen++;
  return 0;
}

long map_delete_elem(struct MapStub *map, const void *key) {
  for (int n = 0; n < map->keys_seen; ++n) {
    void *key_ptr = map->keys_present + n * map->key_size;
    if (memcmp(key_ptr, key, map->key_size)) {
      klee_assert(!map->key_deleted[n] &&
                  "Trying to delete already deleted key");
      map->key_deleted[n] = 1;
      return 0;
    }
  }
  // TODO: figure out behavior when deleting nonexistent key
  klee_assert(map->keys_seen < NUM_ELEMS && "No space left in the map stub");
  void *key_ptr = map->keys_present + map->keys_seen * map->key_size;
  memcpy(key_ptr, key, map->key_size);
  map->key_deleted[map->keys_seen] = 1;
  map->keys_seen++;
  return 0;
}

/* Array of maps Stub */

struct MapofMapStub {
  char *id;
  /* Storing keys, values */
  struct bpf_map_def internal_map;
};

void *map_of_map_allocate(struct bpf_map_def* inner_map, unsigned int id) {
  struct MapofMapStub *arraymap = malloc(sizeof(struct MapofMapStub));
  klee_assert(arraymap != 0);
  arraymap->internal_map.type = inner_map->type;
  arraymap->internal_map.key_size = inner_map->key_size;
  arraymap->internal_map.value_size = inner_map->value_size;
  arraymap->internal_map.max_entries = inner_map->max_entries;
  arraymap->internal_map.map_flags = inner_map->map_flags;
  arraymap->internal_map.map_id = id;
  return arraymap;
}

void *map_of_map_lookup_elem(struct MapofMapStub *map, const void *key) {
  if (!klee_int("map in map found")) return NULL;
  klee_assert(map->internal_map.type == 1 || map->internal_map.type == 2 || map->internal_map.type == 5 || map->internal_map.type == 9 || map->internal_map.type == 27);
  return &(map->internal_map);
}

#endif /* __BPF_MAP_HELPERS__ */