#ifndef __DEBUG_TAGS_H
#define __DEBUG_TAGS_H

#ifdef KLEE_VERIFICATION
#define VIGOR_TAG(name, value)                                                 \
do {                                                                         \
  static const char *name;                                                   \
  klee_make_symbolic(&name, sizeof(const char *), "vigor_tag_" #name);       \
  name = #value;                                                             \
} while (0)
#else 
#define VIGOR_TAG(name, value)
#endif


#endif /* __DEBUG_TAGS_H */