/* Minimal stand-in for samba's lib/util/byteorder.h (little-endian host). */
#ifndef RSVOL_REFBENCH_BYTEORDER_H
#define RSVOL_REFBENCH_BYTEORDER_H
#include <stdint.h>
#include <string.h>
static inline uint16_t rsvol_pull16(const uint8_t *p) { uint16_t v; memcpy(&v, p, 2); return v; }
static inline uint32_t rsvol_pull32(const uint8_t *p) { uint32_t v; memcpy(&v, p, 4); return v; }
#define PULL_LE_U8(d, o) ((uint8_t)((const uint8_t *)(d))[(o)])
#define PULL_LE_U16(d, o) rsvol_pull16((const uint8_t *)(d) + (o))
#define PULL_LE_U32(d, o) rsvol_pull32((const uint8_t *)(d) + (o))
#define PUSH_LE_U8(d, o, v) (((uint8_t *)(d))[(o)] = (uint8_t)(v))
#define PUSH_LE_U16(d, o, v) do { uint16_t _v = (uint16_t)(v); memcpy((uint8_t *)(d) + (o), &_v, 2); } while (0)
#define PUSH_LE_U32(d, o, v) do { uint32_t _v = (uint32_t)(v); memcpy((uint8_t *)(d) + (o), &_v, 4); } while (0)
#endif
