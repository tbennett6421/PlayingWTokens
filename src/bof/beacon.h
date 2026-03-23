/*
 * beacon.h - Minimal Beacon API header for BOF development.
 *
 * Replace with the official beacon.h from your C2 framework if available.
 */

#ifndef BEACON_H_
#define BEACON_H_

#include <windows.h>

/* ── Output callback types ─────────────────────────────────────────── */
#define CALLBACK_OUTPUT      0x0
#define CALLBACK_OUTPUT_OEM  0x1e
#define CALLBACK_ERROR       0x0d
#define CALLBACK_OUTPUT_UTF8 0x20

/* ── Beacon output API ─────────────────────────────────────────────── */
DECLSPEC_IMPORT void    BeaconPrintf(int type, char *fmt, ...);
DECLSPEC_IMPORT void    BeaconOutput(int type, char *data, int len);

/* ── Data parser API ───────────────────────────────────────────────── */
typedef struct {
    char *original;
    char *buffer;
    int   length;
    int   size;
} datap;

DECLSPEC_IMPORT void    BeaconDataParse(datap *parser, char *buffer, int size);
DECLSPEC_IMPORT int     BeaconDataInt(datap *parser);
DECLSPEC_IMPORT short   BeaconDataShort(datap *parser);
DECLSPEC_IMPORT int     BeaconDataLength(datap *parser);
DECLSPEC_IMPORT char   *BeaconDataExtract(datap *parser, int *size);

/* ── Format API (build output buffers) ─────────────────────────────── */
typedef struct {
    char *original;
    char *buffer;
    int   length;
    int   size;
} formatp;

DECLSPEC_IMPORT void    BeaconFormatAlloc(formatp *format, int maxsz);
DECLSPEC_IMPORT void    BeaconFormatReset(formatp *format);
DECLSPEC_IMPORT void    BeaconFormatFree(formatp *format);
DECLSPEC_IMPORT void    BeaconFormatAppend(formatp *format, char *text, int len);
DECLSPEC_IMPORT void    BeaconFormatPrintf(formatp *format, char *fmt, ...);
DECLSPEC_IMPORT char   *BeaconFormatToString(formatp *format, int *size);
DECLSPEC_IMPORT void    BeaconFormatInt(formatp *format, int value);

/* ── Token / process helpers ───────────────────────────────────────── */
DECLSPEC_IMPORT BOOL    BeaconUseToken(HANDLE token);
DECLSPEC_IMPORT void    BeaconRevertToken(void);
DECLSPEC_IMPORT BOOL    BeaconIsAdmin(void);

/* ── Inline execute helpers ────────────────────────────────────────── */
DECLSPEC_IMPORT BOOL    toWideChar(char *src, wchar_t *dst, int max);

#endif /* BEACON_H_ */
