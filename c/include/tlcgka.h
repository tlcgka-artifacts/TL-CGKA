#ifndef TLCGKA_H
#define TLCGKA_H
#include <stddef.h>
#if defined(_WIN32)
#define TL_API __declspec(dllexport)
#else
#define TL_API __attribute__((visibility("default")))
#endif
#ifdef __cplusplus
extern "C" {
#endif
/* Canonical typed request: (operation: UTF-8 string, arguments: tuple).
 * Success returns a canonical value; failure returns UTF-8 error text.
 * Output belongs to caller; release with tlcgka_free(output, output_length).
 * Input is never modified. No state is installed on failed calls.
 * See API.txt for schemas. Functions may be called concurrently. */
TL_API int tlcgka_call(const unsigned char *input, size_t length, unsigned char **output,
                       size_t *output_length);
TL_API void tlcgka_free(void *output, size_t length);
TL_API const char *tlcgka_version(void);
#ifdef __cplusplus
}
#endif
#endif
