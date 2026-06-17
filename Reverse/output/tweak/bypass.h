#pragma once
#ifdef __cplusplus
extern "C" {
#endif
void installBypassHooks(void);
void installSSLBypassAlways(void);
extern volatile int32_t gVcodeActive;
#ifdef __cplusplus
}
#endif
