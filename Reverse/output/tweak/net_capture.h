#pragma once
#import <WebKit/WebKit.h>
#ifdef __cplusplus
extern "C" {
#endif
void installNetCaptureHooks(void);
void injectCaptureScript(WKWebViewConfiguration *configuration);
NSString *captureProxyHost(void);
#ifdef __cplusplus
}
#endif
