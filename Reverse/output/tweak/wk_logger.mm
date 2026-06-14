#import <Foundation/Foundation.h>
#import <WebKit/WebKit.h>
#import "wk_logger.h"
#import "tlog.h"

static NSString * const kCaptureJS =
    @"(function(){"
    "if(window.__qnNetHooked)return;window.__qnNetHooked=true;"
    "function isT(u){return u&&(u.indexOf('passport')!==-1"
    "||u.indexOf('ucapi')!==-1||u.indexOf('vcode')!==-1"
    "||u.indexOf('register')!==-1||u.indexOf('account')!==-1);}"
    "function post(s){try{window.webkit.messageHandlers.qnLog.postMessage(s);}catch(e){}}"
    "var _f=window.fetch;"
    "if(_f)window.fetch=function(i,o){"
    "var u=typeof i==='string'?i:(i&&i.url?i.url:'');"
    "var b=o&&o.body?String(o.body).substring(0,600):'';"
    "var m=(o&&o.method)||'GET';"
    "return _f.apply(this,arguments).then(function(r){"
    "r.clone().text().then(function(t){"
    "if(isT(u))post('F '+m+' '+u+'\\nB:'+b+'\\nR:'+t.substring(0,600));});"
    "return r;});};"
    "var _oo=XMLHttpRequest.prototype.open;"
    "var _ss=XMLHttpRequest.prototype.send;"
    "XMLHttpRequest.prototype.open=function(m,u){"
    "this._qm=m;this._qu=u;return _oo.apply(this,arguments);};"
    "XMLHttpRequest.prototype.send=function(b){"
    "var s=this;"
    "if(isT(s._qu||''))this.addEventListener('load',function(){"
    "post('X '+s._qm+' '+s._qu+'\\nB:'+String(b||'').substring(0,600)"
    "+'\\nR:'+s.responseText.substring(0,600));});"
    "return _ss.apply(this,arguments);};"
    "})();";

@interface QunarWKLogHandler : NSObject <WKScriptMessageHandler>
@end

@implementation QunarWKLogHandler
- (void)userContentController:(WKUserContentController *)ucc
       didReceiveScriptMessage:(WKScriptMessage *)msg {
    @try {
        id b = msg.body;
        NSString *s = [b isKindOfClass:[NSString class]] ? b : [NSString stringWithFormat:@"%@", b];
        tlog(@"wk_net", @{@"s": s.length > 1200 ? [s substringToIndex:1200] : s});
    } @catch(id e) {}
}
@end

static __strong QunarWKLogHandler *gLogHandler;

void registerWKLogger(WKWebViewConfiguration *config) {
    if (!config) return;
    if (!gLogHandler) gLogHandler = [QunarWKLogHandler new];
    @try { [config.userContentController addScriptMessageHandler:gLogHandler name:@"qnLog"]; }
    @catch(id e) {}
    WKUserScript *s = [[WKUserScript alloc]
        initWithSource:kCaptureJS
        injectionTime:WKUserScriptInjectionTimeAtDocumentStart
        forMainFrameOnly:NO];
    [config.userContentController addUserScript:s];
}
