#pragma once
#ifdef __cplusplus
extern "C" {
#endif
void initCleanHooks(void);
void clearAccountOnly(void);      // 普通退出登录：仅清账号数据，保留 GTS/设备标识
void clearQunarLoginState(void);  // 一键新机：全量清除含 GTS 数据库
#ifdef __cplusplus
}
#endif
