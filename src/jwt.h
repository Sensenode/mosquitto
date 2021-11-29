#ifndef JWT_H
#define JWT_H

#if defined(WITH_BRIDGE) && defined(WITH_CJSON) && defined(WITH_TLS)
char *jwt__create(char *audience, time_t issued_at, time_t expiration, char *keyfile);
#endif

#endif
