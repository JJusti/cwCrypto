#ifndef __CRYPTO_BASE_H__
#define __CRYPTO_BASE_H__ 1

#include <memory>
#include <string>
#include <vector>
#include <map>
#include <list>
#include <stdint.h>

#ifndef CW_NAMESPACE_BEGIN
#define CW_NAMESPACE_BEGIN  namespace CW {
#endif // !CW_NAMESPACE_BEGIN

#ifndef CW_NAMESPACE_END
#define CW_NAMESPACE_END    }
#endif // !CW_NAMESPACE_END

#ifndef CW_CRYPTO_NAMESPACE_BEGIN
#define CW_CRYPTO_NAMESPACE_BEGIN   CW_NAMESPACE_BEGIN namespace CRYPTO {
#endif // !CW_CRYPTO_NAMESPACE_BEGIN

#ifndef CW_CRYPTO_NAMESPACE_END
#define CW_CRYPTO_NAMESPACE_END     } CW_NAMESPACE_END
#endif // !CW_CRYPTO_NAMESPACE_END

#endif
