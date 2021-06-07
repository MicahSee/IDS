// A helper class that defines a TCP flow
#include "ids_rule.h"

class alignas(16) Flow {
 public:
  be32_t src_ip;
  be32_t dst_ip;
  be16_t src_port;
  be16_t dst_port;
  IDSRule *rule;
  uint32_t padding;

  Flow() : padding(0) {}

  bool operator==(const Flow &other) const {
    return memcmp(this, &other, sizeof(*this)) == 0;
  }
};
