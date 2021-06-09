/* Put this header file in the utils directory? */
#include <iostream>
#include <fstream>
#include <string>
#include <time.h>

namespace {
  const char *LOG_LOCATION = "/tmp/ids.log";
}

std::string getCurrentDateTime() {
    time_t now = time(0);
    struct tm tstruct;
    char buffer[80];

    tstruct = *localtime(&now);
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %X", &tstruct);

    return std::string(buffer);
}

void logRuleMatch(Flow *matched_flow, IDSRule matched_rule, unsigned int id) {
   std::ofstream match_log(LOG_LOCATION, std::ofstream::out | std::ofstream::app);

   if (match_log.is_open()) {
      //timestamp
      match_log << getCurrentDateTime();

      //log info about the flow as well as the rule message and id
      match_log << " " << ToIpv4Address(matched_flow->src_ip) << ":" << (matched_flow->src_port).raw_value();

      match_log << " -> " << ToIpv4Address(matched_flow->dst_ip) << ":" << (matched_flow->dst_port).raw_value();

      match_log << " " << id;

      match_log << " " << matched_rule.message;

      match_log << "\n";

      match_log.close();
   }
}
