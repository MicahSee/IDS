/* Put this header file in the utils directory? */
#include <iostream>
#include <fstream>
#include <string>
#include <time.h>

#include "ids_rule.h"
#include "flow.h"

namespace {
  const char *LOG_LOCATION = "/tmp/ids.log"
}

std::string getCurrentDateTime() {
    time_t now = time(0);
    struct tm tstruct;
    char buffer[80];

    tstruct = *localtime(&now);
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %X", &tstruct);

    return std::string(buf);
}

void logRuleMatch(Flow matched_flow) {
   std::ofstream match_log(LOG_LOCATION, std::ios::out, std::ios::app);

   if (match_log.is_open()) {
       //timestamp
       match_log << getCurrentDateTime();

       //log info about the flow as well as the rule message and id
       
       match_log.close()
   }
}
