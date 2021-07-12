// Copyright (c) 2016-2017, Nefeli Networks, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// * Redistributions of source code must retain the above copyright notice, this
// list of conditions and the following disclaimer.
//
// * Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// * Neither the names of the copyright holders nor the names of their
// contributors may be used to endorse or promote products derived from this
// software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

#include "ids.h"

#include <algorithm>
#include <tuple>
#include <iostream>
#include <string>
#include <vector>

#include <hs.h>
// #include "aho_corasick_ascii.h"

#include "../utils/checksum.h"
#include "../utils/ether.h"
#include "../utils/format.h"
#include "../utils/http_parser.h"
#include "../utils/ip.h"

#include "../utils/ids_log.h"

using bess::utils::Ethernet;
using bess::utils::Ipv4;
using bess::utils::Tcp;
using bess::utils::be16_t;

const uint64_t TIME_OUT_NS = 10ull * 1000 * 1000 * 1000;  // 10 seconds

const Commands IDS::cmds = {};

namespace {
  std::map<unsigned int, IDSRule> ids_rules;
}

/* create a map of rule ids and rules. key: rule id, entry: rule struct */

static int fullScanHandler(unsigned int id, unsigned long long from,
                        unsigned long long to, unsigned int flags, void *ctx) {
  Flow *matched_flow = static_cast<Flow *>(ctx);

  auto it = ids_rules.find(id);

  if (it != ids_rules.end()) {
    logRuleMatch(matched_flow, it->second, id);
  }
 
  return 0;
}

// const bess::pb::IDSArg &arg

CommandResponse IDS::Init(const bess::pb::IDSArg &arg)
{
    /* Store IDS rules and extracts keywords and regex */
    // std::vector<std::string> keywords;
    std::vector<const char *> patterns;
    std::vector<unsigned int> rule_ids;

    for (const auto &rule : arg.rules()) {
      IDSRule new_rule = {
          .src_ip = Ipv4Prefix(rule.src_ip()),
          .dst_ip = Ipv4Prefix(rule.dst_ip()),
          .src_port = be16_t(static_cast<uint16_t>(rule.src_port())),
          .dst_port = be16_t(static_cast<uint16_t>(rule.dst_port())),
          .message = rule.message()
        };

      // rule_ids.push_back(rule.id())

      // auto content = rule.content_rule();
      // patterns.push_back(content.regex());

      // for (const auto &keyword : content.keywords()) {
      //   keywords.push_back(keyword);
      // }

      // rules_.push_back(new_rule);
      patterns.push_back(rule.regex().c_str());
      rule_ids.push_back(rule.id());

      ids_rules.insert(std::pair<unsigned int, IDSRule>(rule.id(), new_rule));
    }

    /* Aho-Corasick Initalization 
      Eventually this should take keywords associated with regex that are specified by the user
    */
    // keyword_length = keywords.size();
    // buildMatchingMachine(keywords.data(), keyword_length);

    /* Hyperscan Initalization 
      Eventually this should take regex patterns specified by the user in the .bess configuration file
    */
    hs_compile_error_t *compile_err;

    /* compile multiple regex into database for scanning */
    if (hs_compile_multi(patterns.data(), NULL, rule_ids.data(), patterns.size(), HS_MODE_BLOCK, NULL, &database,
                   &compile_err) != HS_SUCCESS) {
        hs_free_compile_error(compile_err);
        return CommandFailure(EINVAL, "error compiling regex patterns");
    }

    /* allocate scratch space to be used across many scans */
    if (hs_alloc_scratch(database, &scratch) != HS_SUCCESS) {
        hs_free_database(database);
        return CommandFailure(ENOMEM, "error allocating scratch space");
    }

    return CommandSuccess();
}

void IDS::ProcessBatch(Context *ctx, bess::PacketBatch *batch) {
  gate_idx_t igate = ctx->current_igate;

  // ! What does this do?
  // Pass reverse traffic
  if (igate == 1) {
    RunChooseModule(ctx, 1, batch);
    return;
  }

  int cnt = batch->cnt();

  for (int i = 0; i < cnt; i++) {
    bess::Packet *pkt = batch->pkts()[i];

    Ethernet *eth = pkt->head_data<Ethernet *>();
    Ipv4 *ip = reinterpret_cast<Ipv4 *>(eth + 1);

    // ! if the protocol is not TCP then don't inspect the packet
    if (ip->protocol != Ipv4::Proto::kTcp) {
      EmitPacket(ctx, pkt, 0);
      continue;
    }

    // ! What will this variable be used for?
    int ip_bytes = ip->header_length << 2;
    Tcp *tcp =
        reinterpret_cast<Tcp *>(reinterpret_cast<uint8_t *>(ip) + ip_bytes);

    Flow flow;
    flow.src_ip = ip->src;
    flow.dst_ip = ip->dst;
    flow.src_port = tcp->src_port;
    flow.dst_port = tcp->dst_port;

    // ! Some kind of timestamp?
    uint64_t now = ctx->current_ns;

    // ! <Key, Values, Hash>
    // ! Iterator is created here 
    // Find existing flow, if we have one.
    std::unordered_map<Flow, FlowRecord, FlowHash>::iterator it =
        flow_cache_.find(flow);

    /**
     * * Throw out packets from flows that have expired or been analyzed.
     * * When is a flow considered to be analyzed?
     **/

    if (it != flow_cache_.end()) {
      if (now >= it->second.ExpiryTime()) {
        // Discard old flow and start over.
        flow_cache_.erase(it);
        it = flow_cache_.end();
      }
    }

    // ! Create a new flow entry
    if (it == flow_cache_.end()) {

      // Only create a new flow entry if the flow's headers match an existing IDS rule
      bool flow_matches_rule = false;
      
      for (auto it = ids_rules.begin(); it != ids_rules.end(); it++) {
        if ((it->second).Match(flow.src_ip, flow.dst_ip, flow.src_port, flow.dst_port)) {
          flow_matches_rule = true;
        }
      }

      if (flow_matches_rule) {
        // Don't have a flow, or threw an aged one out.  If there's no
        // SYN in this packet the reconstruct code will fail.  This is
        // a common case (for any flow that got analyzed and allowed);
        // skip a pointless emplace/erase pair for such packets.
        if (tcp->flags & Tcp::Flag::kSyn) {
          std::tie(it, std::ignore) = flow_cache_.emplace(
              std::piecewise_construct, std::make_tuple(flow), std::make_tuple());
        } else {
          EmitPacket(ctx, pkt, 0);
          continue;
        }
      } else {
        EmitPacket(ctx, pkt, 0);
        continue;
      }
    }

    FlowRecord &record = it->second;
    TcpFlowReconstruct &buffer = record.GetBuffer();

    // If the reconstruct code indicates failure, treat this
    // as a flow to pass.  Note: we only get failure if there is
    // something seriously wrong; we get success if there are holes
    // in the data (in which case the contiguous_len() below is short).
    bool success = buffer.InsertPacket(pkt);
    if (!success) {
      VLOG(1) << "Reconstruction failure";
      flow_cache_.erase(it);
      EmitPacket(ctx, pkt, 0);
      continue;
    }

    // Have something on this flow; keep it alive for a while longer.
    record.SetExpiryTime(now + TIME_OUT_NS);

    EmitPacket(ctx, pkt, 0);

    if (tcp->flags & Tcp::Flag::kFin) {
      const char *buffer_data = buffer.buf();
      unsigned int buffer_length = strlen(buffer_data);

      std::cout << "Reconstructed payload: " << buffer_data << std::endl;

      // perform fast keyword scan, results will contain IDs if keywords were found in the payload
      // std::vector<int> results = searchKeywords(keyword_length, buffer_data);

      // perform full scan if any keyword is matched during the fast scan
      // if (!results.empty()) {
        if (hs_scan(database, buffer_data, buffer_length, 0, scratch, fullScanHandler, static_cast<void *>(&flow)) != HS_SUCCESS) {
            hs_free_scratch(scratch);
            hs_free_database(database);
            std::cout << "scan failed" << std::endl;
        }
      // }

    }

  }
}

std::string IDS::GetDesc() const {
  return bess::utils::Format("%zu IDS rules", ids_rules.size());
}

ADD_MODULE(IDS, "ids", "Intrusion Detection System")
