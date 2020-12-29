// Copyright (c) 2018-2020, The Worktips Project
// Copyright (c) 2014-2019, The Monero Project
// 
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
// 
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
// 
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
// 
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#pragma once
#include <boost/program_options.hpp>
#include "cryptonote_core/cryptonote_core.h"
#include "cryptonote_protocol/cryptonote_protocol_handler.h"
#include "p2p/net_node.h"
#include "rpc/core_rpc_server.h"

#include "blocks/blocks.h"
#include "rpc/core_rpc_server.h"
#include "cryptonote_core/cryptonote_core.h"
#include "cryptonote_protocol/cryptonote_protocol_handler.h"
#include "misc_log_ex.h"

#undef WORKTIPS_DEFAULT_LOG_CATEGORY
#define WORKTIPS_DEFAULT_LOG_CATEGORY "daemon"

namespace daemonize
{
class http_rpc_server
{
public:
  http_rpc_server(boost::program_options::variables_map const &vm,
             cryptonote::core &core,
             nodetool::node_server<cryptonote::t_cryptonote_protocol_handler<cryptonote::core>> &p2p,
             const bool restricted,
             const std::string &port,
             const std::string &description);
  void run();
  void stop();
  ~http_rpc_server();

  // FIXME - replace with rpc::http_server
  cryptonote::core_rpc_server m_server;
  std::string m_description;
};

class daemon {
public:
  static void init_options(boost::program_options::options_description & option_spec);

  daemon(boost::program_options::variables_map vm);
  ~daemon();

  bool run(bool interactive = false);
  void stop();

private:

  boost::program_options::variables_map vm;

  /// 💩
  using protocol_handler = cryptonote::t_cryptonote_protocol_handler<cryptonote::core>;
  using node_server = nodetool::node_server<protocol_handler>;

  // Core objects; these are in unique ptrs because we want daemon to be movable and most of these
  // are not movable, and std::unique_ptr is a sort of pre-C++17 poor man's std::optional.
  std::unique_ptr<cryptonote::core> core;
  std::unique_ptr<protocol_handler> protocol;
  std::unique_ptr<node_server> p2p;
  std::list<http_rpc_server> http_rpcs;
};

} // namespace daemonize
