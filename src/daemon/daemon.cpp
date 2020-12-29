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
//
// Parts of this file are originally copyright (c) 2012-2013 The Cryptonote developers

#include <memory>
#include <stdexcept>
#include "misc_log_ex.h"
#if defined(PER_BLOCK_CHECKPOINT)
#include "blocks/blocks.h"
#endif
#include "rpc/daemon_handler.h"
#include "rpc/rpc_args.h"
#include "cryptonote_protocol/quorumnet.h"

#include "common/password.h"
#include "common/util.h"
#include "daemon/command_server.h"
#include "daemon/command_line_args.h"
#include "net/parse.h"
#include "net/net_ssl.h"
#include "version.h"

#include "command_server.h"
#include "daemon.h"

#include <functional>

#undef WORKTIPS_DEFAULT_LOG_CATEGORY
#define WORKTIPS_DEFAULT_LOG_CATEGORY "daemon"

namespace daemonize {

http_rpc_server::http_rpc_server(boost::program_options::variables_map const &vm,
                       cryptonote::core &core,
                       nodetool::node_server<cryptonote::t_cryptonote_protocol_handler<cryptonote::core>> &p2p,
                       const bool restricted,
                       const std::string &port,
                       const std::string &description)
: m_server{core, p2p}
, m_description{description}
{
  if (!m_server.init(vm, restricted, port))
  {
    throw std::runtime_error("Failed to initialize " + m_description + " HTTP RPC server.");
  }
}

void http_rpc_server::run()
{
  if (!m_server.run(m_server.m_max_long_poll_connections + cryptonote::core_rpc_server::DEFAULT_RPC_THREADS,
                    false /*wait - for all threads in the pool to exit when terminating*/))
  {
    throw std::runtime_error("Failed to start " + m_description + " HTTP RPC server.");
  }
}

void http_rpc_server::stop()
{
  m_server.send_stop_signal();
  m_server.timed_wait_server_stop(5000);
}

http_rpc_server::~http_rpc_server()
{
  try
  {
    m_server.deinit();
  }
  catch (...)
  {
    MERROR("Failed to deinitialize " << m_description << " RPC server...");
  }
}

static uint16_t parse_public_rpc_port(const boost::program_options::variables_map& vm)
{
  const auto& public_node_arg = cryptonote::core_rpc_server::arg_public_node;
  const bool public_node = command_line::get_arg(vm, public_node_arg);
  if (!public_node)
    return 0;

  std::string rpc_port_str;
  const auto &restricted_rpc_port = cryptonote::core_rpc_server::arg_rpc_restricted_bind_port;
  if (!command_line::is_arg_defaulted(vm, restricted_rpc_port))
    rpc_port_str = command_line::get_arg(vm, restricted_rpc_port);
  else if (command_line::get_arg(vm, cryptonote::core_rpc_server::arg_restricted_rpc))
    rpc_port_str = command_line::get_arg(vm, cryptonote::core_rpc_server::arg_rpc_bind_port);
  else
    throw std::runtime_error("restricted RPC mode is required for --" + std::string{public_node_arg.name});

  uint16_t rpc_port;
  if (!epee::string_tools::get_xtype_from_string(rpc_port, rpc_port_str))
    throw std::runtime_error("invalid RPC port " + rpc_port_str);

  const auto rpc_bind_address = command_line::get_arg(vm, cryptonote::rpc_args::descriptors().rpc_bind_ip);
  const auto address = net::get_network_address(rpc_bind_address, rpc_port);
  if (!address)
    throw std::runtime_error("failed to parse RPC bind address");
  if (address->get_zone() != epee::net_utils::zone::public_)
    throw std::runtime_error(std::string(zone_to_string(address->get_zone()))
      + " network zone is not supported, please check RPC server bind address");

  if (address->is_loopback() || address->is_local())
    MLOG_RED(el::Level::Warning, "--" << public_node_arg.name 
      << " is enabled, but RPC server " << address->str() 
      << " may be unreachable from outside, please check RPC server bind address");

  return rpc_port;
}


daemon::daemon(boost::program_options::variables_map vm_) :
    vm{std::move(vm_)},
    core{std::make_unique<cryptonote::core>()},
    protocol{std::make_unique<protocol_handler>(*core, command_line::get_arg(vm, cryptonote::arg_offline))},
    p2p{std::make_unique<node_server>(*protocol)}
{
  MGINFO_BLUE("Initializing daemon objects...");

  MGINFO("- cryptonote protocol");
  if (!protocol->init(vm))
    throw std::runtime_error("Failed to initialize cryptonote protocol.");

  MGINFO("- p2p");
  if (!p2p->init(vm))
    throw std::runtime_error("Failed to initialize p2p server.");

  // Handle circular dependencies
  protocol->set_p2p_endpoint(p2p.get());
  core->set_cryptonote_protocol(protocol.get());
  quorumnet::init_core_callbacks();

  {
    const auto restricted = command_line::get_arg(vm, cryptonote::core_rpc_server::arg_restricted_rpc);
    const auto main_rpc_port = command_line::get_arg(vm, cryptonote::core_rpc_server::arg_rpc_bind_port);
    MGINFO("- core HTTP RPC server");
    http_rpcs.emplace_back(vm, *core, *p2p, restricted, main_rpc_port, "core");
  }

  if (!command_line::is_arg_defaulted(vm, cryptonote::core_rpc_server::arg_rpc_restricted_bind_port))
  {
    auto restricted_rpc_port = command_line::get_arg(vm, cryptonote::core_rpc_server::arg_rpc_restricted_bind_port);
    MGINFO("- restricted HTTP RPC server");
    http_rpcs.emplace_back(vm, *core, *p2p, true, restricted_rpc_port, "restricted");
  }

  MGINFO_BLUE("Done daemon object initialization");
}

daemon::~daemon()
{
  MGINFO_BLUE("Deinitializing daemon objects...");

  while (!http_rpcs.empty()) {
    MGINFO("- " << http_rpcs.back().m_description << " HTTP RPC server");
    http_rpcs.pop_back();
  }

  MGINFO("- p2p");
  try {
    p2p->deinit();
  } catch (const std::exception& e) {
    MERROR("Failed to deinitialize p2p: " << e.what());
  }

  MGINFO("- core");
  try {
    core->deinit();
    core->set_cryptonote_protocol(nullptr);
  } catch (const std::exception& e) {
    MERROR("Failed to deinitialize core: " << e.what());
  }

  MGINFO("- cryptonote protocol");
  try {
    protocol->deinit();
    protocol->set_p2p_endpoint(nullptr);
  } catch (const std::exception& e) {
    MERROR("Failed to stop cryptonote protocol: " << e.what());
  }
  MGINFO_BLUE("Deinitialization complete");
}

void daemon::init_options(boost::program_options::options_description& option_spec)
{
  cryptonote::core::init_options(option_spec);
  node_server::init_options(option_spec);
  cryptonote::core_rpc_server::init_options(option_spec);
}

bool daemon::run(bool interactive)
{
  if (!core)
    throw std::runtime_error{"Can't run stopped daemon"};

  std::atomic<bool> stop_sig(false), shutdown(false);
  boost::thread stop_thread = boost::thread([&stop_sig, &shutdown, this] {
    while (!stop_sig)
      epee::misc_utils::sleep_no_w(100);
    if (shutdown)
      stop();
  });

  WORKTIPS_DEFER
  {
    stop_sig = true;
    stop_thread.join();
  };

  tools::signal_handler::install([&stop_sig, &shutdown](int) { stop_sig = true; shutdown = true; });

  try
  {
    MGINFO_BLUE("Starting up worktipsd services...");
    cryptonote::GetCheckpointsCallback get_checkpoints;
#if defined(PER_BLOCK_CHECKPOINT)
    get_checkpoints = blocks::GetCheckpointsData;
#endif
    MGINFO("Starting core");
    if (!core->init(vm, nullptr, get_checkpoints))
      throw std::runtime_error("Failed to start core");

    for(auto& rpc: http_rpcs)
    {
      MGINFO("Starting " << rpc.m_description << " HTTP RPC server");
      rpc.run();
    }

    // FIXME: this is wonky and needs fixing: if we have no RPC server, then we also get no ability
    // to process commands, even in the interactive daemon.  It also means a core RPC server needs
    // to be usable without having a bound port.
    std::unique_ptr<daemonize::command_server> rpc_commands;
    if (interactive && http_rpcs.size())
    {
      MGINFO("Starting command-line processor");
      rpc_commands = std::make_unique<daemonize::command_server>(http_rpcs.front().m_server);
      rpc_commands->start_handling([this] { stop(); });
    }

    MGINFO("Starting RPC daemon handler");
    cryptonote::rpc::DaemonHandler rpc_daemon_handler(*core, *p2p);

    if (uint16_t public_rpc_port = parse_public_rpc_port(vm))
    {
      MGINFO("Public RPC port " << public_rpc_port << " will be advertised to other peers over P2P");
      p2p->set_rpc_port(public_rpc_port);
    }

    MGINFO_GREEN("Starting up main network");
    p2p->run(); // blocks until p2p goes down
    MGINFO_YELLOW("Main network stopped");

    if (rpc_commands)
    {
      MGINFO("Stopping RPC command processor");
      rpc_commands->stop_handling();
    }

    for (auto& rpc : http_rpcs)
    {
      MGINFO("Stopping " << rpc.m_description << " HTTP RPC server...");
      rpc.stop();
    }

    MGINFO("Node stopped.");
    return true;
  }
  catch (std::exception const& ex)
  {
    MFATAL(ex.what());
    return false;
  }
  catch (...)
  {
    MFATAL("Unknown exception occured!");
    return false;
  }
}

void daemon::stop()
{
  if (!core)
    throw std::logic_error{"Can't send stop signal to a stopped daemon"};

  p2p->send_stop_signal(); // Make p2p stop so that `run()` above continues with tear down
}

} // namespace daemonize
