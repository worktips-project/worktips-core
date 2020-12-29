// Copyright (c) 2014-2019, The Monero Project
// Copyright (c)      2019, The Worktips Project
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

#include <sstream>
#include <numeric>
#include <boost/algorithm/string.hpp>
#include "misc_language.h"
#include "syncobj.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "cryptonote_core/cryptonote_tx_utils.h"
#include "file_io_utils.h"
#include "common/command_line.h"
#include "common/util.h"
#include "string_coding.h"
#include "string_tools.h"
#include "storages/portable_storage_template_helper.h"

#undef WORKTIPS_DEFAULT_LOG_CATEGORY
#define WORKTIPS_DEFAULT_LOG_CATEGORY "miner"

#define AUTODETECT_WINDOW 10 // seconds
#define AUTODETECT_GAIN_THRESHOLD 1.02f  // 2%

#include "miner.h"

extern "C" void rx_slow_hash_allocate_state();
extern "C" void rx_slow_hash_free_state();

namespace cryptonote
{

  namespace
  {
    const command_line::arg_descriptor<std::string> arg_extra_messages =  {"extra-messages-file", "Specify file for extra messages to include into coinbase transactions", "", true};
    const command_line::arg_descriptor<std::string> arg_start_mining =    {"start-mining", "Specify wallet address to mining for", "", true};
    const command_line::arg_descriptor<uint32_t>      arg_mining_threads =  {"mining-threads", "Specify mining threads count", 0, true};
  }


  miner::miner(i_miner_handler* phandler, Blockchain* pbc):m_stop(1),
    m_template{},
    m_template_no(0),
    m_diffic(0),
    m_thread_index(0),
    m_phandler(phandler),
    m_pbc(pbc),
    m_height(0),
    m_threads_active(0),
    m_pausers_count(0),
    m_threads_total(0),
    m_starter_nonce(0),
    m_last_hr_merge_time(0),
    m_hashes(0),
    m_total_hashes(0),
    m_do_print_hashrate(false),
    m_do_mining(false),
    m_current_hash_rate(0)
  {
    m_attrs.set_stack_size(THREAD_STACK_SIZE);
  }
  //-----------------------------------------------------------------------------------------------------
  miner::~miner()
  {
    try { stop(); }
    catch (...) { /* ignore */ }
  }
  //-----------------------------------------------------------------------------------------------------
  bool miner::set_block_template(const block& bl, const difficulty_type& di, uint64_t height)
  {
    CRITICAL_REGION_LOCAL(m_template_lock);
    m_template = bl;
    m_diffic = di;
    m_height = height;
    ++m_template_no;
    m_starter_nonce = crypto::rand<uint32_t>();
    return true;
  }
  //-----------------------------------------------------------------------------------------------------
  bool miner::on_block_chain_update()
  {
    if(!is_mining())
      return true;

    return request_block_template();
  }
  //-----------------------------------------------------------------------------------------------------
  bool miner::request_block_template()
  {
    block bl;
    difficulty_type di{};
    uint64_t height{};
    uint64_t expected_reward; //only used for RPC calls - could possibly be useful here too?

    cryptonote::blobdata extra_nonce;
    if(m_extra_messages.size() && m_config.current_extra_message_index < m_extra_messages.size())
    {
      extra_nonce = m_extra_messages[m_config.current_extra_message_index];
    }

    if(!m_phandler->get_block_template(bl, m_mine_address, di, height, expected_reward, extra_nonce))
    {
      LOG_ERROR("Failed to get_block_template(), stopping mining");
      return false;
    }
    set_block_template(bl, di, height);
    return true;
  }
  //-----------------------------------------------------------------------------------------------------
  bool miner::on_idle()
  {
    m_update_block_template_interval.do_call([&](){
      if(is_mining())request_block_template();
      return true;
    });

    m_update_merge_hr_interval.do_call([&](){
      merge_hr();
      return true;
    });

    m_autodetect_interval.do_call([&](){
      update_autodetection();
      return true;
    });

    return true;
  }
  //-----------------------------------------------------------------------------------------------------
  void miner::do_print_hashrate(bool do_hr)
  {
    m_do_print_hashrate = do_hr;
  }
  //-----------------------------------------------------------------------------------------------------
  void miner::merge_hr()
  {
    if(m_last_hr_merge_time && is_mining())
    {
      m_current_hash_rate = m_hashes * 1000 / ((epee::misc_utils::get_tick_count() - m_last_hr_merge_time + 1));
      CRITICAL_REGION_LOCAL(m_last_hash_rates_lock);
      m_last_hash_rates.push_back(m_current_hash_rate);
      if(m_last_hash_rates.size() > 19)
        m_last_hash_rates.pop_front();
      if(m_do_print_hashrate)
      {
        uint64_t total_hr = std::accumulate(m_last_hash_rates.begin(), m_last_hash_rates.end(), 0);
        float hr = static_cast<float>(total_hr)/static_cast<float>(m_last_hash_rates.size());
        const auto flags = std::cout.flags();
        const auto precision = std::cout.precision();
        std::cout << "hashrate: " << std::setprecision(4) << std::fixed << hr << std::setiosflags(flags) << std::setprecision(precision) << std::endl;
      }
    }
    m_last_hr_merge_time = epee::misc_utils::get_tick_count();
    m_hashes = 0;
  }
  //-----------------------------------------------------------------------------------------------------
  void miner::update_autodetection()
  {
    if (m_threads_autodetect.empty())
      return;

    uint64_t now = epee::misc_utils::get_ns_count();
    uint64_t dt = now - m_threads_autodetect.back().first;
    if (dt < AUTODETECT_WINDOW * 1000000000ull)
      return;

    // work out how many more hashes we got
    m_threads_autodetect.back().first = dt;
    uint64_t dh = m_total_hashes - m_threads_autodetect.back().second;
    m_threads_autodetect.back().second = dh;
    float hs = dh / (dt / (float)1000000000);
    MGINFO("Mining autodetection: " << m_threads_autodetect.size() << " threads: " << hs << " H/s");

    // when we don't increase by at least 2%, stop, otherwise check next
    // if N and N+1 have mostly the same hash rate, we want to "lighter" one
    bool found = false;
    if (m_threads_autodetect.size() > 1)
    {
      int previdx = m_threads_autodetect.size() - 2;
      float previous_hs = m_threads_autodetect[previdx].second / (m_threads_autodetect[previdx].first / (float)1000000000);
      if (previous_hs > 0 && hs / previous_hs < AUTODETECT_GAIN_THRESHOLD)
      {
        m_threads_total = m_threads_autodetect.size() - 1;
        m_threads_autodetect.clear();
        MGINFO("Optimal number of threads seems to be " << m_threads_total);
        found = true;
      }
    }

    if (!found)
    {
      // setup one more thread
      m_threads_autodetect.push_back({now, m_total_hashes});
      m_threads_total = m_threads_autodetect.size();
    }

    // restart all threads
    {
      CRITICAL_REGION_LOCAL(m_threads_lock);
      m_stop = true;
      while (m_threads_active > 0)
        epee::misc_utils::sleep_no_w(100);
      m_threads.clear();
    }
    m_stop = false;
    m_thread_index = 0;
    for(size_t i = 0; i != m_threads_total; i++)
      m_threads.push_back(boost::thread(m_attrs, boost::bind(&miner::worker_thread, this, false)));
  }
  //-----------------------------------------------------------------------------------------------------
  void miner::init_options(boost::program_options::options_description& desc)
  {
    command_line::add_arg(desc, arg_extra_messages);
    command_line::add_arg(desc, arg_start_mining);
    command_line::add_arg(desc, arg_mining_threads);
  }
  //-----------------------------------------------------------------------------------------------------
  bool miner::init(const boost::program_options::variables_map& vm, network_type nettype)
  {
    if(command_line::has_arg(vm, arg_extra_messages))
    {
      std::string buff;
      bool r = epee::file_io_utils::load_file_to_string(command_line::get_arg(vm, arg_extra_messages), buff);
      CHECK_AND_ASSERT_MES(r, false, "Failed to load file with extra messages: " << command_line::get_arg(vm, arg_extra_messages));
      std::vector<std::string> extra_vec;
      boost::split(extra_vec, buff, boost::is_any_of("\n"), boost::token_compress_on );
      m_extra_messages.resize(extra_vec.size());
      for(size_t i = 0; i != extra_vec.size(); i++)
      {
        epee::string_tools::trim(extra_vec[i]);
        if(!extra_vec[i].size())
          continue;
        std::string buff = epee::string_encoding::base64_decode(extra_vec[i]);
        if(buff != "0")
          m_extra_messages[i] = buff;
      }
      m_config_folder_path = boost::filesystem::path(command_line::get_arg(vm, arg_extra_messages)).parent_path().string();
      m_config = {};
      const std::string filename = m_config_folder_path + "/" + MINER_CONFIG_FILE_NAME;
      CHECK_AND_ASSERT_MES(epee::serialization::load_t_from_json_file(m_config, filename), false, "Failed to load data from " << filename);
      MINFO("Loaded " << m_extra_messages.size() << " extra messages, current index " << m_config.current_extra_message_index);
    }

    if(command_line::has_arg(vm, arg_start_mining))
    {
      address_parse_info info;
      if(!cryptonote::get_account_address_from_str(info, nettype, command_line::get_arg(vm, arg_start_mining)) || info.is_subaddress)
      {
        LOG_ERROR("Target account address " << command_line::get_arg(vm, arg_start_mining) << " has wrong format, starting daemon canceled");
        return false;
      }
      m_mine_address = info.address;
      m_threads_total = 1;
      m_do_mining = true;
      if(command_line::has_arg(vm, arg_mining_threads))
      {
        m_threads_total = command_line::get_arg(vm, arg_mining_threads);
      }
    }

    return true;
  }
  //-----------------------------------------------------------------------------------------------------
  bool miner::is_mining() const
  {
    return !m_stop;
  }
  //-----------------------------------------------------------------------------------------------------
  const account_public_address& miner::get_mining_address() const
  {
    return m_mine_address;
  }
  //-----------------------------------------------------------------------------------------------------
  uint32_t miner::get_threads_count() const {
    return m_threads_total;
  }
  //-----------------------------------------------------------------------------------------------------
  bool miner::start(const account_public_address& adr, size_t threads_count, uint64_t stop_after, bool slow_mining)
  {
    m_mine_address = adr;
    m_threads_total = static_cast<uint32_t>(threads_count);
    if (threads_count == 0)
    {
      m_threads_autodetect.clear();
      m_threads_autodetect.push_back({epee::misc_utils::get_ns_count(), m_total_hashes});
      m_threads_total = 1;
    }
    m_starter_nonce = crypto::rand<uint32_t>();
    CRITICAL_REGION_LOCAL(m_threads_lock);
    if(is_mining())
    {
      LOG_ERROR("Starting miner but it's already started");
      return false;
    }

    if(!m_threads.empty())
    {
      LOG_ERROR("Unable to start miner because there are active mining threads");
      return false;
    }

    request_block_template();//lets update block template

    m_stop = false;
    m_thread_index = 0;
    m_stop_height = stop_after ? m_height + stop_after : std::numeric_limits<uint64_t>::max();
    if (stop_after)
      MGINFO("Mining until height " << m_stop_height);
    
    for(size_t i = 0; i != m_threads_total; i++)
    {
      m_threads.push_back(boost::thread(m_attrs, boost::bind(&miner::worker_thread, this, slow_mining)));
    }

    if (threads_count == 0)
      MINFO("Mining has started, autodetecting optimal number of threads, good luck!" );
    else
      MINFO("Mining has started with " << threads_count << " threads, good luck!" );

    return true;
  }
  //-----------------------------------------------------------------------------------------------------
  uint64_t miner::get_speed() const
  {
    if(is_mining()) {
      return m_current_hash_rate;
    }
    else {
      return 0;
    }
  }
  //-----------------------------------------------------------------------------------------------------
  void miner::send_stop_signal()
  {
    m_stop = true;
  }
  extern "C" void rx_stop_mining(void);
  //-----------------------------------------------------------------------------------------------------
  bool miner::stop()
  {
    MTRACE("Miner has received stop signal");

    CRITICAL_REGION_LOCAL(m_threads_lock);
    bool mining = !m_threads.empty();
    if (!mining)
    {
      MTRACE("Not mining - nothing to stop" );
      return true;
    }

    send_stop_signal();

    MINFO("Mining has been stopped, " << m_threads.size() << " finished" );
    m_threads.clear();
    m_threads_autodetect.clear();
    rx_stop_mining();
    return true;
  }
  //-----------------------------------------------------------------------------------------------------
  bool miner::find_nonce_for_given_block(const Blockchain *pbc, block& bl, const difficulty_type& diffic, uint64_t height)
  {
    for(; bl.nonce != std::numeric_limits<uint32_t>::max(); bl.nonce++)
    {
      crypto::hash h;
      get_block_longhash(pbc, bl, h, height, tools::get_max_concurrency());

      if(check_hash(h, diffic))
      {
        bl.invalidate_hashes();
        return true;
      }
    }
    bl.invalidate_hashes();
    return false;
  }
  //-----------------------------------------------------------------------------------------------------
  void miner::on_synchronized()
  {
    if(m_do_mining)
    {
      start(m_mine_address, m_threads_total);
    }
  }
  //-----------------------------------------------------------------------------------------------------
  void miner::pause()
  {
    CRITICAL_REGION_LOCAL(m_miners_count_lock);
    MDEBUG("miner::pause: " << m_pausers_count << " -> " << (m_pausers_count + 1));
    ++m_pausers_count;
    if(m_pausers_count == 1 && is_mining())
      MDEBUG("MINING PAUSED");
  }
  //-----------------------------------------------------------------------------------------------------
  void miner::resume()
  {
    CRITICAL_REGION_LOCAL(m_miners_count_lock);
    MDEBUG("miner::resume: " << m_pausers_count << " -> " << (m_pausers_count - 1));
    --m_pausers_count;
    if(m_pausers_count < 0)
    {
      m_pausers_count = 0;
      MERROR("Unexpected miner::resume() called");
    }
    if(!m_pausers_count && is_mining())
      MDEBUG("MINING RESUMED");
  }
  //-----------------------------------------------------------------------------------------------------
  bool miner::worker_thread(bool slow_mining)
  {
    uint32_t th_local_index = m_thread_index++;
    MLOG_SET_THREAD_NAME(std::string("[miner ") + std::to_string(th_local_index) + "]");
    MGINFO("Miner thread was started ["<< th_local_index << "]");
    uint32_t nonce = m_starter_nonce + th_local_index;
    uint64_t height = 0;
    difficulty_type local_diff = 0;
    uint32_t local_template_ver = 0;
    block b;
    rx_slow_hash_allocate_state();
    ++m_threads_active;
    bool call_stop = false;
#if defined(WORKTIPS_ENABLE_INTEGRATION_TEST_HOOKS)
    call_stop = true;
#endif

    while(!m_stop)
    {
      if(m_pausers_count)//anti split workaround
      {
        epee::misc_utils::sleep_no_w(100);
        continue;
      }

      if(local_template_ver != m_template_no)
      {
        CRITICAL_REGION_BEGIN(m_template_lock);
        b = m_template;
        local_diff = m_diffic;
        height = m_height;
        CRITICAL_REGION_END();
        local_template_ver = m_template_no;
        nonce = m_starter_nonce + th_local_index;
      }

      if(!local_template_ver)//no any set_block_template call
      {
        LOG_PRINT_L2("Block template not set yet");
        epee::misc_utils::sleep_no_w(1000);
        continue;
      }

      if (height >= m_stop_height)
      {
        m_stop = true;
        call_stop = true;
        break;
      }

      b.nonce = nonce;
      crypto::hash h;
      get_block_longhash(m_pbc, b, h, height, slow_mining ? 0 : tools::get_max_concurrency());

      if(check_hash(h, local_diff))
      {
        //we lucky!
        ++m_config.current_extra_message_index;
        MGINFO_GREEN("Found block " << get_block_hash(b) << " at height " << height << " for difficulty: " << local_diff);
        cryptonote::block_verification_context bvc;
        if(!m_phandler->handle_block_found(b, bvc) || !bvc.m_added_to_main_chain)
        {
          --m_config.current_extra_message_index;
        }else
        {
          //success update, lets update config
          if (!m_config_folder_path.empty())
            epee::serialization::store_t_to_json_file(m_config, m_config_folder_path + "/" + MINER_CONFIG_FILE_NAME);
        }

#if defined(WORKTIPS_ENABLE_INTEGRATION_TEST_HOOKS)
        if (m_debug_mine_singular_block)
        {
          m_debug_mine_singular_block = false;
          break;
        }
#endif
      }

      nonce+=m_threads_total;
      ++m_hashes;
      ++m_total_hashes;
    }
    rx_slow_hash_free_state();
    MGINFO("Miner thread stopped ["<< th_local_index << "]");
    --m_threads_active;
    if (call_stop)
      stop();
    return true;
  }
}
