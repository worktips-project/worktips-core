#include "cryptonote_config.h"
#include "common/worktips.h"
#include "int-util.h"
#include <vector>
#include <boost/lexical_cast.hpp>
#include <cfenv>

#include "service_node_rules.h"

namespace service_nodes {

// TODO(worktips): Move to worktips_economy, this will also need access to worktips::exp2
uint64_t get_staking_requirement(cryptonote::network_type m_nettype, uint64_t height, uint8_t hf_version)
{
  if (m_nettype == cryptonote::TESTNET || m_nettype == cryptonote::FAKECHAIN)
      return COIN * 100;

  if (hf_version >= cryptonote::network_version_13_enforce_checkpoints)
  {
    constexpr int64_t heights[] = {
        167000,
		210200,
		253400,
		296600,
		339800,
		383000,
		426200,
		469400,
		512600,
		555800,
		599000,
		642200,
		685400,
    };

    constexpr int64_t lsr[] = {
        60458380815527,
        58332319724305,
        56438564443912,
        54729190407764,
        52166159862153,
        50719282221956,
        48364595203882,
        46083079931076,
        44859641110978,
        42682297601941,
        39541539965538,
        37429820555489,
        35000000000000,
    };

    assert(height >= heights[0]);
    constexpr uint64_t LAST_HEIGHT      = heights[worktips::array_count(heights) - 1];
    constexpr uint64_t LAST_REQUIREMENT = lsr    [worktips::array_count(lsr) - 1];
    if (height >= LAST_HEIGHT)
        return LAST_REQUIREMENT;

    size_t i = 0;
    for (size_t index = 1; index < worktips::array_count(heights); index++)
    {
      if (heights[index] > static_cast<int64_t>(height))
      {
        i = (index - 1);
        break;
      }
    }

    int64_t H      = height;
    int64_t result = lsr[i] + (H - heights[i]) * ((lsr[i + 1] - lsr[i]) / (heights[i + 1] - heights[i]));
    return static_cast<uint64_t>(result);
  }

  uint64_t hardfork_height = m_nettype == cryptonote::MAINNET ? 54689 : 96210 /* stagenet */;
  if (height < hardfork_height) height = hardfork_height;

  uint64_t height_adjusted = height - hardfork_height;
  uint64_t base = 0, variable = 0;
  std::fesetround(FE_TONEAREST);
  if (hf_version >= cryptonote::network_version_11_infinite_staking)
  {
    base     = 150000 * COIN;
    variable = (250007.0 * COIN) / worktips::exp2(height_adjusted/129600.0);
  }
  else
  {
    base      = 100000 * COIN;
    variable  = (350000.0 * COIN) / worktips::exp2(height_adjusted/129600.0);
  }

  uint64_t result = base + variable;
  return result;
}

uint64_t portions_to_amount(uint64_t portions, uint64_t staking_requirement)
{
  uint64_t hi, lo, resulthi, resultlo;
  lo = mul128(staking_requirement, portions, &hi);
  div128_64(hi, lo, STAKING_PORTIONS, &resulthi, &resultlo);
  return resultlo;
}

bool check_service_node_portions(uint8_t hf_version, const std::vector<uint64_t>& portions)
{
  if (portions.size() > MAX_NUMBER_OF_CONTRIBUTORS) return false;

  uint64_t reserved = 0;
  for (auto i = 0u; i < portions.size(); ++i)
  {
    const uint64_t min_portions = get_min_node_contribution(hf_version, STAKING_PORTIONS, reserved, i);
    if (portions[i] < min_portions) return false;
    reserved += portions[i];
  }

  return reserved <= STAKING_PORTIONS;
}

crypto::hash generate_request_stake_unlock_hash(uint32_t nonce)
{
  crypto::hash result   = {};
  char const *nonce_ptr = (char *)&nonce;
  char *hash_ptr        = result.data;
  static_assert(sizeof(result) % sizeof(nonce) == 0, "The nonce should be evenly divisible into the hash");
  for (size_t i = 0; i < sizeof(result) / sizeof(nonce); ++i)
  {
    memcpy(hash_ptr, nonce_ptr, sizeof(nonce));
    hash_ptr += sizeof(nonce);
  }

  assert(hash_ptr == (char *)result.data + sizeof(result));
  return result;
}

uint64_t get_locked_key_image_unlock_height(cryptonote::network_type nettype, uint64_t node_register_height, uint64_t curr_height)
{
  uint64_t blocks_to_lock = staking_num_lock_blocks(nettype);
  uint64_t result         = curr_height + (blocks_to_lock / 2);
  return result;
}

static uint64_t get_min_node_contribution_pre_v11(uint64_t staking_requirement, uint64_t total_reserved)
{
  return std::min(staking_requirement - total_reserved, staking_requirement / MAX_NUMBER_OF_CONTRIBUTORS);
}

uint64_t get_min_node_contribution(uint8_t version, uint64_t staking_requirement, uint64_t total_reserved, size_t num_contributions)
{
  if (version < cryptonote::network_version_11_infinite_staking)
    return get_min_node_contribution_pre_v11(staking_requirement, total_reserved);

  const uint64_t needed = staking_requirement - total_reserved;
  assert(MAX_NUMBER_OF_CONTRIBUTORS > num_contributions);
  if (MAX_NUMBER_OF_CONTRIBUTORS <= num_contributions) return UINT64_MAX;

  const size_t num_contributions_remaining_avail = MAX_NUMBER_OF_CONTRIBUTORS - num_contributions;
  return needed / num_contributions_remaining_avail;
}

uint64_t get_min_node_contribution_in_portions(uint8_t version, uint64_t staking_requirement, uint64_t total_reserved, size_t num_contributions)
{
  uint64_t atomic_amount = get_min_node_contribution(version, staking_requirement, total_reserved, num_contributions);
  uint64_t result        = (atomic_amount == UINT64_MAX) ? UINT64_MAX : (get_portions_to_make_amount(staking_requirement, atomic_amount));
  return result;
}

uint64_t get_portions_to_make_amount(uint64_t staking_requirement, uint64_t amount)
{
  uint64_t lo, hi, resulthi, resultlo;
  lo = mul128(amount, STAKING_PORTIONS, &hi);
  if (lo > UINT64_MAX - (staking_requirement - 1))
    hi++;
  lo += staking_requirement-1;
  div128_64(hi, lo, staking_requirement, &resulthi, &resultlo);
  return resultlo;
}

static bool get_portions_from_percent(double cur_percent, uint64_t& portions) {
  if(cur_percent < 0.0 || cur_percent > 100.0) return false;

  // Fix for truncation issue when operator cut = 100 for a pool Service Node.
  if (cur_percent == 100.0)
  {
    portions = STAKING_PORTIONS;
  }
  else
  {
    portions = (cur_percent / 100.0) * STAKING_PORTIONS;
  }

  return true;
}

bool get_portions_from_percent_str(std::string cut_str, uint64_t& portions) {

  if(!cut_str.empty() && cut_str.back() == '%')
  {
    cut_str.pop_back();
  }

  double cut_percent;
  try
  {
    cut_percent = boost::lexical_cast<double>(cut_str);
  }
  catch(...)
  {
    return false;
  }

  return get_portions_from_percent(cut_percent, portions);
}

} // namespace service_nodes
