#include "gtest/gtest.h"

#include "common/worktips.h"
#include "cryptonote_core/worktips_name_system.h"

TEST(worktips_name_system, name_tests)
{
  struct name_test
  {
    std::string name;
    bool allowed;
  };

  name_test const worktipsnet_names[] = {
      {"a.worktips", true},
      {"domain.worktips", true},
      {"xn--tda.worktips", true},
      {"xn--Mchen-Ost-9db-u6b.worktips", true},

      {"abc.domain.worktips", false},
      {"a", false},
      {"a.loko", false},
      {"a domain name.worktips", false},
      {"-.worktips", false},
      {"a_b.worktips", false},
      {" a.worktips", false},
      {"a.worktips ", false},
      {" a.worktips ", false},
      {"localhost.worktips", false},
      {"localhost", false},
  };

  name_test const session_wallet_names[] = {
      {"Hello", true},
      {"1Hello", true},
      {"1Hello1", true},
      {"_Hello1", true},
      {"1Hello_", true},
      {"_Hello_", true},
      {"999", true},
      {"xn--tda", true},
      {"xn--Mchen-Ost-9db-u6b", true},

      {"-", false},
      {"@", false},
      {"'Hello", false},
      {"@Hello", false},
      {"[Hello", false},
      {"]Hello", false},
      {"Hello ", false},
      {" Hello", false},
      {" Hello ", false},

      {"Hello World", false},
      {"Hello\\ World", false},
      {"\"hello\"", false},
      {"hello\"", false},
      {"\"hello", false},
  };

  for (uint16_t type16 = 0; type16 < static_cast<uint16_t>(lns::mapping_type::_count); type16++)
  {
    auto type = static_cast<lns::mapping_type>(type16);
    name_test const *names = lns::is_worktipsnet_type(type) ? worktipsnet_names : session_wallet_names;
    size_t names_count     = lns::is_worktipsnet_type(type) ? worktips::char_count(worktipsnet_names) : worktips::char_count(session_wallet_names);

    for (size_t i = 0; i < names_count; i++)
    {
      name_test const &entry = names[i];
      ASSERT_EQ(lns::validate_lns_name(type, entry.name), entry.allowed) << "Values were {type=" << type << ", name=\"" << entry.name << "\"}";
    }
  }
}

TEST(worktips_name_system, value_encrypt_and_decrypt)
{
  std::string name         = "my lns name";
  lns::mapping_value value = {};
  value.len                = 32;
  memset(&value.buffer[0], 'a', value.len);

  // Encryption and Decryption success
  {
    lns::mapping_value encrypted_value = {};
    lns::mapping_value decrypted_value = {};
    ASSERT_TRUE(lns::encrypt_mapping_value(name, value, encrypted_value));
    ASSERT_TRUE(lns::decrypt_mapping_value(name, encrypted_value, decrypted_value));
    ASSERT_TRUE(value == decrypted_value);
  }

  // Decryption Fail: Encrypted value was modified
  {
    lns::mapping_value encrypted_value = {};
    ASSERT_TRUE(lns::encrypt_mapping_value(name, value, encrypted_value));

    encrypted_value.buffer[0] = 'Z';
    lns::mapping_value decrypted_value;
    ASSERT_FALSE(lns::decrypt_mapping_value(name, encrypted_value, decrypted_value));
  }

  // Decryption Fail: Name was modified
  {
    std::string name_copy = name;
    lns::mapping_value encrypted_value = {};
    ASSERT_TRUE(lns::encrypt_mapping_value(name_copy, value, encrypted_value));

    name_copy[0] = 'Z';
    lns::mapping_value decrypted_value;
    ASSERT_FALSE(lns::decrypt_mapping_value(name_copy, encrypted_value, decrypted_value));
  }
}
