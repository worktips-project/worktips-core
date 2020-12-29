// Copyright (c) 2017-2019, The Monero Project
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

#pragma once

#include "device.hpp"

namespace hw {

    namespace core {

        void register_all(std::map<std::string, std::unique_ptr<device>> &registry);

        class device_default : public hw::device {
        public:
            device_default();
            ~device_default();

            device_default(const device_default &device) = delete;
            device_default& operator=(const device_default &device) = delete;

            explicit operator bool() const override { return false; };

             /* ======================================================================= */
            /*                              SETUP/TEARDOWN                             */
            /* ======================================================================= */
            bool set_name(std::string_view name) override;
            std::string get_name() const override;

            bool init(void) override;
            bool release() override;

            bool connect(void) override;
            bool disconnect() override;
 
            bool set_mode(device_mode mode) override;

            device_type get_type() const override {return device_type::SOFTWARE;};

            /* ======================================================================= */
            /*  LOCKER                                                                 */
            /* ======================================================================= */ 
            void lock(void)  override;
            void unlock(void) override;
            bool try_lock(void) override;
            
            /* ======================================================================= */
            /*                             WALLET & ADDRESS                            */
            /* ======================================================================= */
            bool  get_public_address(cryptonote::account_public_address &pubkey) override;
            bool  get_secret_keys(crypto::secret_key &viewkey , crypto::secret_key &spendkey) override;
            bool  generate_chacha_key(const cryptonote::account_keys &keys, crypto::chacha_key &key, uint64_t kdf_rounds) override;
 
            /* ======================================================================= */
            /*                               SUB ADDRESS                               */
            /* ======================================================================= */
            bool  derive_subaddress_public_key(const crypto::public_key &pub, const crypto::key_derivation &derivation, const std::size_t output_index,  crypto::public_key &derived_pub) override;
            crypto::public_key  get_subaddress_spend_public_key(const cryptonote::account_keys& keys, const cryptonote::subaddress_index& index) override;
            std::vector<crypto::public_key>  get_subaddress_spend_public_keys(const cryptonote::account_keys &keys, uint32_t account, uint32_t begin, uint32_t end) override;
            cryptonote::account_public_address  get_subaddress(const cryptonote::account_keys& keys, const cryptonote::subaddress_index &index) override;
            crypto::secret_key  get_subaddress_secret_key(const crypto::secret_key &sec, const cryptonote::subaddress_index &index) override;

            /* ======================================================================= */
            /*                            DERIVATION & KEY                             */
            /* ======================================================================= */
            bool  verify_keys(const crypto::secret_key &secret_key, const crypto::public_key &public_key)  override;
            bool  scalarmultKey(rct::key & aP, const rct::key &P, const rct::key &a) override;
            bool  scalarmultBase(rct::key &aG, const rct::key &a) override;
            bool  sc_secret_add(crypto::secret_key &r, const crypto::secret_key &a, const crypto::secret_key &b) override;
            crypto::secret_key  generate_keys(crypto::public_key &pub, crypto::secret_key &sec, const crypto::secret_key& recovery_key = crypto::secret_key(), bool recover = false) override;
            bool  generate_key_derivation(const crypto::public_key &pub, const crypto::secret_key &sec, crypto::key_derivation &derivation) override;
            bool  conceal_derivation(crypto::key_derivation &derivation, const crypto::public_key &tx_pub_key, const std::vector<crypto::public_key> &additional_tx_pub_keys, const crypto::key_derivation &main_derivation, const std::vector<crypto::key_derivation> &additional_derivations) override;
            bool  derivation_to_scalar(const crypto::key_derivation &derivation, const size_t output_index, crypto::ec_scalar &res) override;
            bool  derive_secret_key(const crypto::key_derivation &derivation, const std::size_t output_index, const crypto::secret_key &sec,  crypto::secret_key &derived_sec) override;
            bool  derive_public_key(const crypto::key_derivation &derivation, const std::size_t output_index, const crypto::public_key &pub,  crypto::public_key &derived_pub) override;
            bool  secret_key_to_public_key(const crypto::secret_key &sec, crypto::public_key &pub) override;
            bool  generate_key_image(const crypto::public_key &pub, const crypto::secret_key &sec, crypto::key_image &image) override;
            bool  generate_key_image_signature(const crypto::key_image& image, const crypto::public_key& pub, const crypto::secret_key& sec, crypto::signature& sig) override;
            bool  generate_unlock_signature(const crypto::public_key& pub, const crypto::secret_key& sec, crypto::signature& sig) override;
            bool  generate_lns_signature(std::string_view signature_data, const cryptonote::account_keys& keys, const cryptonote::subaddress_index& index, crypto::signature& sig) override;


            /* ======================================================================= */
            /*                               TRANSACTION                               */
            /* ======================================================================= */

            void generate_tx_proof(const crypto::hash &prefix_hash, 
                                   const crypto::public_key &R, const crypto::public_key &A, const std::optional<crypto::public_key> &B, const crypto::public_key &D, const crypto::secret_key &r,
                                   crypto::signature &sig) override;

            bool open_tx(crypto::secret_key &tx_key, cryptonote::txversion txversion, cryptonote::txtype txtype) override;
            void get_transaction_prefix_hash(const cryptonote::transaction_prefix& tx, crypto::hash& h) override;

            bool  encrypt_payment_id(crypto::hash8 &payment_id, const crypto::public_key &public_key, const crypto::secret_key &secret_key) override;

            rct::key genCommitmentMask(const rct::key &amount_key) override;

            bool  ecdhEncode(rct::ecdhTuple & unmasked, const rct::key & sharedSec, bool short_amount) override;
            bool  ecdhDecode(rct::ecdhTuple & masked, const rct::key & sharedSec, bool short_amount) override;

            bool generate_output_ephemeral_keys(
                size_t tx_version,
                bool& found_change,
                const cryptonote::account_keys& sender_account_keys,
                const crypto::public_key& txkey_pub,
                const crypto::secret_key& tx_key,
                const cryptonote::tx_destination_entry& dst_entr,
                const std::optional<cryptonote::tx_destination_entry>& change_addr,
                size_t output_index,
                bool need_additional_txkeys,
                const std::vector<crypto::secret_key>& additional_tx_keys,
                std::vector<crypto::public_key>& additional_tx_public_keys,
                std::vector<rct::key>& amount_keys,
                crypto::public_key& out_eph_public_key) override;

            bool clsag_prehash(const std::string &blob, size_t inputs_size, size_t outputs_size, const rct::keyV &hashes, const rct::ctkeyV &outPk, rct::key &prehash) override;
            bool clsag_prepare(const rct::key &p, const rct::key &z, rct::key &I, rct::key &D, const rct::key &H, rct::key &a, rct::key &aG, rct::key &aH) override;
            bool clsag_hash(const rct::keyV &data, rct::key &hash) override;
            bool clsag_sign(const rct::key &c, const rct::key &a, const rct::key &p, const rct::key &z, const rct::key &mu_P, const rct::key &mu_C, rct::key &s) override;

            bool update_staking_tx_secret_key(crypto::secret_key& key) override;

            bool  close_tx(void) override;
        };

    }



}

