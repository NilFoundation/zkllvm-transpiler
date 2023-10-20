//---------------------------------------------------------------------------//
// Copyright (c) 2023 Elena Tatuzova <e.tatuzova@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//
// @file Declaration of interfaces for PLONK unified addition component.
//---------------------------------------------------------------------------//

#ifndef CRYPTO3_RECURSIVE_VERIFIER_GENERATOR_HPP
#define CRYPTO3_RECURSIVE_VERIFIER_GENERATOR_HPP

#include <sstream>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include<nil/crypto3/hash/keccak.hpp>
#include<nil/crypto3/hash/sha2.hpp>

#include<nil/crypto3/hash/sha2.hpp>

namespace nil {
    namespace blueprint {
        template<typename PlaceholderParams>
        struct recursive_verifier_generator{
            using field_type = typename PlaceholderParams::field_type;
            using proof_type = nil::crypto3::zk::snark::placeholder_proof<field_type, PlaceholderParams>;

            static std::string generate_field_array2_from_64_hex_string(std::string str){
                BOOST_ASSERT_MSG(str.size() == 64, "input string must be 64 hex characters long");
                std::string first_half = str.substr(0, 32);
                std::string second_half = str.substr(32, 32);
                return  "{\"vector\": [{\"field\": \"0x" + first_half + "\"},{\"field\": \"0x" + second_half + "\"}]}";
            }

            template<typename CommitmentSchemeType>
            static inline std::string generate_commitment(typename CommitmentSchemeType::commitment_type commitment) {
                if constexpr(std::is_same<
                        CommitmentSchemeType,
                        nil::crypto3::zk::commitments::lpc_commitment_scheme<typename CommitmentSchemeType::lpc>
                    >::value
                ){
                    if constexpr(std::is_same<typename CommitmentSchemeType::lpc::merkle_hash_type, nil::crypto3::hashes::sha2<256>>::value){
                        std::stringstream out;
                        out << commitment;
                        std::cout << out.str() << " len = " << out.str().size() << std::endl;
                        return generate_field_array2_from_64_hex_string(out.str());
                    } else if constexpr(std::is_same<typename CommitmentSchemeType::lpc::merkle_hash_type, nil::crypto3::hashes::keccak_1600<256>>::value){
                        return "keccak\n";
                    } else {
                        BOOST_ASSERT_MSG(false, "unsupported merkle hash type");
                        return "unsupported merkle hash type";
                    }
                }
                BOOST_ASSERT_MSG(false, "unsupported commitment scheme type");
                return "unsupported commitment scheme type";
            }

            static inline std::string generate_input(
                std::vector<typename field_type::value_type> public_input,
                const proof_type &proof
            ){
                std::stringstream out;
                out << "[" << std::endl;
                out << "\t{\"array\":[" << std::endl;
                out << "\t\t" << generate_commitment<typename PlaceholderParams::commitment_scheme_type>(
                    proof.commitments.at(nil::crypto3::zk::snark::VARIABLE_VALUES_BATCH)
                ) << "," << std::endl;
                out << "\t\t" << generate_commitment<typename PlaceholderParams::commitment_scheme_type>(
                    proof.commitments.at(nil::crypto3::zk::snark::PERMUTATION_BATCH)
                ) << "," << std::endl;
                out << "\t\t" << generate_commitment<typename PlaceholderParams::commitment_scheme_type>(
                    proof.commitments.at(nil::crypto3::zk::snark::QUOTIENT_BATCH)
                ) << std::endl;
                out << "\t]}" << std::endl;
                out << "]" << std::endl;
                return out.str();
            }
        };
    }
}

#endif   // CRYPTO3_RECURSIVE_VERIFIER_GENERATOR_HPP