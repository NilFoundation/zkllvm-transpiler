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
#include <nil/crypto3/algebra/random_element.hpp>

#include<nil/blueprint/transpiler/templates/recursive_verifier.hpp>

namespace nil {
    namespace blueprint {
        template<typename PlaceholderParams>
        struct recursive_verifier_generator{
            using field_type = typename PlaceholderParams::field_type;
            using arithmetization_params = typename PlaceholderParams::arithmetization_params;
            using proof_type = nil::crypto3::zk::snark::placeholder_proof<field_type, PlaceholderParams>;
            using common_data_type = typename nil::crypto3::zk::snark::placeholder_public_preprocessor<field_type, PlaceholderParams>::preprocessed_data_type::common_data_type;
            using verification_key_type = typename common_data_type::verification_key_type;
            using commitment_scheme_type = typename PlaceholderParams::commitment_scheme_type;
            using constraint_system_type = typename PlaceholderParams::constraint_system_type;

            static std::string generate_field_array2_from_64_hex_string(std::string str){
                BOOST_ASSERT_MSG(str.size() == 64, "input string must be 64 hex characters long");
                std::string first_half = str.substr(0, 32);
                std::string second_half = str.substr(32, 32);
                return  "{\"vector\": [{\"field\": \"0x" + first_half + "\"},{\"field\": \"0x" + second_half + "\"}]}";
            }

            template<typename HashType>
            static inline std::string generate_hash(typename HashType::digest_type hashed_data){
                if constexpr(std::is_same<HashType, nil::crypto3::hashes::sha2<256>>::value){
                    std::stringstream out;
                    out << hashed_data;
                    return generate_field_array2_from_64_hex_string(out.str());
                }  else if constexpr(nil::crypto3::hashes::is_poseidon<HashType>::value){
                    //std::cout << "Poseidon" << std::endl
                    std::stringstream out;
                    out << "{\"field\": \"" <<  hashed_data <<  "\"}";
                    return out.str();
                } else if constexpr(std::is_same<HashType, nil::crypto3::hashes::keccak_1600<256>>::value){
                    return "keccak\n";
                }
                BOOST_ASSERT_MSG(false, "unsupported merkle hash type");
                return "unsupported merkle hash type";
            }

            template<typename CommitmentSchemeType>
            static inline std::string generate_commitment(typename CommitmentSchemeType::commitment_type commitment) {
                if constexpr(std::is_same<
                        CommitmentSchemeType,
                        nil::crypto3::zk::commitments::lpc_commitment_scheme<typename CommitmentSchemeType::lpc>
                    >::value
                ){
                    return generate_hash<typename CommitmentSchemeType::lpc::merkle_hash_type>(commitment);
                } else if constexpr(nil::crypto3::hashes::is_poseidon<typename CommitmentSchemeType::lpc::merkle_hash_type>::value){
                    std::cout << "Poseidon" << std::endl;
                    return generate_hash<typename CommitmentSchemeType::lpc::merkle_hash_type>(commitment);
                }
                BOOST_ASSERT_MSG(false, "unsupported commitment scheme type");
                return "unsupported commitment scheme type";
            }

            template<typename CommitmentSchemeType>
            static inline std::string generate_eval_proof(typename CommitmentSchemeType::proof_type eval_proof) {
                if constexpr(std::is_same<
                        CommitmentSchemeType,
                        nil::crypto3::zk::commitments::lpc_commitment_scheme<typename CommitmentSchemeType::lpc>
                    >::value
                ){
                    if( CommitmentSchemeType::lpc::use_grinding ){
                        BOOST_ASSERT_MSG(false, "grinding is not supported");
                        std::cout << "Grinding is not supported" << std::endl;
                        return "Grinding is not supported";
                    }

                    std::stringstream out;
                    out << "\t\t{\"array\":[" << std::endl;
                    auto batch_info = eval_proof.z.get_batch_info();
                    std::size_t sum = 0;
                    std::size_t poly_num = 0;
                    for(const auto& [k, v]: batch_info){
                        std::cout << "Batch " << k << " polynomials num = " << v << std::endl;
                        for(std::size_t i = 0; i < v; i++){
                            poly_num++;
                            BOOST_ASSERT(eval_proof.z.get_poly_points_number(k, i) != 0);
                            for(std::size_t j = 0; j < eval_proof.z.get_poly_points_number(k, i); j++){
                                if( sum != 0 ) out << "," << std::endl;
                                out << "\t\t\t{\"field\":\"" << eval_proof.z.get(k, i, j) << "\"}";
                                //std::cout << "batch " << k << " poly " << i << " value " <<  eval_proof.z.get(k, i, j) << std::endl;
                                sum++;
                            }
                        }
                        std::cout << "Sum = " << sum << std::endl;
                    }
                    std::cout << "Polynomials num = "<< poly_num << std::endl;
                    std::cout << "Evaluations num = "<< sum << std::endl;
                    out << std::endl << "\t\t]}," << std::endl;
                    out << "\t\t{\"array\": [" << std::endl;
                    for( std::size_t i = 0; i < eval_proof.fri_proof.fri_roots.size(); i++){
                        if(i != 0) out << "," << std::endl;
                        out << "\t\t\t" << generate_commitment<CommitmentSchemeType>(
                            eval_proof.fri_proof.fri_roots[i]
                        );
                    }
                    out << std::endl << "\t\t]}," << std::endl;
                    out << "\t\t{\"array\": [" << std::endl;
                    std::size_t cur = 0;
                    for( std::size_t i = 0; i < eval_proof.fri_proof.query_proofs.size(); i++){
                        for( const auto &[j, initial_proof]: eval_proof.fri_proof.query_proofs[i].initial_proof){
                            for( std::size_t k = 0; k < initial_proof.values.size(); k++){
                                if(cur != 0) out << "," << std::endl;
                                BOOST_ASSERT_MSG(initial_proof.values[k].size() == 1, "Unsupported step_list[0] value");
                                out << "\t\t\t{\"field\":\"" << initial_proof.values[k][0][0] << "\"}," << std::endl;
                                out << "\t\t\t{\"field\":\"" << initial_proof.values[k][0][1] << "\"}";
                                cur++;
                                cur++;
                            }
                        }
                    }
                    std::cout << "Initial points values = " << cur++ << std::endl;
                    out << std::endl << "\t\t]}," << std::endl;
                    out << "\t\t{\"array\": [" << std::endl;
                    cur = 0;
                    for( std::size_t i = 0; i < eval_proof.fri_proof.query_proofs.size(); i++){
                        for( std::size_t j = 0; j < eval_proof.fri_proof.query_proofs[i].round_proofs.size(); j++){
                            const auto &round_proof = eval_proof.fri_proof.query_proofs[i].round_proofs[j];
                            if(cur != 0) out << "," << std::endl;
                            BOOST_ASSERT_MSG(round_proof.y.size() == 1, "Unsupported step_lis value");
                            out << "\t\t\t{\"field\":\"" << round_proof.y[0][0] << "\"}," << std::endl;
                            out << "\t\t\t{\"field\":\"" << round_proof.y[0][1] << "\"}";
                            cur++;
                            cur++;
                        }
                    }
                    std::cout << "Round proofs values num = " << cur << std::endl;
                    out << std::endl << "\t\t]}," << std::endl;

                    std::cout << "Print initial merkle proofs for FRI" << std::endl;
                    out << "\t\t{\"array\": [" << std::endl;
                    cur = 0;
                    std::cout << "Print merkle proof" << std::endl;
                    for( std::size_t i = 0; i < eval_proof.fri_proof.query_proofs.size(); i++){
                        for( const auto &[j, initial_proof]: eval_proof.fri_proof.query_proofs[i].initial_proof){
                            for( std::size_t k = 0; k < initial_proof.p.path().size(); k++){
                                if(cur != 0) out << "," << std::endl;
                                out << "\t\t\t{\"field\":" << initial_proof.p.path()[k][0].position() << "}";
                                cur ++;
                            }
                            break;
                        }
                    }
                    out << std::endl << "\t\t]}," << std::endl;

                    out << "\t\t{\"array\": [" << std::endl;
                    cur = 0;
                    for( std::size_t i = 0; i < eval_proof.fri_proof.query_proofs.size(); i++){
                        for( const auto &[j, initial_proof]: eval_proof.fri_proof.query_proofs[i].initial_proof){
                            for( std::size_t k = 0; k < initial_proof.p.path().size(); k++){
                                if(cur != 0) out << "," << std::endl;
                                out << "\t\t\t" << generate_hash<typename CommitmentSchemeType::lpc::merkle_hash_type>(
                                    initial_proof.p.path()[k][0].hash()
                                );
                                cur ++;
                            }
                        }
                    }
                    out << std::endl << "\t\t]}," << std::endl;


                    std::cout << "Print round merkle proofs for FRI" << std::endl;
                    out << "\t\t{\"array\": [" << std::endl;
                    cur = 0;
                    for( std::size_t i = 0; i < eval_proof.fri_proof.query_proofs.size(); i++){
                        for( std::size_t j = 0; j < eval_proof.fri_proof.query_proofs[i].round_proofs.size(); j++){
                            const auto& p = eval_proof.fri_proof.query_proofs[i].round_proofs[j].p;
                            for( std::size_t k = 0; k < p.path().size(); k++){
                                if(cur != 0) out << "," << std::endl;
                                out << "\t\t\t{\"field\": " << p.path()[k][0].position() << "}";
                                cur++;
                            }
                        }
                    }
                    out << std::endl << "\t\t]}," << std::endl;

                    out << "\t\t{\"array\": [" << std::endl;
                    cur = 0;
                    for( std::size_t i = 0; i < eval_proof.fri_proof.query_proofs.size(); i++){
                        for( std::size_t j = 0; j < eval_proof.fri_proof.query_proofs[i].round_proofs.size(); j++){
                            const auto& p = eval_proof.fri_proof.query_proofs[i].round_proofs[j].p;
                            for( std::size_t k = 0; k < p.path().size(); k++){
                                if(cur != 0) out << "," << std::endl;
                                out << "\t\t\t" << generate_hash<typename CommitmentSchemeType::lpc::merkle_hash_type>(
                                    p.path()[k][0].hash()
                                );
                                cur++;
                            }
                        }
                    }
                    out << std::endl << "\t\t]}," << std::endl;

                    std::cout << "Print final polynomial" << std::endl;
                    cur = 0;
                    out << "\t\t{\"array\": [" << std::endl;
                    for( std::size_t i = 0; i < eval_proof.fri_proof.final_polynomial.size(); i++){
                        if(cur != 0) out << "," << std::endl;
                        out << "\t\t\t{\"field\": \"" << eval_proof.fri_proof.final_polynomial[i] << "\"}";
                        cur++;
                    }
                    out << std::endl << "\t\t]}";

                    return out.str();
                }
                BOOST_ASSERT_MSG(false, "unsupported commitment scheme type");
                return "unsupported commitment scheme type";
            }

            static inline std::string generate_input(
                std::vector<typename field_type::value_type> public_input,
                const verification_key_type &vk,
                const proof_type &proof
            ){
                std::stringstream out;
                out << "[" << std::endl;

                out << "\t{\"array\":[" << std::endl;
                out << "\t\t" << generate_hash<typename PlaceholderParams::transcript_hash_type>(
                    vk.constraint_system_hash
                ) << "," << std::endl;
                out << "\t\t" << generate_hash<typename PlaceholderParams::transcript_hash_type>(
                    vk.fixed_values_commitment
                ) << std::endl;
                out << "\t]}," << std::endl;

                out << "\t{\"struct\":[" << std::endl;
                out << "\t\t{\"array\":[" << std::endl;
                out << "\t\t\t" << generate_commitment<typename PlaceholderParams::commitment_scheme_type>(
                    proof.commitments.at(nil::crypto3::zk::snark::VARIABLE_VALUES_BATCH)
                ) << "," << std::endl;
                out << "\t\t\t" << generate_commitment<typename PlaceholderParams::commitment_scheme_type>(
                    proof.commitments.at(nil::crypto3::zk::snark::PERMUTATION_BATCH)
                ) << "," << std::endl;
                out << "\t\t\t" << generate_commitment<typename PlaceholderParams::commitment_scheme_type>(
                    proof.commitments.at(nil::crypto3::zk::snark::QUOTIENT_BATCH)
                ) << std::endl;
                out << "\t\t]}," << std::endl;
                out << "\t\t{\"field\": \"" << proof.eval_proof.challenge << "\"}," << std::endl;
                out << generate_eval_proof<typename PlaceholderParams::commitment_scheme_type>(
                    proof.eval_proof.eval_proof
                ) << std::endl;
                out << "\t]}" << std::endl;

                out << "]" << std::endl;
                return out.str();
            }


            static inline std::string generate_recursive_verifier(
                const constraint_system_type &constraint_system,
                const common_data_type &common_data,
                const commitment_scheme_type &commitment_scheme,
                std::size_t permutation_size
            ){
                if constexpr(std::is_same<
                        commitment_scheme_type,
                        nil::crypto3::zk::commitments::lpc_commitment_scheme<typename commitment_scheme_type::lpc>
                    >::value
                ){
                    std::cout << "Permutation_size = " << permutation_size << std::endl;
                    std::string result = nil::blueprint::recursive_verifier_template;
                    bool use_lookups = constraint_system.lookup_gates().size() > 0;
                    transpiler_replacements reps;

                    auto fri_params = commitment_scheme.get_fri_params();
                    std::size_t batches_num = use_lookups?5:4;
                    auto lambda = PlaceholderParams::commitment_scheme_type::fri_type::lambda;

                    std::size_t round_proof_layers_num = 0;
                    std::cout << "Log extended domain = " << log2(fri_params.D[0]->m) << std::endl;
                    for(std::size_t i = 0; i < fri_params.r; i++ ){
                        round_proof_layers_num += log2(fri_params.D[i]->m) -1;
                    }

                    std::size_t rows_amount = common_data.rows_amount;
                    std::size_t quotient_degree = (permutation_size + 1)* (common_data.rows_amount -1 );
                    std::cout << "Quotient degree = " << quotient_degree - 1 << std::endl;
                    std::size_t quotient_polys = (quotient_degree % rows_amount != 0)? (quotient_degree / rows_amount + 1): (quotient_degree / rows_amount);
                    std::cout << "Quotient polys = " << quotient_polys << std::endl;

                    std::size_t poly_num = 2 * permutation_size + 2 + (use_lookups?2:1) + arithmetization_params::total_columns
                        + constraint_system.sorted_lookup_columns_number() + quotient_polys;

                    std::size_t points_num = 4 * permutation_size + 6;
                    for(std::size_t i = 0; i < arithmetization_params::constant_columns + arithmetization_params::selector_columns; i++){
                        points_num += common_data.columns_rotations[i + arithmetization_params::witness_columns + arithmetization_params::public_input_columns].size() + 1;
                    }
                    std::cout << "Fixed values points num = " << points_num << std::endl;
                    for(std::size_t i = 0; i < arithmetization_params::witness_columns + arithmetization_params::public_input_columns; i++){
                        points_num += common_data.columns_rotations[i].size();
                    }
                    std::cout << "Variable values points num = " << points_num << std::endl;
                    points_num += use_lookups? 4 : 2;
                    std::cout << "Permutation polys points num = " << points_num << std::endl;
                    points_num += quotient_polys;
                    std::cout << "Quotient polys points num = " << points_num << std::endl;

                    if( use_lookups ) points_num += constraint_system.sorted_lookup_columns_number() * 3;


                    reps["$BATCHES_NUM$"] = to_string(batches_num);
                    reps["$COMMITMENTS_NUM$"] = to_string(batches_num - 1);
                    reps["$POINTS_NUM$"] = to_string(points_num);
                    reps["$POLY_NUM$"] = to_string(poly_num);
                    reps["$INITIAL_PROOF_POINTS_NUM$"] = to_string(poly_num * lambda * 2);
                    reps["$ROUND_PROOF_POINTS_NUM$"] = to_string(fri_params.r * 2 * lambda);
                    reps["$FRI_ROOTS_NUM$"] = to_string(fri_params.r);
                    reps["$INITIAL_MERKLE_PROOFS_NUM$"] = to_string(batches_num * lambda);
                    reps["$INITIAL_MERKLE_PROOFS_POSITION_NUM$"] = to_string(lambda * (log2(fri_params.D[0]->m) - 1));
                    reps["$INITIAL_MERKLE_PROOFS_HASH_NUM$"] = to_string(lambda * (log2(fri_params.D[0]->m) - 1) * batches_num);
                    reps["$ROUND_MERKLE_PROOFS_POSITION_NUM$"] = to_string(lambda * round_proof_layers_num);
                    reps["$ROUND_MERKLE_PROOFS_HASH_NUM$"] = to_string(lambda * round_proof_layers_num);
                    reps["$FINAL_POLYNOMIAL_SIZE$"] = to_string(log2(fri_params.D[0]->m) - fri_params.r);
                    reps["$LAMBDA$"] = to_string(lambda);

                    result = replace_all(result, reps);
                    return result;
                }
                BOOST_ASSERT_MSG(false, "unsupported commitment scheme type");
                return "unsupported commitment scheme type";
            }
        };
    }
}

#endif   // CRYPTO3_RECURSIVE_VERIFIER_GENERATOR_HPP