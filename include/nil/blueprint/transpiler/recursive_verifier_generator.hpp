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
#include <map>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include<nil/crypto3/hash/keccak.hpp>
#include<nil/crypto3/hash/sha2.hpp>

#include<nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/zk/math/expression.hpp>
#include <nil/crypto3/zk/math/expression_visitors.hpp>
#include <nil/crypto3/zk/math/expression_evaluator.hpp>

#include<nil/blueprint/transpiler/templates/recursive_verifier.hpp>
#include<nil/blueprint/transpiler/util.hpp>

namespace nil {
    namespace blueprint {
        template<typename PlaceholderParams, typename ProofType, typename CommonDataType>
        struct recursive_verifier_generator{
            using field_type = typename PlaceholderParams::field_type;
            using arithmetization_params = typename PlaceholderParams::arithmetization_params;
            using proof_type = ProofType;
            using common_data_type = CommonDataType;
            using verification_key_type = typename common_data_type::verification_key_type;
            using commitment_scheme_type = typename PlaceholderParams::commitment_scheme_type;
            using constraint_system_type = typename PlaceholderParams::constraint_system_type;
            using columns_rotations_type = std::array<std::set<int>, PlaceholderParams::total_columns>;
            using variable_type = typename constraint_system_type::variable_type;
            using variable_indices_type = std::map<variable_type, std::size_t>;
            using degree_visitor_type = typename constraint_system_type::degree_visitor_type;
            using expression_type = typename constraint_system_type::expression_type;
            using term_type = typename constraint_system_type::term_type;
            using binary_operation_type = typename constraint_system_type::binary_operation_type;
            using pow_operation_type = typename constraint_system_type::pow_operation_type;
            using assignment_table_type = typename PlaceholderParams::assignment_table_type;

            // TODO: Move logic to utils.hpp. It's similar to EVM verifier generator
            static std::string zero_indices(columns_rotations_type col_rotations, std::size_t permutation_size){
                std::vector<std::size_t> zero_indices;
                std::uint16_t fixed_values_points = 0;
                std::stringstream result;

                for(std::size_t i= 0; i < PlaceholderParams::constant_columns + PlaceholderParams::selector_columns; i++){
                    fixed_values_points += col_rotations[i + PlaceholderParams::witness_columns + PlaceholderParams::public_input_columns].size() + 1;
                }

                for(std::size_t i= 0; i < PlaceholderParams::total_columns; i++){
                    std::size_t j = 0;
                    for(auto& rot: col_rotations[i]){
                        if(rot == 0){
                            zero_indices.push_back(j);
                            break;
                        }
                        j++;
                    }
                }

                std::uint16_t sum = fixed_values_points;
                std::size_t i = 0;
                for(; i < PlaceholderParams::witness_columns + PlaceholderParams::public_input_columns; i++){
                    zero_indices[i] = sum + zero_indices[i];
                    sum += col_rotations[i].size();
                }

                sum = 0;
                for(; i < PlaceholderParams::total_columns; i++){
                    zero_indices[i] = sum + zero_indices[i];
                    sum += col_rotations[i].size() + 1;
                }

                for( i = 0; i < PlaceholderParams::total_columns; i++){
                    if( i != 0 ) result << ", ";
                    result << zero_indices[i] + 4 * permutation_size + 6;
                }
                return result.str();
            }

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
                } else if constexpr(std::is_same<HashType, nil::crypto3::hashes::keccak_1600<256>>::value){
                    return "{\"field\": \"" <<  hashed_data <<  "\"}";
                } else {
                    std::stringstream out;
                    out << "{\"field\": \"" <<  hashed_data <<  "\"}";
                    return out.str();
                }
                BOOST_ASSERT_MSG(false, "unsupported merkle hash type");
                return "unsupported merkle hash type";
            }

            template<typename CommitmentSchemeType>
            static inline std::string generate_commitment(typename CommitmentSchemeType::commitment_type commitment) {
                return generate_hash<typename CommitmentSchemeType::lpc::merkle_hash_type>(commitment);
            }

            static inline std::string generate_lookup_options_amount_list(
                const constraint_system_type &constraint_system
            ) {
                std::string result;
                for(std::size_t i = 0; i < constraint_system.lookup_tables().size(); i++){
                    if( i != 0 ) result += ", ";
                    result += to_string(constraint_system.lookup_tables()[i].lookup_options.size());
                }
                return result;
            }

            static inline std::string generate_lookup_columns_amount_list(
                const constraint_system_type &constraint_system
            ) {
                std::string result;
                for(std::size_t i = 0; i < constraint_system.lookup_tables().size(); i++){
                    if( i != 0 ) result += ", ";
                    result += to_string(constraint_system.lookup_tables()[i].lookup_options[0].size());
                }
                return result;
            }

            static inline std::string generate_lookup_constraints_amount_list(
                const constraint_system_type &constraint_system
            ) {
                std::string result;
                for(std::size_t i = 0; i < constraint_system.lookup_gates().size(); i++){
                    if( i != 0 ) result += ", ";
                    result += to_string(constraint_system.lookup_gates()[i].constraints.size());
                }
                return result;
            }

            static inline std::string generate_lookup_constraint_table_ids_list(
                const constraint_system_type &constraint_system
            ){
                std::string result;
                for(std::size_t i = 0; i < constraint_system.lookup_gates().size(); i++){
                    for(std::size_t j = 0; j < constraint_system.lookup_gates()[i].constraints.size(); j++){
                        if( i != 0 || j!=0 ) result += ", ";
                        result += to_string(constraint_system.lookup_gates()[i].constraints[j].table_id);
                    }
                }
                return result;
            }

            static inline std::string generate_lookup_expressions_amount_list(
                const constraint_system_type &constraint_system
            ) {
                std::string result;
                for(std::size_t i = 0; i < constraint_system.lookup_gates().size(); i++){
                    for(std::size_t j = 0; j < constraint_system.lookup_gates()[i].constraints.size(); j++){
                        if( i != 0 || j != 0) result += ", ";
                        result += to_string(constraint_system.lookup_gates()[i].constraints[j].lookup_input.size());
                    }
                }
                return result;
            }

            static inline std::string generate_lookup_expressions_computation(
                const constraint_system_type &constraint_system
            ){
                return "";
            }

            template<typename CommitmentSchemeType>
            static inline std::string generate_eval_proof(typename CommitmentSchemeType::proof_type eval_proof) {
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
                    for(std::size_t i = 0; i < v; i++){
                        poly_num++;
                        BOOST_ASSERT(eval_proof.z.get_poly_points_number(k, i) != 0);
                        for(std::size_t j = 0; j < eval_proof.z.get_poly_points_number(k, i); j++){
                            if( sum != 0 ) out << "," << std::endl;
                            out << "\t\t\t{\"field\":\"" << eval_proof.z.get(k, i, j) << "\"}";
                            sum++;
                        }
                    }
                }
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
                for( std::size_t i = 0; i < eval_proof.fri_proof.query_proofs.size(); i++){
                    if(i != 0) out << "," << std::endl;
                    out << "\t\t\t{\"array\":[" << std::endl;
                    std::size_t cur = 0;
                    for( const auto &[j, initial_proof]: eval_proof.fri_proof.query_proofs[i].initial_proof){
                        for( std::size_t k = 0; k < initial_proof.values.size(); k++){
                            if(cur != 0) out << "," << std::endl;
                            BOOST_ASSERT_MSG(initial_proof.values[k].size() == 1, "Unsupported step_list[0] value");
                            out << "\t\t\t\t{\"field\":\"" << initial_proof.values[k][0][0] << "\"}," << std::endl;
                            out << "\t\t\t\t{\"field\":\"" << initial_proof.values[k][0][1] << "\"}";
                            cur++;
                            cur++;
                        }
                    }
                    out << "\n\t\t\t]}";
                }
                out << std::endl << "\n\t\t]}," << std::endl;
                out << "\t\t{\"array\": [" << std::endl;
                std::size_t cur = 0;
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
                out << std::endl << "\t\t]}," << std::endl;

                out << "\t\t{\"array\": [" << std::endl;
                cur = 0;
                for( std::size_t i = 0; i < eval_proof.fri_proof.query_proofs.size(); i++){
                    for( const auto &[j, initial_proof]: eval_proof.fri_proof.query_proofs[i].initial_proof){
                        for( std::size_t k = 0; k < initial_proof.p.path().size(); k++){
                            if(cur != 0) out << "," << std::endl;
                            out << "\t\t\t{\"int\":" << initial_proof.p.path()[k][0].position() << "}";
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

                out << "\t\t{\"array\": [" << std::endl;
                cur = 0;
                for( std::size_t i = 0; i < eval_proof.fri_proof.query_proofs.size(); i++){
                    for( std::size_t j = 0; j < eval_proof.fri_proof.query_proofs[i].round_proofs.size(); j++){
                        const auto& p = eval_proof.fri_proof.query_proofs[i].round_proofs[j].p;
                        for( std::size_t k = 0; k < p.path().size(); k++){
                            if(cur != 0) out << "," << std::endl;
                            out << "\t\t\t{\"int\": " << p.path()[k][0].position() << "}";
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

                cur = 0;
                out << "\t\t{\"array\": [" << std::endl;
                for( std::size_t i = 0; i < eval_proof.fri_proof.final_polynomial.size(); i++){
                    if(cur != 0) out << "," << std::endl;
                    out << "\t\t\t{\"field\": \"" << eval_proof.fri_proof.final_polynomial[i] << "\"}";
                    cur++;
                }
                out << std::endl << "\t\t]}";

                return out.str();
                BOOST_ASSERT_MSG(false, "unsupported commitment scheme type");
                return "unsupported commitment scheme type";
            }

            static inline std::string generate_input(
                const verification_key_type &vk,
                const typename assignment_table_type::public_input_container_type &public_inputs,
                const proof_type &proof,
                const std::array<std::size_t, arithmetization_params::public_input_columns> public_input_sizes
            ){
                std::stringstream out;
                out << "[" << std::endl;

                if(arithmetization_params::public_input_columns != 0){
                    out << "\t{\"array\":[" << std::endl;
                    std::size_t cur = 0;
                    for(std::size_t i = 0; i < arithmetization_params::public_input_columns; i++){
                        std::size_t max_non_zero = 0;
                        for(std::size_t j = 0; j < public_inputs[i].size(); j++){
                            if( public_inputs[i][j] != 0 ) max_non_zero = j;
                        }
                        if( max_non_zero + 1 > public_input_sizes[i] ) {
                            std::cout << "Public input size is larger than reserved. Real size = " << max_non_zero  + 1 << " reserved = " << public_input_sizes[i] << std::endl;
                            exit(1);
                        }
                        BOOST_ASSERT(max_non_zero <= public_input_sizes[i]);
                        for(std::size_t j = 0; j < public_input_sizes[i]; j++){
                            if(cur != 0) out << "," << std::endl;
                            if( j >= public_inputs[i].size() )
                                out << "\t\t{\"field\": \"" << typename field_type::value_type(0) << "\"}";
                            else
                                out << "\t\t{\"field\": \"" << public_inputs[i][j] << "\"}";
                            cur++;
                        }
                    }
                    out << std::endl << "\t]}," << std::endl;
                }

                out << "\t{\"array\":[" << std::endl;
                out << "\t\t" << generate_hash<typename PlaceholderParams::transcript_hash_type>(
                    vk.constraint_system_with_params_hash
                ) << "," << std::endl;
                out << "\t\t" << generate_hash<typename PlaceholderParams::transcript_hash_type>(
                    vk.fixed_values_commitment
                ) << std::endl;
                out << "\t]}," << std::endl;

                out << "\t{\"struct\":[" << std::endl;
                out << "\t\t{\"array\":[" << std::endl;
                out << "\t\t\t" << generate_commitment<typename PlaceholderParams::commitment_scheme_type>(proof.commitments.at(1))//(nil::crypto3::zk::snark::VARIABLE_VALUES_BATCH)
                    << "," << std::endl;
                out << "\t\t\t" << generate_commitment<typename PlaceholderParams::commitment_scheme_type>(
                    proof.commitments.at(2))//(nil::crypto3::zk::snark::PERMUTATION_BATCH)
                    << "," << std::endl;
                out << "\t\t\t" << generate_commitment<typename PlaceholderParams::commitment_scheme_type>(
                    proof.commitments.at(3)) // (nil::crypto3::zk::snark::QUOTIENT_BATCH)
                ;

                if( proof.commitments.find(4) != proof.commitments.end() ){ /*nil::crypto3::zk::snark::LOOKUP_BATCH*/
                    out << "," << std::endl << "\t\t\t" << generate_commitment<typename PlaceholderParams::commitment_scheme_type>(
                        proof.commitments.at(4) //nil::crypto3::zk::snark::LOOKUP_BATCH)
                    );
                }
                out << std::endl;

                out << "\t\t]}," << std::endl;
                out << "\t\t{\"field\": \"" << proof.eval_proof.challenge << "\"}," << std::endl;
                out << generate_eval_proof<typename PlaceholderParams::commitment_scheme_type>(
                    proof.eval_proof.eval_proof
                ) << std::endl;
                out << "\t]}" << std::endl;

                out << "]" << std::endl;
                return out.str();
            }

            // TODO move logic to utils.hpp to prevent code duplication
            static inline variable_indices_type get_plonk_variable_indices(const columns_rotations_type &col_rotations, std::size_t start_index){
                std::map<variable_type, std::size_t> result;
                std::size_t j = 0;
                for(std::size_t i = 0; i < PlaceholderParams::constant_columns; i++){
                    for(auto& rot: col_rotations[i + PlaceholderParams::witness_columns + PlaceholderParams::public_input_columns]){
                        variable_type v(i, rot, true, variable_type::column_type::constant);
                        result[v] = j + start_index;
                        j++;
                    }
                    j++;
                }
                for(std::size_t i = 0; i < PlaceholderParams::selector_columns; i++){
                    for(auto& rot: col_rotations[i + PlaceholderParams::witness_columns + PlaceholderParams::public_input_columns + PlaceholderParams::constant_columns]){
                        variable_type v(i, rot, true, variable_type::column_type::selector);
                        result[v] = j + start_index;
                        j++;
                    }
                    j++;
                }
                for(std::size_t i = 0; i < PlaceholderParams::witness_columns; i++){
                    for(auto& rot: col_rotations[i]){
                        variable_type v(i, rot, true, variable_type::column_type::witness);
                        result[v] = j + start_index;
                        j++;
                    }
                }
                for(std::size_t i = 0; i < PlaceholderParams::public_input_columns; i++){
                    for(auto& rot: col_rotations[i + PlaceholderParams::witness_columns]){
                        variable_type v(i, rot, true, variable_type::column_type::public_input);
                        result[v] = j + start_index;
                        j++;
                    }
                }
                return result;
            }

            template<typename VariableType>
            class expression_gen_code_visitor : public boost::static_visitor<std::string> {
                const variable_indices_type &_indices;
            public:
                expression_gen_code_visitor(const variable_indices_type &var_indices) :_indices(var_indices){}

                std::string generate_expression(const expression_type& expr) {
                    return boost::apply_visitor(*this, expr.get_expr());
                }

                std::string operator()(const term_type& term) {
                    std::string result;
                    std::vector <std::string> v;
                    if( term.get_coeff() != field_type::value_type::one() || term.get_vars().size() == 0)
                        v.push_back("pallas::base_field_type::value_type(0x" + to_hex_string(term.get_coeff()) + "_cppui255)");
                    for(auto& var: term.get_vars()){
                        v.push_back("z[" + to_string(_indices.at(var)) + "]");
                    }
                    for(std::size_t i = 0; i < v.size(); i++){
                        if(i != 0) result += " * ";
                        result += v[i];
                    }
                    return result;
                }

                std::string operator()(
                        const pow_operation_type& pow) {
                    std::string result = boost::apply_visitor(*this, pow.get_expr().get_expr());
                    return "pow" + to_string(pow.get_power()) + "(" + result +")";
                }

                std::string operator()(
                        const binary_operation_type& op) {
                    std::string left = boost::apply_visitor(*this, op.get_expr_left().get_expr());
                    std::string right = boost::apply_visitor(*this, op.get_expr_right().get_expr());
                    switch (op.get_op()) {
                        case binary_operation_type::ArithmeticOperatorType::ADD:
                            return "(" + left + " + " + right + ")";
                        case binary_operation_type::ArithmeticOperatorType::SUB:
                            return "(" + left + " - " + right + ")";
                        case binary_operation_type::ArithmeticOperatorType::MULT:
                            return "(" + left + " * " + right + ")";
                    }
                }
            };

            static inline std::string rot_string (int j){
                if(j == 0) return "xi"; else
                if(j == 1 ) return "xi*omega"; else
                if(j == -1) return "xi/omega"; else
                if(j > 0) return "xi*pow(omega, " + to_string(j) + ")"; else
                if(j < 0) return "xi/pow(omega, " + to_string(-j) + ")";
                return "";
            }

            static inline std::vector<std::string> split_point_string(std::string point){
                std::vector<std::string> result;
                std::size_t found = point.find("& ");
                std::size_t j = 0;
                std::size_t prev = 0;
                while (found!=std::string::npos){
                    result.push_back(point.substr(prev, found-prev));
                    prev = found + 2;
                    found = point.find("& ",prev);
                    j++;
                }
                return result;
            }

            static inline std::tuple<
                std::vector<std::vector<std::string>>, std::vector<std::size_t>, std::map<std::string, std::size_t>
            > calculate_unique_point_sets(
                const common_data_type &common_data,
                std::size_t permutation_size,
                bool use_lookups,
                std::size_t quotient_size,
                std::size_t sorted_size
            ){
                std::set<std::string> unique_points;
                std::vector<std::string> points;
                std::map<std::string, std::size_t> singles;
                std::vector<std::vector<std::string>> result;
                std::vector<std::size_t> points_ids;

                singles["eta"] = singles.size();
                singles[rot_string(0)] = singles.size();
                singles[rot_string(1)] = singles.size();

                for(std::size_t i = 0; i < permutation_size*2; i++){
                    points.push_back(rot_string(0) + "& eta& ");
                }
                unique_points.insert(rot_string(0) + "& eta& ");
                points.push_back(rot_string(0) + "& "+ rot_string(1) + "& eta& ");
                points.push_back(rot_string(0) + "& "+ rot_string(1) + "& eta& ");
                unique_points.insert(rot_string(0) + "& "+ rot_string(1) + "& eta& ");

                for(std::size_t i = 0; i < PlaceholderParams::constant_columns; i++){
                    std::stringstream str;
                    for(auto j:common_data.columns_rotations[i + PlaceholderParams::witness_columns + PlaceholderParams::public_input_columns]){
                        if(singles.find(rot_string(j)) == singles.end())
                            singles[rot_string(j)] = singles.size();
                        str << rot_string(j) << "& ";
                    }
                    str << "eta& ";
                    unique_points.insert(str.str());
                    points.push_back(str.str());
                }

                for(std::size_t i = 0; i < PlaceholderParams::selector_columns; i++){
                    std::stringstream str;
                    for(auto j:common_data.columns_rotations[i + PlaceholderParams::witness_columns + PlaceholderParams::public_input_columns + PlaceholderParams::constant_columns]){
                        if(singles.find(rot_string(j)) == singles.end())
                            singles[rot_string(j)] = singles.size();
                        str << rot_string(j) << "& ";
                    }
                    str << "eta& ";
                    unique_points.insert(str.str());
                    points.push_back(str.str());
                }

                for(std::size_t i = 0; i < PlaceholderParams::witness_columns; i++){
                    std::stringstream str;
                    for(auto j:common_data.columns_rotations[i]){
                        if(singles.find(rot_string(j)) == singles.end())
                            singles[rot_string(j)] = singles.size();
                        str << rot_string(j) << "& ";
                    }
                    unique_points.insert(str.str());
                    points.push_back(str.str());
                }

                for(std::size_t i = 0; i < PlaceholderParams::public_input_columns; i++){
                    std::stringstream str;
                    for(auto j:common_data.columns_rotations[i + PlaceholderParams::witness_columns]){
                        if(singles.find(rot_string(j)) == singles.end())
                            singles[rot_string(j)] = singles.size();
                        str << rot_string(j) << "& ";
                    }
                    unique_points.insert(str.str());
                    points.push_back(str.str());
                }

                unique_points.insert(rot_string(0) + "& " + rot_string(1) + "& ");//Permutation
                points.push_back(rot_string(0) + "& " + rot_string(1) + "& ");
                if(use_lookups){
                    points.push_back(rot_string(0) + "& " + rot_string(1) + "& ");
                }
                unique_points.insert(rot_string(0) + "& ");// Quotient
                for(std::size_t i = 0; i < quotient_size; i++){
                    points.push_back(rot_string(0) + "& ");
                }
                if(use_lookups){
                    unique_points.insert(rot_string(0) + "& " + rot_string(1) + "& " + rot_string(common_data.usable_rows_amount) + "& "); // Lookups
                    for( std::size_t i = 0; i < sorted_size; i++ ){
                        points.push_back(rot_string(0) + "& " + rot_string(1) + "& " + rot_string(common_data.usable_rows_amount) + "& ");
                    }
                    singles[rot_string(common_data.usable_rows_amount)] = singles.size();
                }

                for(std::size_t i = 0; i < points.size(); i++){
                    std::size_t j = 0;
                    bool found = false;
                    for(const auto &unique_point:unique_points){
                        if(points[i] == unique_point){
                            found = true;
                            points_ids.push_back(j);
                            break;
                        }
                        j++;
                    }
                    BOOST_ASSERT(found);
                }

                for( const auto &p: unique_points){
                    result.push_back(split_point_string(p));
                }

                return std::make_tuple(result, points_ids, singles);
            }

            static inline std::string generate_recursive_verifier(
                const constraint_system_type &constraint_system,
                const common_data_type &common_data,
                const commitment_scheme_type &commitment_scheme,
                std::size_t permutation_size,
                const std::array<std::size_t, arithmetization_params::public_input_columns> public_input_sizes
            ){
                std::string result = nil::blueprint::recursive_verifier_template;
                bool use_lookups = constraint_system.lookup_gates().size() > 0;
                transpiler_replacements lookup_reps;
                transpiler_replacements reps;

                auto fri_params = commitment_scheme.get_commitment_params();
                std::size_t batches_num = use_lookups?5:4;
                auto lambda = PlaceholderParams::commitment_scheme_type::fri_type::lambda;

                std::size_t round_proof_layers_num = 0;
                for(std::size_t i = 0; i < fri_params.r; i++ ){
                    round_proof_layers_num += log2(fri_params.D[i]->m) -1;
                }

                std::size_t lookup_degree = constraint_system.lookup_poly_degree_bound();

                std::size_t rows_amount = common_data.rows_amount;
                std::size_t quotient_degree = std::max(
                    (permutation_size + 2) * (common_data.rows_amount -1 ),
                    (lookup_degree + 1) * (common_data.rows_amount -1 )
                );

                std::size_t quotient_polys = (quotient_degree % rows_amount != 0)? (quotient_degree / rows_amount + 1): (quotient_degree / rows_amount);

                std::size_t poly_num = 2 * permutation_size + 2 + (use_lookups?2:1)
                    + arithmetization_params::total_columns
                    + constraint_system.sorted_lookup_columns_number() + quotient_polys;

                std::size_t points_num = 4 * permutation_size + 6;
                std::size_t table_values_num = 0;
                for(std::size_t i = 0; i < arithmetization_params::constant_columns + arithmetization_params::selector_columns; i++){
                    points_num += common_data.columns_rotations[i + arithmetization_params::witness_columns + arithmetization_params::public_input_columns].size() + 1;
                    table_values_num += common_data.columns_rotations[i + arithmetization_params::witness_columns + arithmetization_params::public_input_columns].size() + 1;
                }
                for(std::size_t i = 0; i < arithmetization_params::witness_columns + arithmetization_params::public_input_columns; i++){
                    points_num += common_data.columns_rotations[i].size();
                    table_values_num += common_data.columns_rotations[i].size();
                }
                points_num += use_lookups? 4 : 2;
                points_num += quotient_polys;

                if( use_lookups ) {
                    points_num += constraint_system.sorted_lookup_columns_number() * 3;
                }


                std::size_t constraints_amount = 0;
                std::string gates_sizes = "";
                std::stringstream constraints_body;
                std::size_t cur = 0;
                auto verifier_indices = get_plonk_variable_indices(common_data.columns_rotations, 4*permutation_size + 6);

                expression_gen_code_visitor<variable_type> visitor(verifier_indices);
                for(std::size_t i = 0; i < constraint_system.gates().size(); i++){
                    constraints_amount += constraint_system.gates()[i].constraints.size();
                    if( i != 0) gates_sizes += ", ";
                    gates_sizes += to_string(constraint_system.gates()[i].constraints.size());
                    for(std::size_t j = 0; j < constraint_system.gates()[i].constraints.size(); j++, cur++){
                        constraints_body << "\tconstraints[" << cur << "] = " << visitor.generate_expression(constraint_system.gates()[i].constraints[j]) << ";" << std::endl;
                    }
                }

                std::stringstream lookup_expressions_body;
                cur = 0;
                for(const auto &lookup_gate: constraint_system.lookup_gates()){
                    for(const auto &lookup_constraint: lookup_gate.constraints){
                        for( const auto &expr: lookup_constraint.lookup_input){
                            lookup_expressions_body << "\texpressions[" << cur << "] = " << visitor.generate_expression(expr) << ";" << std::endl;
                            cur++;
                        }
                    }
                }

                std::stringstream lookup_gate_selectors_list;
                cur = 0;
                for(const auto &lookup_gate: constraint_system.lookup_gates()){
                    variable_type var(lookup_gate.tag_index, 0, true, variable_type::column_type::selector);
                    lookup_gate_selectors_list << "\t\tlookup_gate_selectors[" << cur << "] = proof.z[" << verifier_indices[var] <<"];" << std::endl;
                    cur++;
                }

                std::stringstream lookup_table_selectors_list;
                cur = 0;
                for(const auto &lookup_table: constraint_system.lookup_tables()){
                    variable_type var(lookup_table.tag_index, 0, true, variable_type::column_type::selector);
                    lookup_table_selectors_list << "\t\tlookup_table_selectors[" << cur << "] = proof.z[" << verifier_indices[var] <<"];" << std::endl;
                    cur++;
                }

                std::stringstream lookup_shifted_table_selectors_list;
                cur = 0;
                for(const auto &lookup_table: constraint_system.lookup_tables()){
                    variable_type var(lookup_table.tag_index, 1, true, variable_type::column_type::selector);
                    lookup_shifted_table_selectors_list << "\t\tshifted_lookup_table_selectors[" << cur << "] = proof.z[" << verifier_indices[var] <<"];" << std::endl;
                    cur++;
                }

                std::stringstream lookup_options_list;
                cur = 0;
                for(const auto &lookup_table: constraint_system.lookup_tables()){
                    for(const auto &lookup_option: lookup_table.lookup_options){
                        for( const auto &column: lookup_option){
                            variable_type var(column.index, 0, true, variable_type::column_type::constant);
                            lookup_options_list << "\t\tlookup_table_lookup_options[" << cur << "] = proof.z[" << verifier_indices[var] <<"];" << std::endl;
                            cur++;
                        }
                    }
                }

                std::stringstream lookup_shifted_options_list;
                cur = 0;
                for(const auto &lookup_table: constraint_system.lookup_tables()){
                    for(const auto &lookup_option: lookup_table.lookup_options){
                        for( const auto &column: lookup_option){
                            variable_type var(column.index, 1, true, variable_type::column_type::constant);
                            lookup_shifted_options_list << "\t\tshifted_lookup_table_lookup_options[" << cur << "] = proof.z[" << verifier_indices[var] <<"];" << std::endl;
                            cur++;
                        }
                    }
                }

                std::stringstream gates_selectors_indices;
                cur = 0;
                for(const auto &gate: constraint_system.gates()){
                    if(cur != 0) gates_selectors_indices << ", ";
                    gates_selectors_indices << gate.selector_index;
                    cur++;
                }

                auto [z_points_indices, singles_strs, singles_map, poly_ids] = calculate_unique_points<PlaceholderParams, common_data_type>(
                    common_data, permutation_size, use_lookups, quotient_polys,
                    use_lookups?constraint_system.sorted_lookup_columns_number():0,
                    "recursive" // Generator mode
                );

                std::string singles_str = "";
                for(const auto &[k, v]: singles_map){
                    singles_str+= "\tsingles[" + to_string(v) + "] = " + k + ";\n";
                }

                std::string lpc_poly_ids_const_arrays = "";
                for(std::size_t i = 0; i < poly_ids.size(); i++){
                    lpc_poly_ids_const_arrays += "\tconstexpr std::array<std::size_t, " + to_string(poly_ids[i].size()) + "> lpc_poly_ids" + to_string(i) + " = {";
                    for(std::size_t j = 0; j < poly_ids[i].size(); j++){
                        if(j != 0) lpc_poly_ids_const_arrays += ", ";
                        lpc_poly_ids_const_arrays += to_string(poly_ids[i][j]);
                    }
                    lpc_poly_ids_const_arrays += "};\n";
                }

                std::stringstream prepare_U_V_str;
                prepare_U_V_str << "\tpallas::base_field_type::value_type theta_acc = pallas::base_field_type::value_type(1);\n\n";
                for(std::size_t i = 0; i < singles_strs.size();i++){
                    for(std::size_t j = 0; j <z_points_indices.size(); j++){
                        if( z_points_indices[j] == i)
                            prepare_U_V_str << "\tU[" + to_string(i) << "] += theta_acc * proof.z[" << j << "]; theta_acc *= challenges.lpc_theta;\n";
                    }
                    prepare_U_V_str << "\n";
                }

                std::string public_input_sizes_str = "";
                std::size_t full_public_input_size = 0;
                for(std::size_t i = 0; i < public_input_sizes.size(); i++){
                    if(i != 0) public_input_sizes_str += ", ";
                    public_input_sizes_str += to_string(public_input_sizes[i]);
                    full_public_input_size += public_input_sizes[i];
                }

                std::stringstream lpc_y_computation;
                for( std::size_t i = 0; i < singles_strs.size(); i++){
                    lpc_y_computation << "\t\tQ0 = pallas::base_field_type::value_type(0);" << std::endl;
                    lpc_y_computation << "\t\tQ1 = pallas::base_field_type::value_type(0);" << std::endl;
                    for( std::size_t j = 0; j < poly_ids[i].size(); j++){
                        lpc_y_computation << "\t\tQ0 += proof.initial_proof_values[i]["<< poly_ids[i][j]*2 <<"] * theta_acc;" << std::endl;
                        lpc_y_computation << "\t\tQ1 += proof.initial_proof_values[i]["<< poly_ids[i][j]*2 + 1 <<"] * theta_acc;" << std::endl;
                        lpc_y_computation << "\t\ttheta_acc *= challenges.lpc_theta;\n";
                    }
                    lpc_y_computation << "\t\tQ0 -= U["<< i << "];" << std::endl;
                    lpc_y_computation << "\t\tQ1 -= U["<< i << "];" << std::endl;
                    lpc_y_computation << "\t\tQ0 /= (res[0][0] - singles[" << i << "]);" << std::endl;
                    lpc_y_computation << "\t\tQ1 /= (res[0][1] - singles[" << i << "]);" << std::endl;
                    lpc_y_computation << "\t\ty[0] += Q0;" << std::endl;
                    lpc_y_computation << "\t\ty[1] += Q1;" << std::endl;
                }

                std::size_t fixed_values_size = permutation_size * 2 + 2 + arithmetization_params::constant_columns + arithmetization_params::selector_columns;
                std::size_t variable_values_size = arithmetization_params::witness_columns + arithmetization_params::public_input_columns;
                std::string batches_size_list = to_string(fixed_values_size) + ", " + to_string(variable_values_size) + ", " +
                    to_string(use_lookups?2:1) + ", " + to_string(quotient_polys);
                if(use_lookups) batches_size_list += ", " + to_string(constraint_system.sorted_lookup_columns_number());

                lookup_reps["$LOOKUP_VARS$"] = use_lookups?lookup_vars:"";
                lookup_reps["$LOOKUP_EXPRESSIONS$"] = use_lookups?lookup_expressions:"";
                lookup_reps["$LOOKUP_CODE$"] = use_lookups?lookup_code:"";
                result = replace_all(result, lookup_reps);

                reps["$USE_LOOKUPS_DEFINE$"] = use_lookups?"#define __USE_LOOKUPS__ 1\n":"";
                reps["$USE_LOOKUPS$"] = use_lookups? "true" : "false";
                reps["$BATCHES_NUM$"] = to_string(batches_num);
                reps["$COMMITMENTS_NUM$"] = to_string(batches_num - 1);
                reps["$POINTS_NUM$"] = to_string(points_num);
                reps["$POLY_NUM$"] = to_string(poly_num);
                reps["$INITIAL_PROOF_POINTS_NUM$"] = to_string(poly_num * 2);
                reps["$ROUND_PROOF_POINTS_NUM$"] = to_string(fri_params.r * 2 * lambda);
                reps["$FRI_ROOTS_NUM$"] = to_string(fri_params.r);
                reps["$INITIAL_MERKLE_PROOFS_NUM$"] = to_string(batches_num * lambda);
                reps["$INITIAL_MERKLE_PROOFS_POSITION_NUM$"] = to_string(lambda * (log2(fri_params.D[0]->m) - 1));
                reps["$INITIAL_MERKLE_PROOFS_HASH_NUM$"] = to_string(lambda * (log2(fri_params.D[0]->m) - 1) * batches_num);
                reps["$ROUND_MERKLE_PROOFS_POSITION_NUM$"] = to_string(lambda * round_proof_layers_num);
                reps["$ROUND_MERKLE_PROOFS_HASH_NUM$"] = to_string(lambda * round_proof_layers_num);
                reps["$FINAL_POLYNOMIAL_SIZE$"] = to_string(std::pow(2, std::log2(fri_params.max_degree + 1) - fri_params.r + 1) - 2);
                reps["$LAMBDA$"] = to_string(lambda);
                reps["$PERMUTATION_SIZE$"] = to_string(permutation_size);
                reps["$ZERO_INDICES$"] = zero_indices(common_data.columns_rotations, permutation_size);
                reps["$TOTAL_COLUMNS$"] = to_string(arithmetization_params::total_columns);
                reps["$ROWS_LOG$"] = to_string(log2(rows_amount));
                reps["$ROWS_AMOUNT$"] = to_string(rows_amount);
                reps["$TABLE_VALUES_NUM$"] = to_string(table_values_num);
                reps["$GATES_AMOUNT$"] = to_string(constraint_system.gates().size());
                reps["$CONSTRAINTS_AMOUNT$"] = to_string(constraints_amount);
                reps["$GATES_SIZES$"] = gates_sizes;
                reps["$GATES_SELECTOR_INDICES$"] = gates_selectors_indices.str();
                reps["$CONSTRAINTS_BODY$"] = constraints_body.str();
                reps["$WITNESS_COLUMNS_AMOUNT$"] = to_string(arithmetization_params::witness_columns);
                reps["$PUBLIC_INPUT_COLUMNS_AMOUNT$"] = to_string(arithmetization_params::public_input_columns);
                reps["$CONSTANT_COLUMNS_AMOUNT$"] = to_string(arithmetization_params::constant_columns);
                reps["$SELECTOR_COLUMNS_AMOUNT$"] = to_string(arithmetization_params::selector_columns);
                reps["$QUOTIENT_POLYS_START$"] = to_string(4*permutation_size + 6 + table_values_num + (use_lookups?4:2));
                reps["$QUOTIENT_POLYS_AMOUNT$"] = to_string(quotient_polys);
                reps["$D0_SIZE$"] = to_string(fri_params.D[0]->m);
                reps["$D0_LOG$"] = to_string(log2(fri_params.D[0]->m));
                reps["$D0_OMEGA$"] = "pallas::base_field_type::value_type(0x" + to_hex_string(fri_params.D[0]->get_domain_element(1)) + "_cppui255)";
                reps["$OMEGA$"] = "pallas::base_field_type::value_type(0x" + to_hex_string(common_data.basic_domain->get_domain_element(1)) + "_cppui255)";
                reps["$FRI_ROUNDS$"] = to_string(fri_params.r);
                reps["$UNIQUE_POINTS$"] = to_string(singles_strs.size());
                reps["$SINGLES_AMOUNT$"] = to_string(singles_strs.size());
                reps["$SINGLES_COMPUTATION$"] = singles_str;
                reps["$PREPARE_U_AND_V$"] = prepare_U_V_str.str();
                reps["$SORTED_COLUMNS$"] = to_string(constraint_system.sorted_lookup_columns_number());
                reps["$SORTED_ALPHAS$"] = to_string(use_lookups? constraint_system.sorted_lookup_columns_number() - 1: 1);
                reps["$LOOKUP_TABLE_AMOUNT$"] = to_string(constraint_system.lookup_tables().size());
                reps["$LOOKUP_GATE_AMOUNT$"] = to_string(constraint_system.lookup_gates().size());
                reps["$LOOKUP_OPTIONS_AMOUNT$"] = to_string(constraint_system.lookup_options_num());
                reps["$LOOKUP_OPTIONS_AMOUNT_LIST$"] = generate_lookup_options_amount_list(constraint_system);
                reps["$LOOKUP_CONSTRAINTS_AMOUNT$"] = to_string(constraint_system.lookup_constraints_num());
                reps["$LOOKUP_CONSTRAINTS_AMOUNT_LIST$"] = generate_lookup_constraints_amount_list(constraint_system);
                reps["$LOOKUP_EXPRESSIONS_AMOUNT$"] = to_string(constraint_system.lookup_expressions_num());
                reps["$LOOKUP_EXPRESSIONS_AMOUNT_LIST$"] = generate_lookup_expressions_amount_list(constraint_system);
                reps["$LOOKUP_TABLES_COLUMNS_AMOUNT$"] = to_string(constraint_system.lookup_tables_columns_num());
                reps["$LOOKUP_TABLES_COLUMNS_AMOUNT_LIST$"] = generate_lookup_columns_amount_list(constraint_system);
                reps["$LOOKUP_EXPRESSIONS_BODY$"] = lookup_expressions_body.str();
                reps["$LOOKUP_CONSTRAINT_TABLE_IDS_LIST$"] = generate_lookup_constraint_table_ids_list(constraint_system);
                reps["$LOOKUP_GATE_SELECTORS_LIST$"] = lookup_gate_selectors_list.str();
                reps["$LOOKUP_TABLE_SELECTORS_LIST$"] = lookup_table_selectors_list.str();
                reps["$LOOKUP_SHIFTED_TABLE_SELECTORS_LIST$"] = lookup_shifted_table_selectors_list.str();
                reps["$LOOKUP_OPTIONS_LIST$"] = lookup_options_list.str();
                reps["$LOOKUP_SHIFTED_OPTIONS_LIST$"] = lookup_shifted_options_list.str();
                reps["$LOOKUP_SORTED_START$"] = to_string(4*permutation_size + 6 + table_values_num + (use_lookups?4:2) + quotient_polys);
                reps["$BATCHES_AMOUNT_LIST$"] = batches_size_list;
                reps["$PUBLIC_INPUT_SIZES$"] = public_input_sizes_str;
                reps["$FULL_PUBLIC_INPUT_SIZE$"] = to_string(full_public_input_size);
                reps["$LPC_POLY_IDS_CONSTANT_ARRAYS$"] = lpc_poly_ids_const_arrays;
                reps["$LPC_Y_COMPUTATION$"] = lpc_y_computation.str();
                reps["$PUBLIC_INPUT_CHECK$"] = arithmetization_params::public_input_columns == 0 ? "" :public_input_check_str;
                reps["$PUBLIC_INPUT_INPUT$"] = arithmetization_params::public_input_columns == 0 ? "" : public_input_input_str;

                result = replace_all(result, reps);
                return result;
            }
        };
    }
}

#endif   // CRYPTO3_RECURSIVE_VERIFIER_GENERATOR_HPP