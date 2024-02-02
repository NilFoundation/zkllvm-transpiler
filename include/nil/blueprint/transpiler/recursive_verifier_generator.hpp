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
<<<<<<< HEAD
=======

>>>>>>> f206e94a0635f5ba293f7decb9e08ffe08503bc1
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
            using columns_rotations_type = std::array<std::set<int>, PlaceholderParams::total_columns>;
            using variable_type = nil::crypto3::zk::snark::plonk_variable<typename PlaceholderParams::field_type::value_type>;
            using variable_indices_type = std::map<variable_type, std::size_t>;

            // TODO: Move logic to utils.hpp. It's similar to EVM verifier generator
            static std::string zero_indices(columns_rotations_type col_rotations){
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
                    if( i != 0) result << ", ";
                    result << zero_indices[i];
                }

                sum = 0;
                for(; i < PlaceholderParams::total_columns; i++){
                    zero_indices[i] = sum + zero_indices[i];
                    sum += col_rotations[i].size() + 1;
                    if( i != 0) result << ", ";
                    result << zero_indices[i];
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
                    vk.constraint_system_with_params_hash
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

            // TODO move logic to utils.hpp to prevent code duplication
            static inline variable_indices_type get_plonk_variable_indices(const columns_rotations_type &col_rotations, std::size_t start_index){
                using variable_type = nil::crypto3::zk::snark::plonk_variable<typename PlaceholderParams::field_type::value_type>;
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

                std::string generate_expression(const nil::crypto3::math::expression<VariableType>& expr) {
                    return boost::apply_visitor(*this, expr.get_expr());
                }

                std::string operator()(const nil::crypto3::math::term<VariableType>& term) {
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
                        const nil::crypto3::math::pow_operation<VariableType>& pow) {
                    std::string result = boost::apply_visitor(*this, pow.get_expr().get_expr());
                    return "pow(" + result + ", " + to_string(pow.get_power()) + ")";
                }

                std::string operator()(
                        const nil::crypto3::math::binary_arithmetic_operation<VariableType>& op) {
                    std::string left = boost::apply_visitor(*this, op.get_expr_left().get_expr());
                    std::string right = boost::apply_visitor(*this, op.get_expr_right().get_expr());
                    switch (op.get_op()) {
                        case nil::crypto3::math::ArithmeticOperator::ADD:
                            return "(" + left + " + " + right + ")";
                        case nil::crypto3::math::ArithmeticOperator::SUB:
                            return "(" + left + " - " + right + ")";
                        case nil::crypto3::math::ArithmeticOperator::MULT:
                            return "(" + left + " * " + right + ")";
                    }
                }
            };

            static inline std::string generate_recursive_verifier(
                const constraint_system_type &constraint_system,
                const common_data_type &common_data,
                const commitment_scheme_type &commitment_scheme,
<<<<<<< HEAD
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
=======
=======
>>>>>>> f206e94a0635f5ba293f7decb9e08ffe08503bc1
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
                    std::size_t table_values_num = 0;
                    for(std::size_t i = 0; i < arithmetization_params::constant_columns + arithmetization_params::selector_columns; i++){
                        points_num += common_data.columns_rotations[i + arithmetization_params::witness_columns + arithmetization_params::public_input_columns].size() + 1;
                        table_values_num += common_data.columns_rotations[i + arithmetization_params::witness_columns + arithmetization_params::public_input_columns].size() + 1;
                    }
                    std::cout << "Fixed values points num = " << points_num << std::endl;
                    for(std::size_t i = 0; i < arithmetization_params::witness_columns + arithmetization_params::public_input_columns; i++){
                        points_num += common_data.columns_rotations[i].size();
                        table_values_num += common_data.columns_rotations[i].size();
                    }
                    std::cout << "Variable values points num = " << points_num << std::endl;
                    points_num += use_lookups? 4 : 2;
                    std::cout << "Permutation polys points num = " << points_num << std::endl;
                    points_num += quotient_polys;
                    std::cout << "Quotient polys points num = " << points_num << std::endl;

                    if( use_lookups ) points_num += constraint_system.sorted_lookup_columns_number() * 3;

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
                            std::cout << visitor.generate_expression(constraint_system.gates()[i].constraints[j]) << std::endl;
                            std::cout << constraint_system.gates()[i].constraints[j] << std::endl;
                        }
                    }

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
                    reps["$PERMUTATION_SIZE$"] = to_string(permutation_size);
                    reps["$ZERO_INDICES$"] = zero_indices(common_data.columns_rotations);
                    reps["$TOTAL_COLUMNS$"] = to_string(arithmetization_params::total_columns);
                    reps["$ROWS_AMOUNT$"] = to_string(rows_amount);
                    reps["$TABLE_VALUES_NUM$"] = to_string(table_values_num);
                    reps["$GATES_AMOUNT$"] = to_string(constraint_system.gates().size());
                    reps["$CONSTRAINTS_AMOUNT$"] = to_string(constraints_amount);
                    reps["$GATES_SIZES$"] = gates_sizes;
                    reps["$CONSTRAINTS_BODY$"] = constraints_body.str();
                    reps["$WITNESS_COLUMNS_AMOUNT$"] = to_string(arithmetization_params::witness_columns);
                    reps["$PUBLIC_INPUT_COLUMNS_AMOUNT$"] = to_string(arithmetization_params::public_input_columns);
                    reps["$CONSTANT_COLUMNS_AMOUNT$"] = to_string(arithmetization_params::constant_columns);
                    reps["$SELECTOR_COLUMNS_AMOUNT$"] = to_string(arithmetization_params::selector_columns);
                    reps["$QUOTIENT_POLYS_START$"] = to_string(4*permutation_size + 6 + table_values_num + (use_lookups?4:2));
                    reps["$QUOTIENT_POLYS_AMOUNT$"] = to_string(quotient_polys);

                    result = replace_all(result, reps);
                    return result;
                }
                BOOST_ASSERT_MSG(false, "unsupported commitment scheme type");
                return "unsupported commitment scheme type";
<<<<<<< HEAD
>>>>>>> f302960... Add recursive generator, update EVM verifier #39
=======
>>>>>>> f206e94a0635f5ba293f7decb9e08ffe08503bc1
            }
        };
    }
}

<<<<<<< HEAD
#endif   // CRYPTO3_RECURSIVE_VERIFIER_GENERATOR_HPP
=======
#endif   // CRYPTO3_RECURSIVE_VERIFIER_GENERATOR_HPP
>>>>>>> f206e94a0635f5ba293f7decb9e08ffe08503bc1
