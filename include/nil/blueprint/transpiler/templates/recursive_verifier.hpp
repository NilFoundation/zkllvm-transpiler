#ifndef __RECURSIVE_VERIFIER_TEMPLATE_HPP__
#define __RECURSIVE_VERIFIER_TEMPLATE_HPP__

#include <string>

namespace nil {
    namespace blueprint {
        std::string recursive_verifier_template = R"(
#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/poseidon.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>

using namespace nil::crypto3;
using namespace nil::crypto3::algebra::curves;

const bool use_lookups = false;
const size_t batches_num = $BATCHES_NUM$;
const size_t commitments_num = $COMMITMENTS_NUM$;
const size_t points_num = $POINTS_NUM$;
const size_t poly_num = $POLY_NUM$;
const size_t initial_proof_points_num = $INITIAL_PROOF_POINTS_NUM$;
const size_t round_proof_points_num = $ROUND_PROOF_POINTS_NUM$;
const size_t fri_roots_num = $FRI_ROOTS_NUM$;
const size_t initial_merkle_proofs_num = $INITIAL_MERKLE_PROOFS_NUM$;
const size_t initial_merkle_proofs_position_num = $INITIAL_MERKLE_PROOFS_POSITION_NUM$;
const size_t initial_merkle_proofs_hash_num = $INITIAL_MERKLE_PROOFS_HASH_NUM$;
const size_t round_merkle_proofs_position_num = $ROUND_MERKLE_PROOFS_POSITION_NUM$;
const size_t round_merkle_proofs_hash_num = $ROUND_MERKLE_PROOFS_HASH_NUM$;
const size_t final_polynomial_size = $FINAL_POLYNOMIAL_SIZE$;
const size_t lambda = $LAMBDA$;
const size_t rows_amount = $ROWS_AMOUNT$;
const size_t rows_log = $ROWS_LOG$;
const size_t total_columns = $TOTAL_COLUMNS$;
const size_t permutation_size = $PERMUTATION_SIZE$;
const std::array<size_t, total_columns> zero_indices = {$ZERO_INDICES$};
const size_t table_values_num = $TABLE_VALUES_NUM$;
const size_t gates_amount = $GATES_AMOUNT$;
const size_t constraints_amount = $CONSTRAINTS_AMOUNT$;
const size_t witness_amount = $WITNESS_COLUMNS_AMOUNT$;
const size_t public_input_amount = $PUBLIC_INPUT_COLUMNS_AMOUNT$;
const size_t constant_amount = $CONSTANT_COLUMNS_AMOUNT$;
const size_t selector_amount = $SELECTOR_COLUMNS_AMOUNT$;
const size_t quotient_polys_start = $QUOTIENT_POLYS_START$;
const size_t quotient_polys_amount = $QUOTIENT_POLYS_AMOUNT$;
const size_t D0_size = $D0_SIZE$;
const size_t D0_log = $D0_LOG$;
const pallas::base_field_type::value_type D0_omega = $D0_OMEGA$;
const pallas::base_field_type::value_type omega = $OMEGA$;
const size_t fri_rounds = $FRI_ROUNDS$;
const std::array<int, gates_amount> gates_sizes = {$GATES_SIZES$};
const size_t unique_points = $UNIQUE_POINTS$;
const std::array<int, poly_num> point_ids = {$POINTS_IDS$};
const size_t singles_amount = $SINGLES_AMOUNT$;

struct placeholder_proof_type{
    std::array<pallas::base_field_type::value_type, commitments_num> commitments;
    pallas::base_field_type::value_type challenge;
    std::array<pallas::base_field_type::value_type, points_num> z;
    std::array<pallas::base_field_type::value_type, fri_roots_num> fri_roots;
    std::array<pallas::base_field_type::value_type, initial_proof_points_num> initial_proof_values;
    std::array<pallas::base_field_type::value_type, round_proof_points_num> round_proof_values;
    std::array<int, initial_merkle_proofs_position_num> initial_proof_positions;
    std::array<pallas::base_field_type::value_type, initial_merkle_proofs_hash_num> initial_proof_hashes;
    std::array<int, round_merkle_proofs_position_num> round_merkle_proof_positions;
    std::array<pallas::base_field_type::value_type, round_merkle_proofs_hash_num> round_proof_hashes;
    std::array<pallas::base_field_type::value_type, final_polynomial_size> final_polynomial;
};

struct placeholder_challenges_type{
    pallas::base_field_type::value_type fri_etha;
    pallas::base_field_type::value_type perm_beta;
    pallas::base_field_type::value_type perm_gamma;
    pallas::base_field_type::value_type lookup_theta;
    pallas::base_field_type::value_type lookup_gamma;
    pallas::base_field_type::value_type lookup_beta;
    std::array<pallas::base_field_type::value_type, 1> lookup_alphas;
    pallas::base_field_type::value_type gate_theta;
    std::array<pallas::base_field_type::value_type, 8> alphas;
    std::array<pallas::base_field_type::value_type, fri_roots_num> fri_alphas;
    std::array<pallas::base_field_type::value_type, lambda> fri_x_indices;
    pallas::base_field_type::value_type lpc_theta;
    pallas::base_field_type::value_type xi;
};

typedef __attribute__((ext_vector_type(2))) typename pallas::base_field_type::value_type permutation_argument_thetas_type;
typedef __attribute__((ext_vector_type(3))) typename pallas::base_field_type::value_type permutation_argument_output_type;

struct placeholder_permutation_argument_input_type{
    std::array<typename pallas::base_field_type::value_type, permutation_size> xi_values;
    std::array<typename pallas::base_field_type::value_type, permutation_size> id_perm;
    std::array<typename pallas::base_field_type::value_type, permutation_size> sigma_perm;
    permutation_argument_thetas_type thetas;
};

pallas::base_field_type::value_type transcript(pallas::base_field_type::value_type tr_state, pallas::base_field_type::value_type value) {
    return hash<hashes::poseidon>(value, hash<hashes::poseidon>(tr_state, tr_state));
}

std::pair<pallas::base_field_type::value_type, pallas::base_field_type::value_type > transcript_challenge(pallas::base_field_type::value_type tr_state) {
    return std::make_pair(hash<hashes::poseidon>(tr_state, tr_state), hash<hashes::poseidon>(tr_state, tr_state));
}

std::array<pallas::base_field_type::value_type, singles_amount> fill_singles(
    pallas::base_field_type::value_type xi,
    pallas::base_field_type::value_type etha
){
    std::array<pallas::base_field_type::value_type, singles_amount> singles;
$SINGLES_COMPUTATION$;
    return singles;
}

placeholder_challenges_type generate_challenges(
    const std::array<pallas::base_field_type::value_type, 2> &vk,
    const placeholder_proof_type &proof
){
    placeholder_challenges_type challenges;

    pallas::base_field_type::value_type tr_state(0x2fadbe2852044d028597455bc2abbd1bc873af205dfabb8a304600f3e09eeba8_cppui255);

    tr_state = transcript(tr_state, vk[0]);
    tr_state = transcript(tr_state, vk[1]);

    // LPC additional point
    std::tie(tr_state, challenges.fri_etha) = transcript_challenge(tr_state);

    tr_state = transcript(tr_state, proof.commitments[0]);

    std::tie(tr_state, challenges.perm_beta) = transcript_challenge(tr_state);
    std::tie(tr_state, challenges.perm_gamma) = transcript_challenge(tr_state);

    // Call lookup argument
    if( use_lookups ){
        __builtin_assigner_exit_check(false);
    }

    // Call gate argument
    tr_state = transcript(tr_state, proof.commitments[1]);
    std::tie(tr_state, challenges.gate_theta) = transcript_challenge(tr_state);

    for(std::size_t i = 0; i < 8; i++){
        std::tie(tr_state, challenges.alphas[i]) = transcript_challenge(tr_state);
    }
    tr_state = transcript(tr_state, proof.commitments[2]);

    std::tie(tr_state, challenges.xi) = transcript_challenge(tr_state);

    tr_state = transcript(tr_state, vk[1]);
    tr_state = transcript(tr_state, proof.commitments[0]);
    tr_state = transcript(tr_state, proof.commitments[1]);
    tr_state = transcript(tr_state, proof.commitments[2]);

    std::tie(tr_state, challenges.lpc_theta) = transcript_challenge(tr_state);

    for(std::size_t i = 0; i < fri_roots_num; i++){
        tr_state = transcript(tr_state, proof.fri_roots[i]);
        std::tie(tr_state, challenges.fri_alphas[i]) = transcript_challenge(tr_state);
    }

    for(std::size_t i = 0; i < lambda; i++){
        std::tie(tr_state, challenges.fri_x_indices[i]) = transcript_challenge(tr_state);
    }

    return challenges;
}

pallas::base_field_type::value_type pow2(pallas::base_field_type::value_type x, size_t plog){
    if(plog == 0) return pallas::base_field_type::value_type(1);
    pallas::base_field_type::value_type result = x;
    for(std::size_t i = 0; i < plog; i++){
        result = result * result;
    }
    return result;
}

pallas::base_field_type::value_type pow(pallas::base_field_type::value_type x, size_t p){
    pallas::base_field_type::value_type result = x;
    for(std::size_t i = 1; i < p; i++){
        result = result * x;
    }
    return result;
}

std::pair<pallas::base_field_type::value_type, pallas::base_field_type::value_type> xi_polys(
    pallas::base_field_type::value_type xi
){
    pallas::base_field_type::value_type xi_n = pow2(xi, rows_log) - pallas::base_field_type::value_type(1);
    pallas::base_field_type::value_type l0 = (xi - pallas::base_field_type::value_type(1))*pallas::base_field_type::value_type(rows_amount);
    l0 = xi_n / l0;
    return std::make_pair(l0, xi_n);
}

std::array<pallas::base_field_type::value_type, constraints_amount> calculate_constraints(std::array<pallas::base_field_type::value_type, points_num> z){
    std::array<pallas::base_field_type::value_type, constraints_amount> constraints;
$CONSTRAINTS_BODY$

    return constraints;
}

typename pallas::base_field_type::value_type
    gate_argument_verifier(
        std::array<typename pallas::base_field_type::value_type, gates_amount> selectors,
        std::array<typename pallas::base_field_type::value_type, constraints_amount> constraints,
        typename pallas::base_field_type::value_type theta
    ) {

    return __builtin_assigner_gate_arg_verifier(
        selectors.data(),
        (int*)gates_sizes.data(),
        gates_amount,
        constraints.data(),
        constraints_amount,
        theta
    );
}

std::array<pallas::base_field_type::value_type, 4> getV3(
    pallas::base_field_type::value_type xi0,pallas::base_field_type::value_type xi1,pallas::base_field_type::value_type xi2
){
    std::array<pallas::base_field_type::value_type, 4> result;
    result[0] = - xi0 * xi1 * xi2;
    result[1] = xi0 * xi1  + xi1 * xi2 + xi0 * xi2;
    result[2] = - xi0 - xi1 - xi2;
    result[3] = pallas::base_field_type::value_type(1);
    __builtin_assigner_exit_check(result[0] + xi0 * result[1] + xi0 * xi0 * result[2] + xi0*xi0*xi0*result[3] == pallas::base_field_type::value_type(0));
    return result;
}

std::array<pallas::base_field_type::value_type, 4> getV2(
    pallas::base_field_type::value_type xi0,pallas::base_field_type::value_type xi1
){
    std::array<pallas::base_field_type::value_type, 4> result;
    result[0] =  xi0 * xi1;
    result[1] = - xi0 - xi1;
    result[2] = pallas::base_field_type::value_type(1);
    result[3] = pallas::base_field_type::value_type(0);
    __builtin_assigner_exit_check(result[0] + xi0 * result[1] + xi0 * xi0 * result[2] + xi0*xi0*xi0*result[3] == pallas::base_field_type::value_type(0));
    return result;
}

std::array<pallas::base_field_type::value_type, 4> getV1(
    pallas::base_field_type::value_type xi0
){
    std::array<pallas::base_field_type::value_type, 4> result;
    result[0] = - xi0;
    result[1] = pallas::base_field_type::value_type(1);
    result[2] = pallas::base_field_type::value_type(0);
    result[3] = pallas::base_field_type::value_type(0);
    __builtin_assigner_exit_check(result[0] + xi0 * result[1] + xi0 * xi0 * result[2] + xi0*xi0*xi0*result[3] == pallas::base_field_type::value_type(0));
    return result;
}

std::array<pallas::base_field_type::value_type, 3> getU3(
    pallas::base_field_type::value_type x0,pallas::base_field_type::value_type x1,pallas::base_field_type::value_type x2,
    pallas::base_field_type::value_type z0,pallas::base_field_type::value_type z1,pallas::base_field_type::value_type z2
){
    std::array<pallas::base_field_type::value_type, 3> result;
    pallas::base_field_type::value_type denom = (x0-x1)*(x1-x2)*(x2-x0);

    z0 = z0 * (x2-x1);
    z1 = z1 * (x0-x2);
    z2 = z2 * (x1-x0);

    result[0] = (z0*x1*x2 + z1*x0*x2 + z2*x0*x1)/denom;
    result[1] = (-z0*(x1 + x2) - z1*(x0 + x2) - z2 * (x0 + x1))/denom;
    result[2] = (z0 + z1 + z2)/denom;

    __builtin_assigner_exit_check(result[0] + x0 * result[1] + x0 * x0 * result[2] == z0/(x2-x1));
    __builtin_assigner_exit_check(result[0] + x1 * result[1] + x1 * x1 * result[2] == z1/(x0-x2));
    __builtin_assigner_exit_check(result[0] + x2 * result[1] + x2 * x2 * result[2] == z2/(x1-x0));

    return result;
}

std::array<pallas::base_field_type::value_type, 3> getU2(
    pallas::base_field_type::value_type x0,pallas::base_field_type::value_type x1,
    pallas::base_field_type::value_type z0,pallas::base_field_type::value_type z1
){
    std::array<pallas::base_field_type::value_type, 3> result;
    pallas::base_field_type::value_type denom = (x0-x1);
    result[0] = (-z0*x1 + z1*x0)/denom;
    result[1] = (z0 - z1)/denom;
    result[2] = pallas::base_field_type::value_type(0);

    __builtin_assigner_exit_check(result[0] + x0 * result[1] + x0 * x0 * result[2] == z0);
    __builtin_assigner_exit_check(result[0] + x1 * result[1] + x1 * x1 * result[2] == z1);

    return result;
}

std::array<pallas::base_field_type::value_type, 3> getU1(
    pallas::base_field_type::value_type x0,
    pallas::base_field_type::value_type z0
){
    std::array<pallas::base_field_type::value_type, 3> result;
    result[0] = z0;
    result[1] = pallas::base_field_type::value_type(0);
    result[2] = pallas::base_field_type::value_type(0);

    __builtin_assigner_exit_check(result[0] + x0 * result[1] + x0 * x0 * result[2] == z0);

    return result;
}

pallas::base_field_type::value_type eval4(std::array<pallas::base_field_type::value_type, 4> poly, pallas::base_field_type::value_type x){
    pallas::base_field_type::value_type result;
    result = poly[3];
    result = result *x + poly[2];
    result = result *x + poly[1];
    result = result *x + poly[0];
    __builtin_assigner_exit_check(poly[0] + x * poly[1] + x * x * poly[2] + x*x*x*poly[3] == result);
    return result;
}

pallas::base_field_type::value_type eval3(std::array<pallas::base_field_type::value_type, 3> poly, pallas::base_field_type::value_type x){
    pallas::base_field_type::value_type result;
    result = poly[2];
    result = result *x + poly[1];
    result = result *x + poly[0];
    __builtin_assigner_exit_check(poly[0] + x * poly[1] + x * x * poly[2] == result);
    return result;
}

constexpr std::size_t L0_IND = 0;
constexpr std::size_t Z_AT_XI_IND = 1;
constexpr std::size_t F_CONSOLIDATED_IND = 2;
constexpr std::size_t T_CONSOLIDATED_IND = 3;

[[circuit]] bool placeholder_verifier(
    std::array<pallas::base_field_type::value_type, 2> vk,
    placeholder_proof_type proof
) {
    placeholder_challenges_type challenges = generate_challenges(vk, proof);
    __builtin_assigner_exit_check(challenges.xi == proof.challenge);

    std::array<pallas::base_field_type::value_type, 4> different_values;
    std::tie(different_values[L0_IND], different_values[Z_AT_XI_IND]) = xi_polys(challenges.xi);

    std::array<pallas::base_field_type::value_type, 8> F = {0,0,0,0,0,0,0,0};

    // Call permutation argument
    placeholder_permutation_argument_input_type perm_arg_input;
    perm_arg_input.thetas[0] = challenges.perm_beta;
    perm_arg_input.thetas[1] = challenges.perm_gamma;

    for( std::size_t i = 0; i < permutation_size; i++ ){
        perm_arg_input.xi_values[i] = proof.z[4*permutation_size + 6 + zero_indices[i]];
        perm_arg_input.id_perm[i] = proof.z[2*i];
        perm_arg_input.sigma_perm[i] = proof.z[2*permutation_size + 2*i];
    }

    permutation_argument_output_type permutation_argument = __builtin_assigner_permutation_arg_verifier(
        perm_arg_input.xi_values.data(),
        perm_arg_input.id_perm.data(),
        perm_arg_input.sigma_perm.data(),
        permutation_size,
        different_values[L0_IND],
        proof.z[4*permutation_size + 6 + table_values_num],     // V
        proof.z[4*permutation_size + 6 + table_values_num + 1], // V_shifted
        proof.z[4*permutation_size],                            // q_last
        proof.z[4*permutation_size + 3],                        // q_blind
        perm_arg_input.thetas
    );

    F[0] = permutation_argument[0];
    F[1] = permutation_argument[1];
    F[2] = permutation_argument[2];
    {
        std::array<pallas::base_field_type::value_type, constraints_amount> constraints;
        std::array<pallas::base_field_type::value_type, gates_amount> selectors;
        constraints = calculate_constraints(proof.z);

        for( std::size_t i = 0; i < gates_amount; i++ ){
            selectors[i] = proof.z[4 * permutation_size + 6 + zero_indices[i + witness_amount+public_input_amount + constant_amount]];
        }


        F[7] = gate_argument_verifier(
            selectors,
            constraints,
            challenges.gate_theta
        );
        F[7] *= (pallas::base_field_type::value_type(1) - proof.z[4*permutation_size] - proof.z[4*permutation_size + 3]);
    }

    different_values[F_CONSOLIDATED_IND] = pallas::base_field_type::value_type(0);
    for(std::size_t i = 0; i < 8; i++){
        F[i] *= challenges.alphas[i];
        different_values[F_CONSOLIDATED_IND] += F[i];
    }

    different_values[T_CONSOLIDATED_IND] = pallas::base_field_type::value_type(0);
    pallas::base_field_type::value_type factor = pallas::base_field_type::value_type(1);
    for(std::size_t i = 0; i < quotient_polys_amount; i++){
        different_values[T_CONSOLIDATED_IND] += proof.z[quotient_polys_start + i] * factor;
        factor *= (different_values[Z_AT_XI_IND] + pallas::base_field_type::value_type(1));
    }
    __builtin_assigner_exit_check(different_values[F_CONSOLIDATED_IND] == different_values[T_CONSOLIDATED_IND] * (different_values[Z_AT_XI_IND]));


    // Commitment scheme
    std::array<pallas::base_field_type::value_type, singles_amount> singles = fill_singles(challenges.xi, challenges.fri_etha);
    std::array<std::array<pallas::base_field_type::value_type, 4>, unique_points> V;
    std::array<std::array<pallas::base_field_type::value_type, 3>, poly_num> U;
    std::array<std::array<pallas::base_field_type::value_type, 3>, unique_points> combined_U;
    std::array<pallas::base_field_type::value_type, 3> tmp;
    std::size_t z_ind = 0;
$PREPARE_U_AND_V$
    for(std::size_t u = 0; u < unique_points; u++){
        combined_U[u][0] = pallas::base_field_type::value_type(0);
        combined_U[u][1] = pallas::base_field_type::value_type(0);
        combined_U[u][2] = pallas::base_field_type::value_type(0);
        for(std::size_t j = 0; j < poly_num; j++){
            combined_U[u][0] = combined_U[u][0] * challenges.lpc_theta;
            combined_U[u][1] = combined_U[u][1] * challenges.lpc_theta;
            combined_U[u][2] = combined_U[u][2] * challenges.lpc_theta;
            if( point_ids[j] == u ){
                combined_U[u][0] = combined_U[u][0] + U[j][0];
                combined_U[u][1] = combined_U[u][1] + U[j][1];
                combined_U[u][2] = combined_U[u][2] + U[j][2];
            }
        }
    }

    std::array<std::array<typename pallas::base_field_type::value_type, 3>, D0_log> res;
    std::size_t round_proof_ind = 0;
    std::size_t initial_proof_ind = 0;
    pallas::base_field_type::value_type interpolant;
    for(std::size_t i = 0; i < lambda; i++){
        __builtin_assigner_fri_cosets(res.data(), D0_log, D0_omega, 256, challenges.fri_x_indices[i]);

        std::array<pallas::base_field_type::value_type, 2> y = {0,0};
        std::array<pallas::base_field_type::value_type, 2> combined_Q = {0,0};
        std::size_t ind = 0;

        for(std::size_t u = 0; u < unique_points; u++){
            combined_Q[0] = pallas::base_field_type::value_type(0);
            combined_Q[1] = pallas::base_field_type::value_type(0);
            ind = initial_proof_ind;
            for(std::size_t k = 0; k < poly_num; k++ ){
                combined_Q[0] *= challenges.lpc_theta;
                combined_Q[1] *= challenges.lpc_theta;
                if(point_ids [k] == u){
                    combined_Q[0] += proof.initial_proof_values[ind];
                    combined_Q[1] += proof.initial_proof_values[ind+1];
                }
                ind = ind + 2;
            }
            combined_Q[0] = combined_Q[0] - eval3(combined_U[u], res[0][0]);
            combined_Q[1] = combined_Q[1] - eval3(combined_U[u], res[0][1]);
            combined_Q[0] = combined_Q[0] / eval4(V[u], res[0][0]);
            combined_Q[1] = combined_Q[1] / eval4(V[u], res[0][1]);
            y[0] = y[0] + combined_Q[0];
            y[1] = y[1] + combined_Q[1];
        }
        initial_proof_ind = ind;

$COMBINED_Q_COMPUTATION$

        for(std::size_t j = 0; j < fri_rounds; j++){
            interpolant = __builtin_assigner_fri_lin_inter(
                res[j][0],
                y[0],
                y[1],
                challenges.fri_alphas[j]
            );
            __builtin_assigner_exit_check(interpolant == proof.round_proof_values[round_proof_ind]);
            y[0] = proof.round_proof_values[round_proof_ind];
            y[1] = proof.round_proof_values[round_proof_ind + 1];
            round_proof_ind += 2;
        }

        interpolant = pallas::base_field_type::value_type(0);
        pallas::base_field_type::value_type x = res[fri_rounds][0];
        pallas::base_field_type::value_type factor = pallas::base_field_type::value_type(1);
        for(std::size_t j = 0; j < final_polynomial_size; j++){
            interpolant = interpolant + proof.final_polynomial[j] * factor;
            factor = factor * x;
        }
        __builtin_assigner_exit_check(interpolant == y[0]);

        interpolant = pallas::base_field_type::value_type(0);
        x = res[fri_rounds][1];
        factor = pallas::base_field_type::value_type(1);
        for(std::size_t j = 0; j < final_polynomial_size; j++){
            interpolant = interpolant + proof.final_polynomial[j] * factor;
            factor = factor * x;
        }
        __builtin_assigner_exit_check(interpolant == y[1]);
    }

    return true;
}
    )";
    }
}

#endif //__RECURSIVE_VERIFIER_TEMPLATE_HPP__