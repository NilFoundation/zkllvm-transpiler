#ifndef __MODULAR_PUBLIC_INPUT_CHECK_TEMPLATE_HPP__
#define __MODULAR_PUBLIC_INPUT_CHECK_TEMPLATE_HPP__

#include <string>

namespace nil {
    namespace blueprint {
        std::string modular_direct_public_input_function = R"(
function public_input_direct(bytes calldata blob, uint256[] calldata public_input, verifier_state memory state) internal view 
    returns (bool check){
        check = true;

        uint256 result = 0;
        uint256 Omega = 1;

        for(uint256 i = 0; i < public_input.length;){
            if( public_input[i] != 0){
                uint256 L = mulmod(
                    Omega,
                    field.inverse_static(
                        addmod(state.xi, modulus - Omega, modulus),
                        modulus
                    ),
                    modulus
                );
                    
                result = addmod(
                    result, 
                    mulmod(
                        public_input[i], L, modulus
                    ), 
                    modulus
                );
            }
            Omega = mulmod(Omega, omega, modulus);
            unchecked{i++;}
        }
        result = mulmod(result, state.Z_at_xi, modulus);

        // Input is proof_map.eval_proof_combined_value_offset
        if( result != mulmod(basic_marshalling.get_uint256_be(blob, $PUBLIC_INPUT_OFFSET$), rows_amount, modulus)) check = false;
    }
    )";

    std::string modular_direct_public_input_call = R"(
        //Direct public input check
        if(public_input.length > 0) {
            if (!public_input_direct(blob[$TABLE_Z_OFFSET$:$TABLE_Z_OFFSET$+$QUOTIENT_OFFSET$], public_input, state)) {
                console.log("Wrong public input!");
                state.b = false;
            }
        }
    )";

    std::string modular_public_input_gate_function = R"(
        function uint16_from_two_bytes(bytes1 b1, bytes1 b2) internal pure returns( uint256 result){
            unchecked{
                result = uint8(b1);
                result = result << 8;
                result += uint8(b2);
            }
        }

        // Function is optimized for the case when public input cells are placed in the first table row
        function public_input_gate(
            bytes calldata blob, uint256[] calldata public_input, verifier_state memory state, uint256 alpha
        ) internal view returns (uint256 F){
            for( uint256 i = 0; i < public_input.length; ){
                uint256 l;

                if(uint8(public_input_rows[i]) == 0){
                    l = state.l0;
                } else {
                    uint256 Omega = field.pow_small(omega, uint8(public_input_rows[i]), modulus);
                    l = mulmod(
                        Omega,
                        field.inverse_static(
                            addmod(state.xi, modulus - Omega, modulus),
                            modulus
                        ),
                        modulus
                    );
                    l = mulmod(l, state.Z_at_xi, modulus);
                    l = mulmod(l, field.inverse_static(rows_amount, modulus), modulus);
                }

                l = mulmod(l, addmod(
                    basic_marshalling.get_uint256_be(blob, uint16_from_two_bytes(public_input_columns[i<<1], public_input_columns[(i<<1)+1])), 
                    modulus - public_input[i], 
                    modulus
                ), modulus);

                F = mulmod(F, alpha, modulus);
                F = addmod(F, l, modulus);
                unchecked{i++;}
            }
        }
    )";

    std::string modular_public_input_gate_call = R"(
        //Compute public input gate
        state.F[8] = public_input_gate(blob[$TABLE_Z_OFFSET$:$TABLE_Z_OFFSET$+$QUOTIENT_OFFSET$], public_input, state, transcript.get_field_challenge(tr_state, modulus));
    )";
    }
}

#endif //__MODULAR_PUBLIC_INPUT_CHECK_TEMPLATE_HPP__