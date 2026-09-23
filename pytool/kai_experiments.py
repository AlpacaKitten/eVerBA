from sage.all import GF
from polymasking_gadgets import LaolaMultGadget, LaolaSquareGadget, LaolaLinearMultGadget, PolyAESSbox, LaolaQuadGadget, OriginalLaolaMultGadget
from isw_gadgets import ISWMult, AdditiveSecMult, AdditiveSecMultLookup

F = GF(2**8)  # underlying field used for arithmetic
num_worker = 1  # number of threads used during verification, crank this up for larger runs near linear speedup
continue_on_fail = False  # by default the verification terminates on the first tuple that cannot be verified. Setting this to true will verify all tuples.


def test_laola(d: int, k: int, e: int) -> None:
    # for larger parameters and complex gadgets this can be expensive, laola is one of these so it is expected to slow down at around d>3, e>3, k>3.
    laola = LaolaMultGadget.with_defaults(
        # WITH DEFAULT: assert k == 1 or k > d // 2, (
        #     f"Skipped LaolaMultGadget for k={k} and d={d} (k must be <= d//2)"
        # )
        d, #d: degree of polynomial
        k, #nr of encoded Secrets
        e, #
        F, #
    )
    # all gadgets implement a functional correctness call, which tests the actual computation on an encoding against a specification on secrets
    laola.functional_correctness()
    # verification of strong non-interference notion, probing security is available as laola.verify_t_PS and non-interference as laola.verify_t_NI
    laola.verify_t_SNI(
        d,  # test for security against all probe sets of size d
        max_memory_mb=32000,
        num_worker=num_worker,
        continue_on_fail=continue_on_fail,
    )

def test_original_laola(d: int, k: int, e: int) -> None:
    # for larger parameters and complex gadgets this can be expensive, laola is one of these so it is expected to slow down at around d>3, e>3, k>3.
    laola = OriginalLaolaMultGadget.with_defaults(
        # WITH DEFAULT: assert k == 1 or k > d // 2, (
        #     f"Skipped LaolaMultGadget for k={k} and d={d} (k must be <= d//2)"
        # )
        d, #d: degree of polynomial
        k, #nr of encoded Secrets
        e, #
        F, #
    )
    # all gadgets implement a functional correctness call, which tests the actual computation on an encoding against a specification on secrets
    laola.functional_correctness()
    # verification of strong non-interference notion, probing security is available as laola.verify_t_PS and non-interference as laola.verify_t_NI
    laola.verify_t_SNI(
        d,  # test for security against all probe sets of size d
        max_memory_mb=32000,
        num_worker=num_worker,
        continue_on_fail=continue_on_fail,
    )

def test_linear_laola(d: int, k: int, e: int, a: int, b: int) -> None:
    # for larger parameters and complex gadgets this can be expensive, laola is one of these so it is expected to slow down at around d>3, e>3, k>3.
    laola = LaolaLinearMultGadget.with_defaults(
        # WITH DEFAULT: assert k == 1 or k > d // 2, (
        #     f"Skipped LaolaMultGadget for k={k} and d={d} (k must be <= d//2)"
        # )
        d, #d: degree of polynomial
        k, #nr of encoded Secrets
        e,
        a,
        b, #
        F, #
    )
    out = laola.output()

    # all gadgets implement a functional correctness call, which tests the actual computation on an encoding against a specification on secrets
    #laola.functional_correctness()
    for i,o in enumerate(out.get_encoded_shares()):
        print(f"share:{i} {o}")

    # verification of strong non-interference notion, probing security is available as laola.verify_t_PS and non-interference as laola.verify_t_NI
    laola.verify_t_SNI(
        d,  # test for security against all probe sets of size d
        max_memory_mb=32000,
        num_worker=num_worker,
        continue_on_fail=continue_on_fail,
    )

def test_laola_square(d: int, k: int, e: int) -> None:
    # for larger parameters and complex gadgets this can be expensive, laola is one of these so it is expected to slow down at around d>3, e>3, k>3.
    laola = LaolaSquareGadget.with_defaults(
        # WITH DEFAULT: assert k == 1 or k > d // 2, (
        #     f"Skipped LaolaMultGadget for k={k} and d={d} (k must be <= d//2)"
        # )
        d, #d: degree of polynomial
        k, #nr of encoded Secrets
        e, #
        F, #
    )
    out = laola.output()

    # all gadgets implement a functional correctness call, which tests the actual computation on an encoding against a specification on secrets
    #laola.functional_correctness()
    for i,o in enumerate(out.get_encoded_shares()):
        print(f"share:{i} {o}")
    # verification of strong non-interference notion, probing security is available as laola.verify_t_PS and non-interference as laola.verify_t_NI
    laola.verify_t_SNI(
        d,  # test for security against all probe sets of size d
        max_memory_mb=32000,
        num_worker=num_worker,
        continue_on_fail=continue_on_fail,
    )

def test_laola_quad(d: int, k: int, e: int, a: int) -> None:
    # for larger parameters and complex gadgets this can be expensive, laola is one of these so it is expected to slow down at around d>3, e>3, k>3.
    laola = LaolaQuadGadget.with_defaults(
        # WITH DEFAULT: assert k == 1 or k > d // 2, (
        #     f"Skipped LaolaMultGadget for k={k} and d={d} (k must be <= d//2)"
        # )
        d, #d: degree of polynomial
        k, #nr of encoded Secrets
        e,
        a,#
        F, #
    )
    out = laola.output()

    # all gadgets implement a functional correctness call, which tests the actual computation on an encoding against a specification on secrets
    #laola.functional_correctness()
    for i,o in enumerate(out.get_encoded_shares()):
        print(f"share:{i} {o}")
    # verification of strong non-interference notion, probing security is available as laola.verify_t_PS and non-interference as laola.verify_t_NI
    laola.verify_t_SNI(
        d,  # test for security against all probe sets of size d
        max_memory_mb=32000,
        num_worker=num_worker,
        continue_on_fail=continue_on_fail,
    )

def test_polyaessbox(d: int, k:int, e:int) -> None:
    aessbox = PolyAESSbox.with_defaults(d,k,e,F)
    aessbox.functional_correctness()
    aessbox.verify_t_SNI(
         d,  # test for security against all probe sets of size d
        max_memory_mb=32000,
        num_worker=num_worker,
        continue_on_fail=continue_on_fail,
    )


def test_ISW_mult(d: int) -> None:

    # for larger parameters and complex gadgets this can be expensive, laola is one of these so it is expected to slow down at around d>3, e>3, k>3.
    isw = ISWMult.with_defaults(
        d, 1, 0, F
    )  # since ISW mult is over an additive sharing scheme it only permits k=1 and e=0

    # all gadgets implement a functional correctness call, which tests the actual computation on an encoding against a specification on secrets
    isw.functional_correctness()
    # verification of strong non-interference notion, probing security is available as laola.verify_t_PS and non-interference as laola.verify_t_NI
    isw.verify_t_SNI(
        d,  # test for security against all probe sets of size d
        max_memory_mb=32000,
        num_worker=num_worker,
        continue_on_fail=continue_on_fail,
    )


def test_ISW_secmult(d: int) -> None:

    # for larger parameters and complex gadgets this can be expensive, laola is one of these so it is expected to slow down at around d>3, e>3, k>3.
    isw = AdditiveSecMult.with_defaults(
        d, 1, 0, F
    )  # since ISW mult is over an additive sharing scheme it only permits k=1 and e=0

    # all gadgets implement a functional correctness call, which tests the actual computation on an encoding against a specification on secrets
    isw.functional_correctness()
    # verification of strong non-interference notion, probing security is available as laola.verify_t_PS and non-interference as laola.verify_t_NI
    isw.verify_t_SNI(
        d,  # test for security against all probe sets of size d
        max_memory_mb=32000,
        num_worker=num_worker,
        continue_on_fail=continue_on_fail,
    )

def test_ISW_secmultLookup(d: int) -> None:

    # for larger parameters and complex gadgets this can be expensive, laola is one of these so it is expected to slow down at around d>3, e>3, k>3.
    isw = AdditiveSecMultLookup.with_defaults(
        d, 1, 0, F
    )  # since ISW mult is over an additive sharing scheme it only permits k=1 and e=0
    out = isw.output()
    for i,o in enumerate(out.get_encoded_shares()):
        print(f"share:{i} {o}")

    # all gadgets implement a functional correctness call, which tests the actual computation on an encoding against a specification on secrets
    isw.functional_correctness()
    # verification of strong non-interference notion, probing security is available as laola.verify_t_PS and non-interference as laola.verify_t_NI
    isw.verify_t_SNI(
        d,  # test for security against all probe sets of size d
        max_memory_mb=32000,
        num_worker=num_worker,
        continue_on_fail=continue_on_fail,
    )


if __name__ == "__main__":
    min_k, max_k = (
        1,
        1,
    )  # number of embedded secrets, polymasking supports multiple secret embedding
    min_e, max_e = 0, 0  # fault resilience parameter, not important for now
    min_d, max_d = (
        5,5
    )  # degree of polynomial, a polynomial of degree d is secure against d many probes
    for k in range(min_k, max_k + 1):
        for d in range(min_d, max_d + 1):  # d > 0 and k <= d
            for e in range(min_e, max_e + 1):  # e >= 0
                if (
                    k > d
                ):  # k must be less than or equal to d, cant encode more secrets than degree
                    continue
                #test_laola_square(d, k, e)
                #test_laola(d,k,e)
                #test_original_laola(d,k,e)
                
                #test_laola_quad(d,k,e,2)
                test_linear_laola(d,k,e, 4,1)
        
                #test_ISW_mult(d)
                #test_ISW_secmult(d)
                #test_ISW_secmultLookup(d)
