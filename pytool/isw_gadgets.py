# SPDX-License-Identifier: MIT
# Copyright 2025-2026 Max Planck Institute for Security and Privacy (MPI-SP), University of Luebeck Institute for IT-Security (ITS)
from itertools import count
from typing import Optional, Self, Set, Type
from sage.all import GF
from observations import Location, mk_obsval
from gadget import Gadget
from encoding import AddEnc, AddEnc_setup


class ISWMult(Gadget[AddEnc]): #calculates x*y=z, Classical ISW-Sceme, see https://eprint.iacr.org/2015/359.pdf Algorithm1
    def __init__(
        self,
        x: AddEnc,
        y: AddEnc,
        rc: count,
        callloc: Optional[Location],
    ):
        if not isinstance(x, AddEnc) or not isinstance(y, AddEnc):
            raise TypeError(f"{self.name()} requires two AddEnc inputs.")
        if x.field != y.field:
            raise ValueError("Fields differ between the two encodings.")
        super().__init__([x, y], callloc)

        self.randoms = set()
        c = [       #c_i =x_i*y_i
            xi.__mul__(
                yi,
                loc=Location(
                    "ISWMult",
                    2,
                    f"multiplication of shares x,y with index[{i}]",
                    callloc,
                ),
            )
            for i, (xi, yi) in enumerate(zip(x.sharing, y.sharing))
        ]

        for i in range(x.n): #n: number of shares
            for j in range(i + 1, x.n):
                name = f"R_{next(rc)}"
                R_poly = x.variable_ring(name)
                self.randoms.add(R_poly)
                R_obs = mk_obsval(
                    x.obsgraph,
                    R_poly,
                    R_poly,
                    location=Location(
                        "ISWMult", 1, description=f"R_{i}_{j}", caller=callloc
                    ),
                )
                xi_yj = x.sharing[i].__mul__(
                    y.sharing[j],
                    loc=Location(
                        "ISWMult",
                        1,
                        description=f"multiplication of shares x[{i}], y[{j}]",
                        caller=callloc,
                    ),
                )
                xj_yi = x.sharing[j].__mul__(
                    y.sharing[i],
                    loc=Location(
                        "ISWMult",
                        1,
                        description=f"multiplication of shares x[{j}], y[{i}]",
                        caller=callloc,
                    ),
                )
                r_xi_yj = R_obs.__add__(
                    xi_yj,
                    loc=Location(
                        "ISWMult",
                        1,
                        description=f"R_{i}_{j} - x[{i}] * y[{j}]", 
                        caller=callloc,
                    ),
                )
                r_prime = r_xi_yj.__add__(
                    xj_yi,
                    loc=Location(
                        "ISWMult",
                        1,
                        description=f"R_prime_{i}_{j} = (R_{i}_{j} + x[{i}] * y[{j}]) + (x[{j}] * y[{i}])",
                        caller=callloc,
                    ),
                )
                c[i] = c[i].__sub__(
                    R_obs,
                    loc=Location(
                        "ISWMult",
                        1,
                        description=f"c{i} = c{i} - R_{i}_{j}",
                        caller=callloc,
                    ),
                )
                c[j] = c[j].__add__(
                    r_prime,
                    loc=Location(
                        "ISWMult",
                        1,
                        description=f"c{j} = c{j} + R_prime_{i}_{j}",
                        caller=callloc,
                    ),
                )
        new_secrets = [si * ti for si, ti in zip(x.secrets, y.secrets)]
        self.output_enc = x.copy(sharing=c, secrets=new_secrets)

    @classmethod
    def with_defaults(cls: Type[Self], d, k, e, F) -> Self:
        assert e == 0, f"ISWMult only supports e == 0, but got {e}"
        assert k == 1, f"ISWMult only supports k == 1, but got {k}"

        n = d + 1
        secrets = ["x", "y"]
        encodings, rc_count = AddEnc_setup(F, secrets, n, 200)
        x_enc = encodings["x"]
        y_enc = encodings["y"]
        instance = cls(x=x_enc, y=y_enc, rc=rc_count, callloc=None)

        return instance

    def output(self) -> AddEnc:
        return self.output_enc

    def random_vars(self) -> Set:
        return self.randoms


class ISWRefresh(Gadget[AddEnc]):
    def __init__(
        self,
        x: AddEnc,
        rc: count,
        callloc: Optional[Location],
    ):
        if not isinstance(x, AddEnc):
            raise TypeError(f"{self.name()} requires two AddEnc inputs.")
        super().__init__([x], callloc)

        self.randoms = set()
        c = [xi for xi in x.sharing]

        for i in range(x.n):
            for j in range(i + 1, x.n):
                name = f"R_{next(rc)}"
                R_poly = x.variable_ring(name)
                self.randoms.add(R_poly)
                R_obs = mk_obsval(
                    x.obsgraph,
                    R_poly,
                    R_poly,
                    location=Location(
                        "ISWRefresh",
                        1,
                        description=f"R_{i}_{j}",
                        caller=callloc,
                    ),
                )
                c[i] = c[i].__sub__(
                    R_obs,
                    loc=Location(
                        "ISWRefresh",
                        1,
                        description=f"c{i} = c{i} - R_{i}_{j}",
                        caller=callloc,
                    ),
                )
                c[j] = c[j].__add__(
                    R_obs,
                    loc=Location(
                        "ISWRefresh",
                        1,
                        description=f"c{j} = c{j} + R_{i}_{j}",
                        caller=callloc,
                    ),
                )

        self.output_enc = x.copy(sharing=c, secrets=x.secrets)

    @classmethod
    def with_defaults(cls: Type[Self], d, k, e, F) -> Self:
        assert e == 0, f"ISWRefresh only supports e == 0, but got {e}"
        assert k == 1, f"ISWRefresh only supports k == 1, but got {k}"

        n = d + 1
        secrets = ["x"]
        encodings, rc_count = AddEnc_setup(F, secrets, n, 200)
        x_enc = encodings["x"]
        instance = cls(x=x_enc, rc=rc_count, callloc=None)

        return instance

    def output(self) -> AddEnc:
        return self.output_enc

    def random_vars(self) -> Set:
        return self.randoms


class AdditiveSecMult(Gadget[AddEnc]): #Secure evaluation of h : x -> x * g(x)
    def __init__(
        self,
        x: AddEnc,
        rc: count,
        callloc: Optional[Location],
        g= None
    ):
        if g is None:
            g= lambda v: v

        if not isinstance(x, AddEnc):
            raise TypeError(f"{self.name()} requires one AddEnc input.")
        
        super().__init__([x], callloc)

        self.randoms = set()
        r = {}

        
        for i in range(x.n): #n: number of shares
            for j in range(i + 1, x.n):
                #3. ri,j ←$ F2n (random r: rj,i = (ri,j ⊕ f (ai, r′i,j )) ⊕ f (ai, aj ⊕ r′i,j ) ,)
                name = f"R_{next(rc)}"
                R_poly = x.variable_ring(name)
                self.randoms.add(R_poly)
                R_obs = mk_obsval(
                    x.obsgraph,
                    R_poly,
                    R_poly,
                    location=Location(
                        "ISWSecMult", 1, description=f"R_{i}_{j}", caller=callloc
                    ),
                )
                r[(i, j)] = R_obs

                #######################################################################
                #4. r'[i,j] ←$ F2n
                name = f"R_{next(rc)}"
                R1_poly = x.variable_ring(name)
                self.randoms.add(R1_poly)
                R1_obs = mk_obsval(
                    x.obsgraph,
                    R1_poly,
                    R1_poly,
                    location=Location(
                        "ISWSecMult", 1, description=f"R1_{i}_{j}", caller=callloc
                    ),
                )
                ###########################################################
                # 5. t ← ri,j ⊕ ai g(r′i,j )

                xi_gr1ij =x.sharing[i].__mul__(
                    g(R1_obs),
                    loc=Location(
                        "ISWSecMult",
                        1,
                        description=f"multiplication of shares x[{i}],r1[{i}][{j}]",
                        caller=callloc,
                    ),
                )

                
                t = R_obs.__add__(
                    xi_gr1ij,
                    loc=Location(
                        "ISWSecMult",
                        1,
                        description=f"t=r[{i}][{j}]+x[{i}]*r1[{i}][{j}]",
                        caller=callloc,
                    )
                )
                ######################################################
                # 6. t ← t ⊕ (r′i,j g(ai)) // t = ri,j ⊕ f (ai, r′i,j )


                r1ij_gxi = R1_obs.__mul__(
                    g(x.sharing[i]),
                    loc=Location(
                        "ISWSecMult",
                        1,
                        description=f"r1[{i}][{j}] * g(x[{i}])",
                        caller=callloc,
                    )
                )

                t= t.__add__(
                  r1ij_gxi, 
                  loc=Location(
                        "ISWSecMult",
                        1,
                        description=f"t=t+r1[{i}][{j}] * g(x[{i}])",
                        caller=callloc,
                    ) 
                )
                ##################################################
                # 7. t ← t ⊕ (ai g(aj ⊕ r′i,j ))

                xj_r1ij= x.sharing[j].__add__(
                    R1_obs,
                    loc=Location(
                        "ISWSecMult",
                        1,
                        description=f"r1[{i}][{j}]+x[{i}]",
                        caller=callloc,
                    ) 
                )
                

                xi_gxj_r1= x.sharing[i].__mul__(
                    g(xj_r1ij), 
                    loc=Location(
                        "ISWSecMult",
                        1,
                        description=f"a[{i}]*g(x[{j}]+r1[{i}][{j}])",
                        caller=callloc,
                    ) 
                )

                t= t.__add__(
                    xi_gxj_r1, 
                    loc=Location(
                        "ISWSecMult",
                        1,
                        description=f"t=t+a[{i}]*g(x[{j}]+r1[{i}][{j}])",
                        caller=callloc,
                    ) 
                )

                #########################################################
                # 8. t ← t ⊕ ((aj ⊕ r′i,j ) g(ai)) // t = ri,j ⊕ f (ai, aj )

             

                xj_r1ij_gxi=xj_r1ij.__mul__(
                    g(x.sharing[i]),
                    loc=Location(
                        "ISWSecMult",
                        1,
                        description=f"(x[{j}]+r1[{i}][{j}])+x[{i}]",
                        caller=callloc,
                    ) 

                )

                t=t.__add__(
                    xj_r1ij_gxi,
                    loc=Location(
                        "ISWSecMult",
                        1,
                        description=f"t=t+((x[{j}]+r1[{i}][{j}])+x[{i}])",
                        caller=callloc,
                    ) 
                )

                ####################################################################

                # 9. rj,i ← t
                r[(i, j)] = R_obs   
                r[(j, i)] = t 
                

            #########################################################    
            #12. for i = 0 to d do
            
        c = []
        for i in range(x.n):
            ci = x.sharing[i].__mul__(
                g(x.sharing[i]),
                loc=Location(
                    "ISWSecMult", 2,
                    description=f"c[{i}] = x[{i}] * g(x[{i}])",
                    caller=callloc,
                ),
            )
            for j in range(x.n):
                if i != j:
                    ci = ci.__add__(
                        r[(i, j)],
                        loc=Location(
                            "ISWSecMult", 2,
                            description=f"c[{i}] += r[{i}][{j}]",
                            caller=callloc,
                        )
                    )
            c.append(ci)


        
        new_secrets = [si * si for si in x.secrets]  # h(x) = x * g(x) = x^2 for g=id
        self.output_enc = x.copy(sharing=c, secrets=new_secrets)

    @classmethod
    def with_defaults(cls: Type[Self], d, k, e, F, g=None) -> Self:
        assert e == 0, f"ISWMult only supports e == 0, but got {e}"
        assert k == 1, f"ISWMult only supports k == 1, but got {k}"

        n = d + 1
        secrets = ["x"]
        encodings, rc_count = AddEnc_setup(F, secrets, n, 200)
        x_enc = encodings["x"]
        instance = cls(x=x_enc, rc=rc_count, callloc=None, g=g)

        return instance

    def output(self) -> AddEnc:
        return self.output_enc

    def random_vars(self) -> Set:
        return self.randoms


class AdditiveSecMultLookup(Gadget[AddEnc]): 
    #Input: shares (ai )i such that +i ai = a, a look-up table for h : x → x g(x)
    #Output: shares ci satisfying +i ci = a g(a) for some F2 -linear function g
    def __init__(
        self,
        x: AddEnc,
        rc: count,
        callloc: Optional[Location],
        h= None
    ):
        if h is None:
            g= lambda v: v*v
            h= lambda w: w * g(w)

        if not isinstance(x, AddEnc):
            raise TypeError(f"{self.name()} requires one AddEnc input.")
        
        super().__init__([x], callloc)

        self.randoms = set()
        r = {}

        
        for i in range(x.n): #n: number of shares
            for j in range(i + 1, x.n):
                #3. ri,j ←$ F2n 
                name = f"R_{next(rc)}"
                R_poly = x.variable_ring(name)
                self.randoms.add(R_poly)
                R_obs = mk_obsval(
                    x.obsgraph,
                    R_poly,
                    R_poly,
                    location=Location(
                        "ISWSecMult", 1, description=f"R_{i}_{j}", caller=callloc
                    ),
                )
                r[(i, j)] = R_obs

                #######################################################################
                #4. r'[i,j] ←$ F2n
                name = f"R_{next(rc)}"
                R1_poly = x.variable_ring(name)
                self.randoms.add(R1_poly)
                R1_obs = mk_obsval(
                    x.obsgraph,
                    R1_poly,
                    R1_poly,
                    location=Location(
                        "ISWSecMult", 1, description=f"R1_{i}_{j}", caller=callloc
                    ),
                )
                ###########################################################
                # 5. t ← ri,j
                
                t = R_obs
                ######################################################
                # 6. t ← t ⊕ h(ai ⊕ r'i,j)


                hxi_r1ij= h(x.sharing[i].__add__(
                   R1_obs,
                   loc=Location(
                        "ISWSecMultLookup",
                        1,
                        description=f"Calculate g(x[{i}]+r'[{i}][{j}])",
                        caller=callloc,
                    ) 
                ))
            

                t= t.__add__(
                  hxi_r1ij,
                  loc=Location(
                        "ISWSecMult",
                        1,
                        description=f"t=t+g(x[{i}]+r'[{i}][{j}])",
                        caller=callloc,
                    ) 
                )
                ##################################################
                #7. t ← t ⊕ h(aj ⊕ r'i,j)

                hxj_r1ij= h(x.sharing[j].__add__(
                   R1_obs,
                   loc=Location(
                        "ISWSecMultLookup",
                        1,
                        description=f"Calculate h(x[{i}]+r'[{i}][{j}])",
                        caller=callloc,
                    ) 
                ))
            

                t= t.__add__(
                  hxj_r1ij,
                  loc=Location(
                        "ISWSecMultLookup",
                        1,
                        description=f"t=t+h(x[{i}]+r'[{i}][{j}])",
                        caller=callloc,
                    ) 
                )

                #########################################################
                #8.  t ← t ⊕ h ((ai ⊕ r'i,j ) ⊕ aj)

             

                xi_r1ij= x.sharing[i].__add__(
                    R1_obs,
                    loc=Location(
                        "ISWSecMultLookup",
                        1,
                        description=f"Calculate x[{i}]+r'[{i}][{j}])",
                        caller=callloc,
                    ) 
                )

                xi_r1ij_xj= xi_r1ij.__add__(
                    x.sharing[j],
                    loc=Location(
                        "ISWSecMultLookup",
                        1,
                        description=f"Calculate (x[{i}]+r'[{i}][{j}])+x[{j}]",
                        caller=callloc,
                    ) 
                )

                t=t.__add__(
                    h(xi_r1ij_xj),
                    loc=Location(
                        "ISWSecMultLookup",
                        1,
                        description=f"t=t+h((x[{i}]+r1[{i}][{j}])+x[{j}])",
                        caller=callloc,
                    ) 
                )

                ####################################################################

                # t ← t ⊕ h(r'i,j )

                t=t.__add__(
                    h(R1_obs),
                    loc=Location(
                        "ISWSecMultLookup",
                        1,
                        description=f"t=t+h(r1[{i}][{j}])",
                        caller=callloc,
                    ) 
                )
                ###################################################################
                # rj,i<- t
 
                # r[(i, j)] = R_obs   
                r[(j, i)] = t 
                

            #########################################################    
            #12. for i = 0 to d do
            
        c = []
        for i in range(x.n):
            ci = h(x.sharing[i])
            for j in range(x.n):
                if i != j:
                    ci = ci.__add__(
                        r[(i, j)],
                        loc=Location(
                            "ISWSecMult", 2,
                            description=f"c[{i}] += r[{i}][{j}]",
                            caller=callloc,
                        )
                    )
            c.append(ci)


        
        new_secrets = [si * si * si for si in x.secrets]  # h(x) = x * g(x) = x^2 for g=id
        self.output_enc = x.copy(sharing=c, secrets=new_secrets)

    @classmethod
    def with_defaults(cls: Type[Self], d, k, e, F, h=None) -> Self:
        assert e == 0, f"ISWMult only supports e == 0, but got {e}"
        assert k == 1, f"ISWMult only supports k == 1, but got {k}"

        n = d + 1
        secrets = ["x"]
        encodings, rc_count = AddEnc_setup(F, secrets, n, 200)
        x_enc = encodings["x"]
        instance = cls(x=x_enc, rc=rc_count, callloc=None, h=h)

        return instance

    def output(self) -> AddEnc:
        return self.output_enc

    def random_vars(self) -> Set:
        return self.randoms

if __name__ == "__main__":
    fields = [GF(2**8), GF(7)]
    num_processes = 64
    continue_on_fail = False
    log = False
    min_d, max_d = 1, 7
    for d in range(min_d, max_d + 1):
        for F in fields:
            print(f"Testing ISW Mult for d={d}, n={d + 1}, and F={F}")
            isw_mul = ISWMult.with_defaults(d, 1, 0, F)
            isw_mul.functional_correctness()

            isw_ref = ISWRefresh.with_defaults(d, 1, 0, F)
            isw_ref.functional_correctness()

            isw_list =AdditiveSecMultLookup.with_defaults(d,1,0,F,None)
            isw_list.functional_correctness()


