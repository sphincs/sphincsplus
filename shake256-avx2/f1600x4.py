import peachpy.x86_64

stateArg = Argument(ptr(uint64_t))
rcArg = Argument(ptr(uint64_t))
with Function("f1600x4AVX2", (stateArg, rcArg), target=uarch.haswell) as function:
    statePtr = GeneralPurposeRegister64()
    rcPtr = GeneralPurposeRegister64()
    superRound = GeneralPurposeRegister64()

    LOAD.ARGUMENT(statePtr, stateArg)
    LOAD.ARGUMENT(rcPtr, rcArg)

    MOV(superRound, 6)

    def state(offset):
        return [statePtr + 32*offset]

    with Loop() as loop:
        for r in range(4):
            p = [YMMRegister() for i in range(5)]
            for i in range(5): VMOVDQA(p[i], state(i))
            for j in range(1, 5):
                for i in range(5): VPXOR(p[i], p[i], state(5*j+i))

            t = [YMMRegister() for i in range(5)]
            d = [YMMRegister() for i in range(5)]

            for i in range(5): VPSLLQ(t[i], p[(i+1)%5], 1)
            for i in range(5): VPSRLQ(d[i], p[(i+1)%5], 63)
            for i in range(5): VPOR(d[i], d[i], t[i])
            for i in range(5): VPXOR(d[i], p[(i+4)%5], d[i])

            def rot(i, g):
                table = [[0, 24, 18, 6, 12],
                         [7, 23, 2, 9, 22],
                         [1, 3, 17, 16, 20],
                         [13, 8, 4, 5, 15],
                         [19, 10, 21, 14, 11]]
                t = table[g][i]
                return ((t + 1) * t // 2) % 64

            def di(i, g):
                return (3*g + i) % 5
            def si(i, g, r):
                n = [6, 16, 11, 1][r]
                m = [10, 20, 15, 5][r]
                return (i*n + m*g) % 25

            for g in range(5):
                s = [YMMRegister() for i in range(5)]
                for i in range(5):
                    VPXOR(s[i], d[di(i, g)], state(si(di(i, g), g, r)))
                for i in range(5):
                    if rot(i, g) != 0:
                        VPSLLQ(t[i], s[i], rot(i, g))
                for i in range(5):
                    if rot(i, g) != 0:
                        VPSRLQ(s[i], s[i], 64-rot(i, g))
                for i in range(5):
                    if rot(i, g) != 0:
                        VPOR(s[i], s[i], t[i])
                for i in range(5): VPANDN(t[i], s[(i+1)%5], s[(i+2)%5])
                for i in range(5): VPXOR(t[i], t[i], s[i])

                if g == 0:
                    rc = YMMRegister()
                    VPBROADCASTQ(rc, [rcPtr + r*8])
                    VPXOR(t[0], t[0], rc)
                for i in range(5):
                    VMOVDQA(state(si(i, g, r)), t[i])

        ADD(rcPtr, 8*4)
        SUB(superRound, 1)
        JNZ(loop.begin)

    RETURN ()



