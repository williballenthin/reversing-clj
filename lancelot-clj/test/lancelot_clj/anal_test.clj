(ns lancelot-clj.anal-test
  (:require [clojure.test :refer :all]
            [pe.core :as pe]
            [lancelot-clj.dis :refer :all]
            [lancelot-clj.anal :refer :all]
            [lancelot-clj.core :refer [load-binary]]
            [lancelot-clj.testutils :refer :all]
            [clojure.java.io :as io])
  (:import (java.nio ByteBuffer ByteOrder))
  (:import [capstone.Capstone])
  (:import [capstone.X86_const]))


(deftest analysis-test
  (let [cs (make-capstone capstone.Capstone/CS_ARCH_X86 capstone.Capstone/CS_MODE_32)
        base-addr 0x0
        buf (make-byte-buffer [0x55              ;; 0  push    ebp
                               0x89 0xE5         ;; 1  mov     ebp, esp
                               0x50              ;; 3  push    eax
                               0x53              ;; 4  push    ebx
                               0x51              ;; 5  push    ecx
                               0x56              ;; 6  push    esi
                               0x8B 0x75 0x08    ;; 7  mov     esi, [ebp+arg_0]
                               0x8B 0x4D 0x0C    ;; A  mov     ecx, [ebp+arg_4]
                               0xC1 0xE9 0x02    ;; D  shr     ecx, 2
                               0x8B 0x45 0x10    ;; 10 mov     eax, [ebp+arg_8]
                               0x8B 0x5D 0x14    ;; 13 mov     ebx, [ebp+arg_C]
                               ;; 16:        ; CODE XREF: +22
                               0x85 0xC9         ;; 16 test    ecx, ecx
                               0x74 0x0A         ;; 18 jz      short +24            <<--- cjmp
                               0x31 0x06         ;; 1A xor     [esi], eax
                               0x01 0x1E         ;; 1C add     [esi], ebx
                               0x83 0xC6 0x04    ;; 1E add     esi, 4
                               0x49              ;; 21 dec     ecx
                               0xEB 0xF2         ;; 22 jmp     short +16            <<--- jmp, no fallthrough
                               ;; 24:        ; CODE XREF: +18
                               0x5E              ;; 24 pop     esi
                               0x59              ;; 25 pop     ecx
                               0x5B              ;; 26 pop     ebx
                               0x58              ;; 27 pop     eax
                               0xC9              ;; 28 leave
                               0xC2 0x10 0x00])] ;; 29 retn    10h                  <<--- ret, no fallthrough

    (testing "disasm"
      (let [i0 (disassemble-one cs buf base-addr)]
        (is (= (.-address i0) base-addr))
        (is (= (.-mnemonic i0) "push"))
        (is (= (.-opStr i0) "ebp")))
      (let [insns (into [] (map format-insn (sort-by #(.address %) (disassemble-all cs buf base-addr))))]
        (is (= (nth insns 0) "0x0 push ebp"))
        (is (= (nth insns 1) "0x1 mov ebp, esp"))
        ;; note this is overlapping the mov above
        (is (= (nth insns 2) "0x2 in eax, 0x50"))))
    (testing "flow-analysis"
      (let [raw-insns (disassemble-all cs buf base-addr)
            insns (into [] (map analyze-instruction raw-insns))
            insns-by-addr (index-by insns :address)
            flows-by-src (group-by :src (compute-instruction-flows insns))
            flows-by-dst (group-by :dst (compute-instruction-flows insns))]
        ;; this is the initial `push ebp` instruction.
        ;; just a single flow: fallthrough to next insn.
        (is (= (:flow (get insns-by-addr base-addr))
               #{{:type :fall-through
                  :address 0x1}}))
        ;; this is the `jz +24` instruction.
        ;; two flows:
        ;;   - fallthrough to next insn.
        ;;   - cjmp to +24
        (is (= (:flow (get insns-by-addr 0x18))
               #{{:type :fall-through
                  :address 0x1A}
                 {:type :cjmp
                  :address 0x24}}))
        ;; only flow from the `push ebp` is the fallthrough.
        (is (= 1 (count (get flows-by-src 0x0))))
        ;; the `jz ...` has two possible next instructions.
        (is (= 2 (count (get flows-by-src 0x18))))
        ;; entrypoint has no flows to it.
        (is (= 0 (count (get flows-by-dst 0x0))))
        ;; the `mov ebp, esp` instruction can only be reached from `push ebp`.
        (is (= 1 (count (get flows-by-dst 0x1))))
        ;; the `test ecx, ecx` instruction has two ways to get to it:
        ;;   - fallthrough from previous instruction.
        ;;   - jmp from address +22
        (is (= 2 (count (get flows-by-dst 0x16))))))
    (testing "fallthrough-sequence-analysis"
      (let [raw-insns (disassemble-all cs buf base-addr)
            insn-analysis (analyze-instructions raw-insns)]
        ;; this is the "basic block" from the entry (+0x0) until the jz (+0x18).
        ;; ends with a conditional jump.
        (let [bb0 (into #{} (read-fallthrough-sequence insn-analysis 0x0))]
          ;; first two instructions are in the basic block.
          (is (= true (contains? bb0 0x0)))
          (is (= true (contains? bb0 0x1)))
          ;; the overlapping instruction at 0x2 is not.
          (is (= false (contains? bb0 0x2)))
          ;; the `test ecx, ecx` insn in part of these fallthrough instructions.
          ;; however, it is not actually part of the basic block, because its split by the jmp.
          (is (= true (contains? bb0 0x16)))
          ;; the `jz` is part of the sequence, but nothing after it.
          (is (= true (contains? bb0 0x18)))
          (is (= false (contains? bb0 0x19)))
          (is (= false (contains? bb0 0x1A))))
        ;; this is the "basic block" from the `xor` (+0x1A) until the `jmp` (+0x22).
        ;; ends with an unconditional jump (non-fallthrough instruction).
        (let [bb1 (into #{} (read-fallthrough-sequence insn-analysis 0x1A))]
          ;; the xor at +0x1A
          (is (= true (contains? bb1 0x1A)))
          (is (= false (contains? bb1 0x19)))
          (is (= false (contains? bb1 0x1B)))
          ;; the jmp at +0x22
          (is (= true (contains? bb1 0x22)))
          (is (= false (contains? bb1 0x23)))
          (is (= false (contains? bb1 0x24))))
        ;; this is the "basic block" from the `pop esi` (+0x24) until the `ret` (+0x29).
        ;; ends with an instruction with no successors.
        (let [bb2 (into #{} (read-fallthrough-sequence insn-analysis 0x24))]
          ;; the `pop esi` at +0x24
          (is (= true (contains? bb2 0x24)))
          (is (= false (contains? bb2 0x23)))
          ;; the `ret` at +0x29
          (is (= true (contains? bb2 0x29)))
          (is (= false (contains? bb2 0x2A))))))
    (testing "reachable-instruction-analysis"
      (let [raw-insns (disassemble-all cs buf base-addr)
            insn-analysis (analyze-instructions raw-insns)
            reachable-insns (find-reachable-addresses insn-analysis 0x0)]
        (is (= reachable-insns #{0x0 0x1 0x3 0x4 0x5
                                 0x6 0x7 0xA 0xD 0x10
                                 0x13 0x16 0x18 0x1a
                                 0x1c 0x1e 0x21 0x22
                                 0x24 0x25 0x26 0x27
                                 0x28 0x29}))))
    (testing "bb-analysis"
      (let [raw-insns (disassemble-all cs buf base-addr)
            insn-analysis (analyze-instructions raw-insns)]
        (is (= (read-basic-block insn-analysis 0x0)
               ;; all instructions before `test ecx, ecx` at 0x16.
               [0x0 0x1 0x3 0x4 0x5 0x6 0x7 0xA 0xD 0x10 0x13]))
        (is (= (read-basic-block insn-analysis 0x16)
               [0x16 0x18]))
        (is (= (read-basic-block insn-analysis 0x1A)
               [0x1a 0x1c 0x1e 0x21 0x22]))
        (is (= (read-basic-block insn-analysis 0x24)
               [0x24 0x25 0x26 0x27 0x28 0x29]))))
    (testing "function analysis"
      (let [raw-insns (disassemble-all cs buf base-addr)
            insn-analysis (analyze-instructions raw-insns)
            bbs (get-function-blocks insn-analysis base-addr)]
        (is (= (sort (keys bbs)) (list 0x0 0x16 0x1A 0x24))))))
  (let [cs (make-capstone capstone.Capstone/CS_ARCH_X86 capstone.Capstone/CS_MODE_32)
        buf (make-byte-buffer [;;00000000 <A>:
                               ;;0:  b8 01 00 00 00          mov    eax,0x1
                               ;;5:  e8 01 00 00 00          call   b <B>
                               ;;a:  c3                      ret
                               ;;0000000b <B>:
                               ;;b:  b8 02 00 00 00          mov    eax,0x2
                               ;;10: e8 01 00 00 00          call   16 <C>
                               ;;15: c3                      ret
                               ;;00000016 <C>:
                               ;;16: b8 03 00 00 00          mov    eax,0x3
                               ;;1b: e8 e0 ff ff ff          call   0 <A>
                               ;;20: c3                      ret
                               0xB8, 0x01, 0x00, 0x00, 0x00,
                               0xE8, 0x01, 0x00, 0x00, 0x00,
                               0xC3,
                               0xB8, 0x02, 0x00, 0x00, 0x00,
                               0xE8, 0x01, 0x00, 0x00, 0x00,
                               0xC3,
                               0xB8, 0x03, 0x00, 0x00, 0x00,
                               0xE8, 0xE0, 0xFF, 0xFF, 0xFF,
                               0xC3])
        raw-insns (disassemble-all cs buf 0x0)
        insn-analysis (analyze-instructions raw-insns)]
    (testing "find-function-targets"
      (is (= '(0xB) (find-function-targets insn-analysis 0x0)))
      (is (= '(0x16) (find-function-targets insn-analysis 0xB)))
      (is (= '(0x0) (find-function-targets insn-analysis 0x16))))
    (testing "find-functions"
      (is (= #{0x0 0xB 0x16} (find-functions insn-analysis (list 0x0)))))))
