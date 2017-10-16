(ns lancelot-clj.anal-test
  (:require [clojure.test :refer :all]
            [lancelot-clj.dis :refer :all]
            [lancelot-clj.anal :refer :all]
            [lancelot-clj.testutils :refer :all]
            [clojure.java.io :as io])
  (:import (java.nio ByteBuffer ByteOrder))
  (:import [capstone.Capstone])
  (:import [capstone.X86_const]))


(defmethod print-method Number
  [n ^java.io.Writer w]
  (.write w (format "0x%X" n)))


(defn index-by'
  "
  create a map indexed by the given key of the given collection.
  like `group-by`, except its assumed there's only one value per key.

  example::

      (index-by [{:a 1 :b 2} {:a 3 :b 4}] :a)
      => {1 {:a 1 :b 2}
          3 {:a 3 :b 4}}
  "
  [col k]
  (into {} (map #(vector (get % k) %) col)))


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
      (let [insns (into [] (map format-insn (disassemble-all cs buf base-addr)))]
        (is (= (nth insns 0) "0x0 push ebp"))
        (is (= (nth insns 1) "0x1 mov ebp, esp"))
        ;; note this is overlapping the mov above
        (is (= (nth insns 2) "0x2 in eax, 0x50"))))
    (testing "flow-analysis"
      (let [raw-insns (disassemble-all cs buf base-addr)
            insns (into [] (map analyze-instruction raw-insns))
            insns-by-addr (index-by insns :address)
            flows-by-src (group-by :src (flows insns))
            flows-by-dst (group-by :dst (flows insns))]
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
    (testing "cfg-analysis"
      (let [cfg (make-cfg (map analyze-instruction (disassemble-all cs buf base-addr)))]
        ;; the `push ebp` instruction is the first in the cfg, so its a root.
        (is (= true (contains? (:roots cfg) 0x0)))
        ;; however, `mov ebp, esp` is reached from the prev insn/byte, so not a root.
        (is (= false (contains? (:roots cfg) 0x1)))
        ;; the first insn is not a leave, since it falls through to next insn.
        (is (= false (contains? (:leaves cfg) 0x0)))
        ;; the last insn, the `ret`, is a leaf, cause it has no successor insns.
        (is (= true (contains? (:leaves cfg) 0x29)))))
    (testing "fallthrough-sequence-analysis"
      (let [raw-insns (disassemble-all cs buf base-addr)
            insns (into [] (map analyze-instruction raw-insns))
            insns-by-addr (index-by insns :address)]
        ;; this is the "basic block" from the entry (+0x0) until the jz (+0x18).
        ;; ends with a conditional jump.
        (let [bb0 (into #{} (read-fallthrough-sequence insns-by-addr 0x0))]
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
        (let [bb1 (into #{} (read-fallthrough-sequence insns-by-addr 0x1A))]
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
        (let [bb2 (into #{} (read-fallthrough-sequence insns-by-addr 0x24))]
          ;; the `pop esi` at +0x24
          (is (= true (contains? bb2 0x24)))
          (is (= false (contains? bb2 0x23)))
          ;; the `ret` at +0x29
          (is (= true (contains? bb2 0x29)))
          (is (= false (contains? bb2 0x2A))))))
    (testing "reachable-instruction-analysis"
      (let [raw-insns (disassemble-all cs buf base-addr)
            insns (into [] (map analyze-instruction raw-insns))
            insns-by-addr (index-by insns :address)
            reachable-insns (find-reachable-addresses insns-by-addr 0x0)]
        (is (= reachable-insns [0x0 0x1 0x3 0x4 0x5
                                0x6 0x7 0xA 0xD 0x10
                                0x13 0x16 0x18 0x1a
                                0x1c 0x1e 0x21 0x22
                                0x24 0x25 0x26 0x27
                                0x28 0x29]))))
    (testing "bb-analysis"
      (let [raw-insns (disassemble-all cs buf base-addr)
            insns (into [] (map analyze-instruction raw-insns))
            insns-by-addr (index-by insns :address)]
        (is (= (read-basic-block insns-by-addr 0x0)
               ;; all instructions before `test ecx, ecx` at 0x16.
               [0x0 0x1 0x3 0x4 0x5 0x6 0x7 0xA 0xD 0x10 0x13]))
        (is (= (read-basic-block insns-by-addr 0x16)
               [0x16 0x18]))
        (is (= (read-basic-block insns-by-addr 0x1A)
               [0x1a 0x1c 0x1e 0x21 0x22]))
        (is (= (read-basic-block insns-by-addr 0x24)
               [0x24 0x25 0x26 0x27 0x28 0x29]))))))


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
                             0xC2 0x10 0x00])  ;; 29 retn    10h                  <<--- ret, no fallthrough
      insns (into [] (map analyze-instruction (disassemble-all cs buf base-addr)))
      insns-by-addr (index-by insns :address)
      fl (into [] (flows insns))
      flows-by-src (group-by :src fl)
      flows-by-dst (group-by :dst fl)
      reachable-addrs (into #{} (find-reachable-addresses insns-by-addr 0x0))]
  ;;(map format-insn (disassemble-all cs buf base-addr)))
  ;;(read-bb insns-by-addr base-addr))
  (read-basic-block insns-by-addr 0x0))
;;             last-insn (get insns-by-addr (last run))
;;             flow-addrs (mapv :addr (:flow last-insn))))
  ;;(:flow (get insns-by-addr 0x18)))



    ;;(< 1 (count (filter reachable-addrs (map :src (get flows-by-dst addr))))) (conj bb-addrs addr)))
    ;;(filter reachable-addrs (mapv :src (get flows-by-dst 0x4))))

