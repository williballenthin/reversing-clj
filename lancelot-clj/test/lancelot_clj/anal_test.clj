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

(defn index-by
  "
  create a map indexed by the given key of the given collection.
  
  example::

      (index-by [{:a 1 :b 2} {:a 3 :b 4}] :a)
      => {1 {:a 1 :b 2}
          3 {:a 3 :b 4}}
  "
  [col k]
  (into {} (map #(vector (get % k) %) col)))


(deftest analysis-test
  (let [cs (make-capstone capstone.Capstone/CS_ARCH_X86 capstone.Capstone/CS_MODE_32)
        base-addr 0x816044
        buf (make-byte-buffer [0x55              ;; push    ebp
                               0x89 0xE5         ;; mov     ebp, esp
                               0x50              ;; push    eax
                               0x53              ;; push    ebx
                               0x51              ;; push    ecx
                               0x56              ;; push    esi
                               0x8B 0x75 0x08    ;; mov     esi, [ebp+arg_0]
                               0x8B 0x4D 0x0C    ;; mov     ecx, [ebp+arg_4]
                               0xC1 0xE9 0x02    ;; shr     ecx, 2
                               0x8B 0x45 0x10    ;; mov     eax, [ebp+arg_8]
                               0x8B 0x5D 0x14    ;; mov     ebx, [ebp+arg_C]
                               ;; loc_81605A:        ; CODE XREF: sub_816044+22
                               0x85 0xC9         ;; test    ecx, ecx
                               0x74 0x0A         ;; jz      short loc_816068            <<--- cjmp
                               0x31 0x06         ;; xor     [esi], eax
                               0x01 0x1E         ;; add     [esi], ebx
                               0x83 0xC6 0x04    ;; add     esi, 4
                               0x49              ;; dec     ecx
                               0xEB 0xF2         ;; jmp     short loc_81605A            <<--- jmp, no fallthrough
                               ;; loc_816068:        ; CODE XREF: sub_816044+18
                               0x5E              ;; pop     esi
                               0x59              ;; pop     ecx
                               0x5B              ;; pop     ebx
                               0x58              ;; pop     eax
                               0xC9              ;; leave
                               0xC2 0x10 0x00])] ;; retn    10h                         <<--- ret, no fallthrough

    (testing "disasm"
      (let [i0 (disassemble-one cs buf base-addr)]
        (is (= (.-address i0) base-addr))
        (is (= (.-mnemonic i0) "push"))
        (is (= (.-opStr i0) "ebp")))
      (let [insns (into [] (map format-insn (disassemble-all cs buf base-addr)))]
        (is (= (nth insns 0) "0x816044 push ebp"))
        (is (= (nth insns 1) "0x816045 mov ebp, esp"))
        ;; note this is overlapping the mov above
        (is (= (nth insns 2) "0x816046 in eax, 0x50"))))
    (testing "flow-analysis"
      (let [raw-insns (disassemble-all cs buf base-addr)
            insns (into [] (map analyze-instruction raw-insns))
            insns-by-addr (index-by insns :address)]
        ;; this is the initial `push ebp` instruction.
        ;; just a single flow: fallthrough to next insn.
        (is (= (:flow (get insns-by-addr base-addr))
               #{{:type :fall-through 
                  :address (+ 0x1 base-addr)}}))
        ;; this is the `jz 0x816068` instruction.
        ;; two flows:
        ;;   - fallthrough to next insn.
        ;;   - cjmp to 0x816068
        (is (= (:flow (get insns-by-addr (+ 0x18 base-addr)))
               #{{:type :fall-through 
                  :address (+ 0x1A base-addr)}
                 {:type :cjmp
                  :address 0x816068}}))))))


(let [cs (make-capstone capstone.Capstone/CS_ARCH_X86 capstone.Capstone/CS_MODE_32)
      base-addr 0x816044
      buf (make-byte-buffer [0x55              ;; push    ebp
                             0x89 0xE5         ;; mov     ebp, esp
                             0x50              ;; push    eax
                             0x53              ;; push    ebx
                             0x51              ;; push    ecx
                             0x56              ;; push    esi
                             0x8B 0x75 0x08    ;; mov     esi, [ebp+arg_0]
                             0x8B 0x4D 0x0C    ;; mov     ecx, [ebp+arg_4]
                             0xC1 0xE9 0x02    ;; shr     ecx, 2
                             0x8B 0x45 0x10    ;; mov     eax, [ebp+arg_8]
                             0x8B 0x5D 0x14    ;; mov     ebx, [ebp+arg_C]
                             ;; loc_81605A:        ; CODE XREF: sub_816044+22
                             0x85 0xC9         ;; test    ecx, ecx
                             0x74 0x0A         ;; jz      short loc_816068            <<--- cjmp, base-addr+0x18
                             0x31 0x06         ;; xor     [esi], eax
                             0x01 0x1E         ;; add     [esi], ebx
                             0x83 0xC6 0x04    ;; add     esi, 4
                             0x49              ;; dec     ecx
                             0xEB 0xF2         ;; jmp     short loc_81605A            <<--- jmp, no fallthrough
                             ;; loc_816068:        ; CODE XREF: sub_816044+18
                             0x5E              ;; pop     esi
                             0x59              ;; pop     ecx
                             0x5B              ;; pop     ebx
                             0x58              ;; pop     eax
                             0xC9              ;; leave
                             0xC2 0x10 0x00]) ;; retn    10h                         <<--- ret, no fallthrough
      insns (into [] (map analyze-instruction (disassemble-all cs buf base-addr)))
      insns-by-addr (index-by insns :address)]
  (format-insn (:insn (get insns-by-addr (+ 0x18 base-addr))))
  (get insns-by-addr (+ 0x18 base-addr)))
  ;;(:flow (get insns-by-addr (+ 0x18 base-addr))))
