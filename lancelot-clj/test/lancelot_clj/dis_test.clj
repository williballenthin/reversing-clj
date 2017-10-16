(ns lancelot-clj.dis-test
  (:require [clojure.test :refer :all]
            [lancelot-clj.dis :refer :all]
            [lancelot-clj.testutils :refer :all]
            [clojure.java.io :as io])
  (:import (java.nio ByteBuffer ByteOrder))
  (:import [capstone.Capstone])
  (:import [capstone.X86_const]))


(deftest dis-test
  (let [cs (make-capstone capstone.Capstone/CS_ARCH_X86 capstone.Capstone/CS_MODE_32)
        buf (make-byte-buffer [0x55                       ;;   push   ebp
                               0x89 0xe5                  ;;   mov    ebp,esp
                               0x83 0xec 0x1 0            ;;   sub    esp,0x10
                               0xb8 0x01 0x00 0x00 0x00   ;;   mov    eax,0x1
                               0x50])]                    ;;   push   eax
    (testing "disasm-one"
      (let [i0 (disassemble-one cs buf 0x0)]
        (is (= (.-address i0) 0x0))
        (is (= (.-mnemonic i0) "push"))
        (is (= (.-opStr i0) "ebp")))
      (let [i1 (disassemble-one cs buf 0x1 0x1)]
        (is (= (.-address i1) 0x1))
        (is (= (.-mnemonic i1) "mov"))
        (is (= (.-opStr i1) "ebp, esp")))
      ;; here's an overlapping instruction at offset 0x2
      (let [i2 (disassemble-one cs buf 0x2 0x2)]
        (is (= (.-address i2) 0x2))
        (is (= (.-mnemonic i2) "in"))
        (is (= (.-opStr i2) "eax, -0x7d"))))
    (testing "disasm-all"
      (let [insns (into [] (map format-insn (disassemble-all cs buf 0x0)))]
        (is (= (nth insns 0) "0x0 push ebp"))
        (is (= (nth insns 1) "0x1 mov ebp, esp"))
        ;; note this is overlapping the mov above
        (is (= (nth insns 2) "0x2 in eax, -0x7d"))))))
