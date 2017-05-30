(ns capstone-clj.core-test
  (:require [clojure.test :refer :all]
            [capstone-clj.core :refer :all])
  (:import [capstone.Capstone]))


(deftest basic-capstone
  "
    this is the example from:
    http://www.capstone-engine.org/lang_java.html
  "
  (testing "basic capstone"
    (let [arch capstone.Capstone/CS_ARCH_X86
          mode capstone.Capstone/CS_MODE_64
          flavor capstone.Capstone/CS_OPT_SYNTAX_INTEL
          cs (capstone.Capstone. arch mode)
          _ (.setSyntax cs flavor)
          _ (.setDetail cs 1)
          code (byte-array [0x55
                            0x48
                            0x8b
                            0x05
                            0xb8
                            0x13
                            0x00
                            0x00])
          insns (.disasm cs code 0x1000)]
      (testing "disassemble"
        (is (= (alength insns) 2))
        (doseq [[i insn] (map-indexed vector insns)]
          (let [addr (.-address insn)
                mnem (.-mnemonic insn)
                op   (.-opStr insn)]
            (printf "0x%x:\t%s\t%s\n" addr mnem op)
            (condp = i
              0 (testing "first opcode"
                  (is (= addr 0x1000))
                  (is (= mnem "push")))
              1 (testing "second opcode"
                  (is (= addr 0x1001))
                  (is (= mnem "mov")))))))))))
