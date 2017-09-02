(ns lancelot-clj.core-test
  (:require [clojure.test :refer :all]
            [lancelot-clj.core :refer :all]
            [clojure.java.io :as io]))


(def fixtures (.getPath (clojure.java.io/resource "fixtures")))
(def kern32 (io/file fixtures "kernel32.dll"))


(deftest pe32-test
  (let [workspace (load-file kern32)
        nop-va 0x68901000
        call-va 0x68901032
        mov-va 0x68901010
        jnz-va 0x6890102b]
    (testing "check loader"
      (is (= :pe32 (:loader workspace))))
    (testing "fetch bytes")
      ;; TODO: figure out how to get this equality working
      ;;(is (= (seq (into [] (get-bytes workspace 0x68901000 0x8))) (seq [0x90 0x90 0x90 0x90 0x90 0x90 0x90 0x90]))))
    (testing "disassemble"
      (is (= (.-mnemonic (disassemble workspace 0x68901000)) "nop"))
      (is (= (:mnem (op->clj (disassemble workspace 0x68901000))) "nop")))
    (testing "analyze"
      (is (= true (call? (disassemble workspace call-va))))
      (is (= false (call? (disassemble workspace nop-va))))
      (is (= false (call? (disassemble workspace mov-va))))
      (is (= false (call? (disassemble workspace jnz-va))))

      (is (= true (nop? (disassemble workspace nop-va))))
      (is (= true (nop? (disassemble workspace mov-va))))  ;; this is a semantic nop
      (is (= false (nop? (disassemble workspace call-va))))
      (is (= false (nop? (disassemble workspace jnz-va))))

      (is (= true (cjmp? (disassemble workspace jnz-va))))
      (is (= false (cjmp? (disassemble workspace nop-va))))
      (is (= false (cjmp? (disassemble workspace call-va))))
      (is (= false (cjmp? (disassemble workspace mov-va))))

      (is (= false (indirect-target? (disassemble workspace call-va))))
      (is (= false (indirect-target? (disassemble workspace jnz-va)))))))
