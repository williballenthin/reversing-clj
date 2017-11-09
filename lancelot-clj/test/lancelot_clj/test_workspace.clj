(ns lancelot-clj.test-workspace
  (:require [clojure.test :refer :all]
            [lancelot-clj.anal :as analysis]
            [lancelot-clj.core :as core]
            [lancelot-clj.workspace :as workspace]
            [clojure.java.io :as io]))


(def fixtures (.getPath (clojure.java.io/resource "fixtures")))
(def kern32 (io/file fixtures "kernel32.dll"))


(deftest pe32-test
  (let [workspace (workspace/load-binary kern32)
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
      (is (= (.-mnemonic (workspace/disassemble workspace 0x68901000)) "nop")))))
