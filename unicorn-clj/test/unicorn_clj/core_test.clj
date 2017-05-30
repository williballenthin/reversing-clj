(ns unicorn-clj.core-test
  (:require [clojure.test :refer :all]
            [unicorn-clj.core :refer :all])
  (:import [unicorn.Unicorn]))


(deftest basic-unicorn
  "
    this is the example from:
    http://www.unicorn-engine.org/docs/tutorial.html
  "
  (testing "basic unicorn"
    (let [arch unicorn.Unicorn/UC_ARCH_X86
          mode unicorn.Unicorn/UC_MODE_32
          mu (unicorn.Unicorn. arch mode)
          code (byte-array [0x41 0x4a])
          addr 0x1000000]
      (doto mu
        (.mem_map addr (* 2 1024 1024) unicorn.Unicorn/UC_PROT_EXEC)
        (.mem_write addr code)
        (.reg_write unicorn.Unicorn/UC_X86_REG_ECX 0x1234)
        (.reg_write unicorn.Unicorn/UC_X86_REG_EDX 0x7890)
        (.emu_start addr (+ addr (alength code)) 0 0))
      ;; note: return from reg_read is always 64bit
      (let [ecx (bit-and 0xFFFFFFFF (.reg_read mu unicorn.Unicorn/UC_X86_REG_ECX))
            edx (bit-and 0xFFFFFFFF (.reg_read mu unicorn.Unicorn/UC_X86_REG_EDX))]
        (printf "ecx: 0x%x\n" ecx)
        (printf "edx: 0x%x\n" edx)
        (testing "emulation"
          (is (= ecx 0x1235))
          (is (= edx 0x788f)))))))

