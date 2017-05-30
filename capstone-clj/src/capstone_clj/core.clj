(ns capstone-clj.core
  (:gen-class)
  (:import [capstone.Capstone]))



(defn -main
  "I don't do a whole lot ... yet."
  [& args]
  (println "Hello, World!")
  (let [arch capstone.Capstone/CS_ARCH_X86
        mode capstone.Capstone/CS_MODE_64
        flavor capstone.Capstone/CS_OPT_SYNTAX_INTEL
        cs (capstone.Capstone. arch mode)
        _ (.setSyntax cs flavor)
        _ (.setDetail cs 1)]
    (let [code (byte-array [0x55
                            0x48
                            0x8b
                            0x05
                            0xb8
                            0x13
                            0x00
                            0x00])
          insns (.disasm cs code 0x1000)]
      (doseq [[i insn] (map-indexed vector insns)]
        (let [addr (.-address insn)
              mnem (.-mnemonic insn)
              op   (.-opStr insn)]
          (printf "0x%x:\t%s\t%s\n" addr mnem op)))))
  (println "Goodbye, World!"))
