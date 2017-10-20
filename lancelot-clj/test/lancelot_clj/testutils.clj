(ns lancelot-clj.testutils
  (:require[clojure.java.io :as io])
  (:import (java.nio ByteBuffer ByteOrder))
  (:import [capstone.Capstone])
  (:import [capstone.X86_const]))


(defn make-byte-buffer
  [byte-list]
  (let [bytes (byte-array byte-list)
        byte-buffer (ByteBuffer/allocate (count bytes))
        _ (.put byte-buffer bytes)
        _ (.order byte-buffer ByteOrder/LITTLE_ENDIAN)]
    byte-buffer))


;; via: https://stackoverflow.com/a/29587909
(defn boolean? [x]
  (instance? Boolean x))


(defn make-capstone
  ([arch mode detail]
   (let [cs (capstone.Capstone. arch mode)
         _ (.setSyntax cs capstone.Capstone/CS_OPT_SYNTAX_INTEL)
         _ (.setDetail cs (if (boolean? detail)
                            (if detail 1 0)
                            detail))]
     cs))
  ([arch mode]
   (make-capstone arch mode 1)))


(defn format-insn
  "format the given  capstone instruction into a string"
  [insn]
  (when (some? insn)
    (let [addr (.-address insn)
          mnem (.-mnemonic insn)
          op   (.-opStr insn)]
      (format "0x%x %s %s" addr mnem op))))
