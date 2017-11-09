(ns lancelot-clj.dis
  (:gen-class)
  (:require [clojure.java.io :as io]
            [pantomime.mime :as panto]
            [pe.core :as pe]
            [clojure.tools.logging :as log]
            [clojure.set :as set])
  (:import (java.io RandomAccessFile))
  (:import (java.nio ByteBuffer ByteOrder))
  (:import (java.nio.channels FileChannel FileChannel$MapMode))
  (:import [capstone.Capstone])
  (:import [capstone.X86_const]))

(defn at-position
  [byte-buffer position]
  (let [byte-buffer' (.duplicate byte-buffer)]
    (.position byte-buffer' position)
    byte-buffer'))

(defn disassemble-one
  "
  disassemble a single instruction from the given bytes at the given offset.

  example::

      > (disassemble-one cs (get-section pe '.text') 0x401000 0x0)
      < #object[capstone.Capstone$CsInsn ...]
  "
  ([dis buf rva offset]
   (let [lim (.limit buf)
         remaining (- lim offset)
         arr (byte-array (min 0x10 remaining))  ;; assume each insn is at most 0x10 bytes long
         buf' (at-position buf offset)]
     (.get buf' arr)
     (first (.disasm dis arr rva 1))))
  ([dis buf rva]
   (disassemble-one dis buf rva 0x0)))

(defn chunked-pmap [f partition-size coll]
  ;; via: https://stackoverflow.com/a/19972453/87207
  (->> coll                           ; Start with original collection.

       (partition-all partition-size) ; Partition it into chunks.

       (pmap (comp doall              ; Map f over each chunk,
                   (partial map f)))  ; and use doall to force it to be
                                      ; realized in the worker thread.

       (apply concat)))               ; Concatenate the chunked results
                                      ; to form the return value.

(defn disassemble-all
  "
  disassemble instructions at all offsets in the given bytes.
  note, this includes overlapping instructions.

  example::

      > (disassemble-all cs (get-section pe '.text') 0x401000)
      < #object[capstone.Capstone$CsInsn ...]
      < #object[capstone.Capstone$CsInsn ...]
      < ...
  "
  [dis buf rva]
  (chunked-pmap (fn [offset]
                  (disassemble-one dis buf (+ rva offset) offset))
                0x10000
                (range (dec (.limit buf)))))

(defn format-insn
  "format the given  capstone instruction into a string"
  [insn]
  (when (some? insn)
    (let [addr (.-address insn)
          mnem (.-mnemonic insn)
          op   (.-opStr insn)]
      (format "0x%x %s %s" addr mnem op))))

