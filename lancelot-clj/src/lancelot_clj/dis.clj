(ns lancelot-clj.dis
  (:gen-class)
  (:require [clojure.java.io :as io]
            [pantomime.mime :as panto]
            [pe.core :as pe]
            [pe.macros :as pe-macros]
            [clojure.tools.logging :as log]
            [clojure.set :as set])
  (:import (java.io RandomAccessFile))
  (:import (java.nio ByteBuffer ByteOrder))
  (:import (java.nio.channels FileChannel FileChannel$MapMode))
  (:import [capstone.Capstone])
  (:import [capstone.X86_const]))


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
         b (pe-macros/with-position buf offset
             (.get buf arr)
             arr)]
     (first (.disasm dis arr rva 1))))
  ([dis buf rva]
   (disassemble-one dis buf rva 0x0)))


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
  (for [offset (range (dec (.limit buf)))]
    (let [insn (disassemble-one dis buf (+ rva offset) offset)]
      (when (nil? insn)
        (log/info "failed to disassemble: 0x%x" (+ rva offset)))
      insn)))

