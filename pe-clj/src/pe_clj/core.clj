(ns pe-clj.core
  (:gen-class)
  (:require [clojurewerkz.buffy.core :refer :all :as buffy]
            [clojurewerkz.buffy.types :as t])
  (:import (java.io RandomAccessFile))
  (:import (java.nio ByteBuffer ByteOrder))
  (:import (java.nio.channels FileChannel FileChannel$MapMode)))


(def image-dos-header-spec
  (buffy/spec :e_magic (t/ushort-type)  ;; "MZ"  0x5A4D
              :e_cblp (t/ushort-type)
              :e_cp (t/ushort-type)
              :e_crlc (t/ushort-type)
              :e_cparhdr (t/ushort-type)
              :e_minalloc (t/ushort-type)
              :e_maxalloc (t/ushort-type)
              :e_ss (t/ushort-type)
              :e_sp (t/ushort-type)
              :e_csum (t/ushort-type)
              :e_ip (t/ushort-type)
              :e_cs (t/ushort-type)
              :e_lfarlc (t/ushort-type)
              :e_ovno (t/ushort-type)
              :e_res (t/repeated-type (t/ushort-type) 4)
              :e_oemid (t/ushort-type)
              :e_oeminfo (t/ushort-type)
              :e_res (t/repeated-type (t/ushort-type) 10)
              :e_lfanew (t/uint32-type)))


(defn unpack
  [spec byte-buffer]
  (buffy/decompose (buffy/compose-buffer spec :orig-buffer byte-buffer)))


(defn parse-pe
  [byte-buffer]
  {:dos-header (unpack image-dos-header-spec byte-buffer)})


(defn map-file
  [path]
  (let [file (RandomAccessFile. path "r")
        channel (.getChannel file)
        buffer (.map channel FileChannel$MapMode/READ_ONLY 0 (.size channel))
        _ (.load buffer)
        _ (.order buffer ByteOrder/LITTLE_ENDIAN)]
    buffer))


(defn read-pe
  [path]
  (parse-pe (map-file path)))
