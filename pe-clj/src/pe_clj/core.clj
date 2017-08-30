(ns pe-clj.core
  (:gen-class)
  (:require [clojurewerkz.buffy.core :refer :all :as buffy]
            [clojurewerkz.buffy.types :as t]))

(import '[java.io RandomAccessFile])
(import '[java.nio.channels FileChannel])
(import '[java.nio.channels FileChannel$MapMode])


(def image-dos-header-spec
  (spec :e_magic (t/ushort-type)
        :e_cblp (ushort-type)
        :e_cp (ushort-type)
        :e_crlc (ushort-type)
        :e_cparhdr (ushort-type)
        :e_minalloc (ushort-type)
        :e_maxalloc (ushort-type)
        :e_ss (ushort-type)
        :e_sp (ushort-type)
        :e_csum (ushort-type)
        :e_ip (ushort-type)
        :e_cs (ushort-type)
        :e_lfarlc (ushort-type)
        :e_ovno (ushort-type)
        :e_res (string-type 8)
        :e_oemid (ushort-type)
        :e_oeminfo (ushort-type)
        :e_res2 (string-type 8)
        :e_lfanew (uint32-type)))


(defn unpack
  [spec byte-buffer]
  (decompose (compose-buffer spec :orig-buffer byte-buffer)))


(defn parse-pe
  [byte-buffer]
  {:dos-header (unpack image-dos-header-spec byte-buffer)})


(defn read-pe
  [path]
  (let [file (RandomAccessFile. path "r")
        channel (.getChannel file)
        buffer (.map channel FileChannel$MapMode/READ_ONLY 0 (.size channel))
        _ (.load buffer)]
    (parse-pe buffer)))

