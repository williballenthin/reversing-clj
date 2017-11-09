(ns lancelot-clj.workspace
  (:require
   [clojure.set :as set]
   [clojure.java.io :as io]
   [clojure.string :as string]
   [clojure.tools.logging :as log]
   [pantomime.mime :as panto]
   [pe.core :as pe]
   [lancelot-clj.dis :refer :all]
   [lancelot-clj.anal :refer :all]
   )
  (:import (java.io RandomAccessFile))
  (:import (java.nio ByteBuffer ByteOrder))
  (:import (java.nio.channels FileChannel FileChannel$MapMode))
  (:import [java.security MessageDigest])
  (:import [capstone.Capstone])
  (:import [capstone.X86_const])
  )

(defn- hex
  [i]
  (format "%X" i))

(defn- conj-if [c e]
  (if (not (nil? e))
    (conj c e)
    c))

(defn- assoc-if [m k e]
  (if (not (nil? e))
    (assoc m k e)
    m))

(defn map-file
  [path]
  (let [file (RandomAccessFile. path "r")
        channel (.getChannel file)
        buffer (.map channel FileChannel$MapMode/READ_ONLY 0 (.size channel))
        _ (.load buffer)
        _ (.order buffer ByteOrder/LITTLE_ENDIAN)]
    buffer))

(defn panto-taste
  [byte-buffer]
  (let [byte-buffer' (at-position byte-buffer 0)
        arr (byte-array 0x100)  ;; should be able to get by with a 256 byte taste of the header.
        _ (.get byte-buffer' arr)]
    ;; delegate to pantomime, which asks apache tika.
    ;; overkill, but easy.
    (panto/mime-type-of arr)))

(defn pe32?
  [byte-buffer]
  (let [sig (panto-taste byte-buffer)]
    (or
     (= "application/x-msdownload; format=pe32" sig)
     (= "application/x-msdownload" sig))))

(defn detect-file-type
  [byte-buffer]
  (cond
    (pe32? byte-buffer) :pe32
    :default :unknown))

(defmulti load-bytes detect-file-type)

(defn map-pe-header
  [pe]
  (let [base-addr (get-in pe [:nt-header :optional-header :ImageBase])
        header-size (get-in pe [:nt-header :optional-header :SizeOfHeaders])]
    {:start base-addr
     :end (+ base-addr header-size)
     :name "header"
     :permissions #{:read}
     ;; TODO: remove `dec` once rebuild pe.
     :data (pe/get-data pe 0 (dec header-size))}))

(defn map-pe-section
  [pe section]
  (let [start (+ (:VirtualAddress section) (get-in pe [:nt-header :optional-header :ImageBase]))]
    {:start start
     :end (+ start (:VirtualSize section))
     :name (:Name section)
     :data (pe/get-section pe (:Name section))
     ;; TODO: correctly compute permissions.
     :permissions #{:read :write :execute}
     :meta section}))

(defn map-pe
  [pe]
  (into [(map-pe-header pe)]
        (map #(map-pe-section pe %)
             (vals (:section-headers pe)))))

(defmethod load-bytes :pe32
  [byte-buffer]
  (let [pe (pe/parse-pe byte-buffer)
        cs (capstone.Capstone. capstone.Capstone/CS_ARCH_X86 capstone.Capstone/CS_MODE_32)
        _ (.setSyntax cs capstone.Capstone/CS_OPT_SYNTAX_INTEL)
        _ (.setDetail cs 1)]
    {:loader :pe32
     :byte-buffer byte-buffer
     :pe pe
     :map (map-pe pe)
     :dis cs}))

(defn byte-buffer-size
  [byte-buffer]
  (let [byte-buffer' (at-position byte-buffer 0)]
    (.limit byte-buffer')))

(defn byte-buffer->byte-array
  [byte-buffer]
  (let [byte-buffer' (at-position byte-buffer 0)
        size (byte-buffer-size byte-buffer')
        buf (byte-array size)]
    (.get byte-buffer' buf)
    buf))

(defn get-hash
  [byte-buffer algo]
  (let [bytes (byte-buffer->byte-array byte-buffer) ;; TODO: watch memory size. could do this in chunks.
        md5 (MessageDigest/getInstance algo)
        hash (.digest md5 bytes)]
    (string/join "" (map hex hash))))

(defn get-hashes
  [byte-buffer]
  (into {} (for [[kw algo] {:md5 "MD5"
                   :sha1 "SHA-1"
                   :sha256 "SHA-256"}]
             [kw (get-hash byte-buffer algo)])))

(defn get-bytes
  [workspace va length]
  (let [region (first (filter #(and (<= (:start %) va)
                                    (< va (:end %)))
                              (:map workspace)))
        rva (- va (:start region))
        arr (byte-array length)
        data (:data region)
        data' (at-position data rva)]
    (.get data' arr)
    arr))

(defn disassemble
  [workspace va]
  (let [code (get-bytes workspace va 0x10)]  ;; 0x10 is an arbitrary max-insn-length constant
    (first (.disasm (:dis workspace) code va 1))))

(defn op->clj
  "
  converts a disassembled instruction into a clojure map.
  useful for debugging.
  "
  [op]
  {:address (.-address op)
   :mnem (.-mnemonic op)
   :op (.-opStr op)})

(defn load-binary
  [path]
  (let [buf (map-file path)]
    (load-bytes buf)))
