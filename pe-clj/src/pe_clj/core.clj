(ns pe-clj.core
  (:gen-class)
  (:require [clojurewerkz.buffy.core :refer :all :as buffy]
            [clojurewerkz.buffy.types :as t]
            [clojure.java.io :as io]
            [pe-clj.macros :refer :all]
            [clojure.tools.logging :as log])
  (:import (java.io RandomAccessFile))
  (:import (java.nio ByteBuffer ByteOrder))
  (:import (java.nio.channels FileChannel FileChannel$MapMode)))


(defn hex
  [i]
  (format "%X" i))


(defn slice
  ([byte-buffer start end]
   (let [p (.position byte-buffer)]
     ;; TODO: would be nice to have a with-position macro
     (.position byte-buffer start)
     (let [slice (.slice byte-buffer)
           slice-size (- end start)]
       (.position byte-buffer p)
       (.order slice (.order byte-buffer))
       ;; if end is greater than the limit, truncate to limit.
       (when (> (.limit slice) slice-size)
         (.limit slice slice-size))
       slice)))
  ([byte-buffer start]
   (slice byte-buffer start (.limit byte-buffer))))


(defn read-ascii
  "
  read an ascii string from the given byte buffer at the given offset.
  "
  ([byte-buffer]
   ;; since we `.get`, then lets make sure to restore the position.
   (with-position byte-buffer 0x0
     (loop [c (.get byte-buffer)
            s []]
       ;; `.get` returns bytes, which are signed.
       ;; ascii is 7-bit, so the top bit should not be set, aka, should not be negative.
       (if (<= c 0x0)
         (apply str (map char (byte-array s)))
         (recur (.get byte-buffer)
                (conj s c))))))
  ([byte-buffer offset]
   (read-ascii (slice byte-buffer offset))))


(defn spec-size
  [spec]
  (apply + (map #(.size (second %)) spec)))


(defn unpack
  ([spec byte-buffer]
   (buffy/decompose (buffy/compose-buffer spec :orig-buffer byte-buffer)))
  ([spec byte-buffer offset]
   (unpack spec (slice byte-buffer offset))))


(def ^:const image-dos-header-spec
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

(def ^:const signature-spec
  (buffy/spec :Signature (t/uint32-type)))  ;; "PE"


(def ^:const IMAGE_FILE_MACHINE_I386 0x14C)

(def ^:const image-file-header-spec
  (buffy/spec :Machine (t/ushort-type)
              :NumberOfSections (t/ushort-type)
              :TimeDateStamp (t/uint32-type)
              :PointerToSymbolTable (t/uint32-type)
              :NumberOfSymbols (t/uint32-type)
              :SizeOfOptionalHeader (t/ushort-type)
              :Characteristics (t/ushort-type)))

(def ^:const IMAGE_NT_OPTIONAL_HDR32_MAGIC 0x10B)

(def ^:const optional-header-spec
  (buffy/spec :Magic (t/ushort-type)
              :MajorLinkerVersion (t/ubyte-type)
              :MinorLinkerVersion (t/ubyte-type)
              :SizeOfCode (t/uint32-type)
              :SizeOfInitializedData (t/uint32-type)
              :SizeOfUninitializedData (t/uint32-type)
              :AddressOfEntryPoint (t/uint32-type)
              :BaseOfCode (t/uint32-type)
              :BaseOfData (t/uint32-type)
              :ImageBase (t/uint32-type)
              :SectionAlignment (t/uint32-type)
              :FileAlignment (t/uint32-type)
              :MajorOperatingSystemVersion (t/ushort-type)
              :MinorOperatingSystemVersion (t/ushort-type)
              :MajorImageVersion (t/ushort-type)
              :MinorImageVersion (t/ushort-type)
              :MajorSubsystemVersion (t/ushort-type)
              :MinorSubsystemVersion (t/ushort-type)
              :Reserved1 (t/uint32-type)
              :SizeOfImage (t/uint32-type)
              :SizeOfHeaders (t/uint32-type)
              :CheckSum (t/uint32-type)
              :Subsystem (t/ushort-type)
              :DllCharacteristics (t/ushort-type)
              :SizeOfStackReserve (t/uint32-type)
              :SizeOfStackCommit (t/uint32-type)
              :SizeOfHeapReserve (t/uint32-type)
              :SizeOfHeapCommit (t/uint32-type)
              :LoaderFlags (t/uint32-type)
              :NumberOfRvaAndSizes (t/uint32-type)))


(def ^:const IMAGE_DIRECTORY_ENTRY_EXPORT 0)
(def ^:const IMAGE_DIRECTORY_ENTRY_IMPORT 1)
(def ^:const IMAGE_DIRECTORY_ENTRY_RESOURCE 2)
(def ^:const IMAGE_DIRECTORY_ENTRY_EXCEPTION 3)
(def ^:const IMAGE_DIRECTORY_ENTRY_SECURITY 4)
(def ^:const IMAGE_DIRECTORY_ENTRY_BASERELOC 5)
(def ^:const IMAGE_DIRECTORY_ENTRY_DEBUG 6)
;; Architecture on non-x86 platforms
(def ^:const IMAGE_DIRECTORY_ENTRY_COPYRIGHT 7)
(def ^:const IMAGE_DIRECTORY_ENTRY_GLOBALPTR 8)
(def ^:const IMAGE_DIRECTORY_ENTRY_TLS 9)
(def ^:const IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG 10)
(def ^:const IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT 11)
(def ^:const IMAGE_DIRECTORY_ENTRY_IAT 12)
(def ^:const IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT 13)
(def ^:const IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14)
(def ^:const IMAGE_DIRECTORY_ENTRY_RESERVED 15)


(def ^:const data-directory-spec
  (buffy/spec :rva (t/uint32-type)
              :size (t/uint32-type)))


(defn unpack-data-directories
  ([byte-buffer count]
   (into [] (for [i (range count)]
              (unpack data-directory-spec byte-buffer (* i 8)))))
  ([byte-buffer offset count]
   (unpack-data-directories (slice byte-buffer offset) count)))


(def ^:const image-section-header-spec
  (buffy/spec :Name (t/string-type 8)
              :VirtualSize (t/uint32-type)
              :VirtualAddress (t/uint32-type)
              :SizeOfRawData (t/uint32-type)
              :PointerToRawData (t/uint32-type)
              :PointerToRelocations (t/uint32-type)
              :PointerToLinenumbers (t/uint32-type)
              :NumberOfRelocations (t/ushort-type)
              :NumberOfLinenumbers (t/ushort-type)
              :Characteristics (t/uint32-type)))


(defn unpack-image-section-headers
  "
  Parse the given number of section headers at the given byte buffer.
  Return a map from section name to parsed section header.
  "
  ([byte-buffer count]
   (let [section-header-size (spec-size image-section-header-spec)]
     (reduce (fn [m section-header]
               (assoc m (:Name section-header) section-header))
             {}
             (for [i (range count)]
                (unpack image-section-header-spec byte-buffer (* i section-header-size))))))
  ([byte-buffer offset count]
   (unpack-image-section-headers (slice byte-buffer offset) count)))


(defn parse-pe
  [byte-buffer]
  (let [offset-dos-header 0
        dos-header (unpack image-dos-header-spec byte-buffer offset-dos-header)

        offset-nt-header (+ offset-dos-header (:e_lfanew dos-header))
        offset-signature offset-nt-header
        signature (unpack signature-spec byte-buffer offset-signature)

        offset-file-header (+ offset-signature (spec-size signature-spec))
        file-header (unpack image-file-header-spec byte-buffer offset-file-header)

        offset-optional-header (+ offset-file-header (spec-size image-file-header-spec))
        optional-header (unpack optional-header-spec byte-buffer offset-optional-header)

        offset-data-directories (+ offset-optional-header (spec-size optional-header-spec))
        data-directories (unpack-data-directories byte-buffer
                                                  offset-data-directories
                                                  (:NumberOfRvaAndSizes optional-header))

        offset-section-headers (+ offset-optional-header (:SizeOfOptionalHeader file-header))
        section-headers (unpack-image-section-headers byte-buffer
                                                      offset-section-headers
                                                      (:NumberOfSections file-header))]
    {:byte-buffer byte-buffer
     :dos-header dos-header
     :nt-header {:signature (:Signature signature)
                 :file-header file-header
                 :optional-header (merge optional-header {:data-directories data-directories})}
     :section-headers section-headers}))


(defn get-section
  [pe section-name]
  (let [section-header (get-in pe [:section-headers section-name])
        start (:PointerToRawData section-header)
        ;; TODO: we should possibly align this value.
        length (:SizeOfRawData section-header)
        end (+ start length)
        ;; this may have size <= length,
        raw-buf (slice (:byte-buffer pe) start end)
        ;; so allocate a new buffer,
        out-buf (ByteBuffer/allocate length)]
    ;; and place the raw data into it.
    (.put out-buf raw-buf)
    (.position out-buf 0)
    out-buf))


(defn rva->va
  [pe rva]
  (+ rva (get-in pe [:nt-header :optional-header :ImageBase])))


(defn- find-containing-section
  [pe rva]
  (first (filter #(and (>= rva (:VirtualAddress %))
                       (< rva (+ (:VirtualAddress %)
                                 (:VirtualSize %))))
                 (vals (:section-headers pe)))))


(defn- is-in-header
  [pe rva]
  (and (>= rva 0)
       (< rva (get-in pe [:nt-header :optional-header :SizeOfHeaders]))))


(defn- get-header-data
  ([pe rva length]
   (when (>= (+ rva length)
             (get-in pe [:nt-header :optional-header :SizeOfHeaders]))
     (throw (Exception. "overrun header")))
   (slice (:byte-buffer pe) rva (+ rva length)))
  ([pe rva]
   (slice (:byte-buffer pe) rva)))


(defn- get-section-data
  ([pe section rva length]
   (when (>= (+ rva length)
             (+ (:VirtualAddress section) (:VirtualSize section)))
     (throw (Exception. "overrun section")))
   ;; TODO: handle reads from virtual data. just use `get-section` when appropriate.
   (let [offset-section (- rva (:VirtualAddress section))
         offset-file (+ offset-section (:PointerToRawData section))]
     (slice (:byte-buffer pe) offset-file (+ offset-file length))))
  ([pe section rva]
   ;; TODO: handle reads from virtual data. just use `get-section` when appropriate.
   (let [offset-section (- rva (:VirtualAddress section))
         offset-file (+ offset-section (:PointerToRawData section))]
     (slice (:byte-buffer pe) offset-file))))


(defn get-data
  "
  read data from the PE file from the given relative address.
  all the data must be found within the header, or within a single section.
  "
  ([pe rva length]
   (if (is-in-header pe rva)
     (get-header-data pe rva length)
     (if-let [section (find-containing-section pe rva)]
       (get-section-data pe section rva length)
       (throw (Exception. "unknown region")))))
  ([pe rva]
   (if (is-in-header pe rva)
     (get-header-data pe rva)
     (if-let [section (find-containing-section pe rva)]
       (get-section-data pe section rva)
       (throw (Exception. "unknown region"))))))


(defn get-ascii
  ([pe rva max-length]
   (let [buf (get-data pe rva max-length)]
     (read-ascii buf)))
  ([pe rva]
   (let [buf (get-data pe rva)]
     (read-ascii buf))))


(def ^:const image-export-directory-spec
  (buffy/spec :Characteristics (t/uint32-type)
              :TimeDateStamp (t/uint32-type)
              :MajorVersion (t/ushort-type)
              :MinorVersion (t/ushort-type)
              :AddressOfName (t/uint32-type)
              :Base (t/uint32-type)
              :NumberOfFunctions (t/uint32-type)
              :NumberOfNames (t/uint32-type)
              :AddressOfFunctions (t/uint32-type)
              :AddressOfNames (t/uint32-type)
              :AddressOfOrdinals (t/uint32-type)))


(def ^:const image-import-directory-spec
  (buffy/spec :OriginalFirstThunk (t/uint32-type)
              :TimeDateStamp (t/uint32-type)
              :ForwarderChain (t/uint32-type)
              :AddressOfName (t/uint32-type)
              :FirstThunk (t/uint32-type)))


(def ^:const directory-descriptions {:export {:index IMAGE_DIRECTORY_ENTRY_EXPORT
                                              :spec image-export-directory-spec}
                                     :import {:index IMAGE_DIRECTORY_ENTRY_IMPORT
                                              :spec image-import-directory-spec}})


(defn- parse-basic-directory
  "
  parse the basic directory structure.
  does not resolve strings, etc.

  Args:
    pe: from parse-pe
    directory (keyword): from DIRECTORIES.
  "
  [pe directory]
  (let [dir (get directory-descriptions directory)
        data-directory (get-in pe [:nt-header :optional-header :data-directories (:index dir)])
        directory-buf (get-data pe (:rva data-directory) (:size data-directory))
        parsed-directory (unpack (:spec dir) directory-buf)]
    parsed-directory))


(defmulti parse-directory
  (fn [pe directory]
    directory))


(defmethod parse-directory :export
  [pe directory]
  (let [dir (parse-basic-directory pe :export)]
    (merge dir {:Name (get-ascii pe (:AddressOfName dir))})))


(defmethod parse-directory :import
  [pe directory]
  (let [dir (parse-basic-directory pe :import)]
    ;;dir))
    (merge dir {:Name (get-ascii pe (:AddressOfName dir))})))


(defmethod parse-directory :default
  [pe directory]
  (let [dir (parse-basic-directory pe directory)]
    dir))


(defn table-spec
  [type count]
  (buffy/spec :entries (t/repeated-type type count)))


(defn get-export-tables
  [pe]
  (let [export-directory (parse-directory pe :export)
        table-size (* 4 (:NumberOfNames export-directory))
        uint32-table-spec (table-spec (t/uint32-type) (:NumberOfNames export-directory))
        short-table-spec (table-spec (t/ushort-type) (:NumberOfNames export-directory))
        functions-table-buf (get-data pe (:AddressOfFunctions export-directory) table-size)
        functions-table (unpack uint32-table-spec functions-table-buf)
        names-table-buf (get-data pe (:AddressOfNames export-directory) table-size)
        names-table (unpack uint32-table-spec names-table-buf)
        ordinals-table-buf (get-data pe (:AddressOfOrdinals export-directory) table-size)
        ordinals-table (unpack short-table-spec ordinals-table-buf)]
    {:functions functions-table
     :names names-table
     :ordinals ordinals-table}))


(defn- forwarded?
  [pe export-rva]
  (let [export-loc (get-in pe [:nt-header :optional-header :data-directories IMAGE_DIRECTORY_ENTRY_EXPORT])]
    (and (>= export-rva (:rva export-loc))
         (< export-rva (+ (:rva export-loc) (:size export-loc))))))


(defn- get-export
  [pe tables i]
  (let [export-loc (get-in pe [:nt-header :optional-header :data-directories IMAGE_DIRECTORY_ENTRY_EXPORT])
        ordinal (get-in tables [:ordinals :entries i])
        name-rva (get-in tables [:names :entries i])
        fn-rva (get-in tables [:functions :entries ordinal])]
    (if (forwarded? pe fn-rva)
       {:ordinal ordinal
        :name (when (not (zero? name-rva)) (get-ascii pe name-rva))
        :forwarded? true
        :forwarded-symbol (get-ascii pe fn-rva)}
       {:ordinal ordinal
        :name (when (not (zero? name-rva)) (get-ascii pe name-rva))
        :forwarded? false
        :function-address fn-rva})))


(defn get-exports
  [pe]
  (let [tables (get-export-tables pe)]
    (for [i (range (count (get-in tables [:ordinals :entries])))]
      (get-export pe tables i))))


(def the-empty-import-descriptor (ByteBuffer/allocate (spec-size image-import-directory-spec)))


(defn- empty-import-descriptor?
  [import-descriptor]
  (zero? (.compareTo import-descriptor the-empty-import-descriptor)))


(defn take-uint32!
  [byte-buffer]
  (bit-and 0xFFFFFFFF (.getInt byte-buffer)))


(defn- get-thunk-array
  [pe rva]
  (let [buf (get-data pe rva)]
    (loop [ptr (take-uint32! buf)
           thunk-array []]
      (log/info "blah")
      (if (= 0 ptr)
        thunk-array
        (recur (take-uint32! buf)
               (conj thunk-array ptr))))))


(def ^:const image-import-by-name-spec
  (buffy/spec :Hint (t/ushort-type)))


(def ^:const IMAGE_ORDINAL_FLAG 0x80000000)
(def ^:const IMAGE_ORDINAL_MASK 0xFFFF)
(def ^:const IMAGE_ORDINAL_FLAG64 0x8000000000000000)


(defn- get-import-name
  [pe rva]
  (let [buf (get-data pe rva)
        imp (unpack image-import-by-name-spec buf)]
    (merge imp {:Name (read-ascii buf 2)})))


(defn get-import-descriptors
  [pe]
  (loop [offset (get-in pe [:nt-header :optional-header :data-directories IMAGE_DIRECTORY_ENTRY_IMPORT :rva])
         descriptors []]
     (let [import-descriptor-buf (get-data pe offset (spec-size image-import-directory-spec))]
       (if (empty-import-descriptor? import-descriptor-buf)
         descriptors
         (let [descriptor (unpack image-import-directory-spec import-descriptor-buf)
               descriptor' (merge descriptor {:Name (get-ascii pe (:AddressOfName descriptor))})]
           (recur (+ offset (spec-size image-import-directory-spec))
                  (conj descriptors descriptor')))))))


(defn get-imports
  [pe]
  (flatten (for [import-descriptor (get-import-descriptors pe)]
              (for [thunk (get-thunk-array pe (:OriginalFirstThunk import-descriptor))]
                (if (= 0 (bit-and IMAGE_ORDINAL_FLAG thunk))
                  (merge (get-import-name pe thunk) {:Dll (:Name import-descriptor)})
                  {:Ordinal (bit-and IMAGE_ORDINAL_MASK thunk)
                   :Dll (:Name import-descriptor)})))))


;; TODO: get-resources [pe] -> ???
;; TODO: get-relocated-section-data [pe section-name base-address=default] -> ByteBuffer


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


(def fixtures' (.getPath (clojure.java.io/resource "fixtures")))
(def kern32' (io/file fixtures' "kernel32.dll"))

(let [pe (read-pe kern32')
      descs (get-import-descriptors pe)
      desc (nth descs 0)]
  (get-thunk-array pe (:OriginalFirstThunk desc))
  (get-imports pe))
