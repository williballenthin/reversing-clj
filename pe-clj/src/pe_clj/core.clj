(ns pe-clj.core
  (:gen-class)
  (:require [clojurewerkz.buffy.core :refer :all :as buffy]
            [clojurewerkz.buffy.types :as t])
  (:import (java.io RandomAccessFile))
  (:import (java.nio ByteBuffer ByteOrder))
  (:import (java.nio.channels FileChannel FileChannel$MapMode)))


(defn slice-byte-buffer
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
   (slice-byte-buffer byte-buffer start (.limit byte-buffer))))


(defn spec-size
  [spec]
  (apply + (map #(.size (second %)) spec)))


(defn unpack
  ([spec byte-buffer]
   (buffy/decompose (buffy/compose-buffer spec :orig-buffer byte-buffer)))
  ([spec byte-buffer offset]
   (unpack spec (slice-byte-buffer byte-buffer offset))))


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

(def signature-spec
  (buffy/spec :Signature (t/uint32-type)))  ;; "PE"

(def IMAGE_FILE_MACHINE_I386 0x14C)

(def image-file-header-spec
  (buffy/spec :Machine (t/ushort-type)
              :NumberOfSections (t/ushort-type)
              :TimeDateStamp (t/uint32-type)
              :PointerToSymbolTable (t/uint32-type)
              :NumberOfSymbols (t/uint32-type)
              :SizeOfOptionalHeader (t/ushort-type)
              :Characteristics (t/ushort-type)))

(def IMAGE_NT_OPTIONAL_HDR32_MAGIC 0x10B)

(def optional-header-spec
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


(def data-directory-spec
  (buffy/spec :rva (t/uint32-type)
              :size (t/uint32-type)))


(defn unpack-data-directories
  ([byte-buffer count]
   (into [] (for [i (range count)]
              (unpack data-directory-spec byte-buffer (* i 8)))))
  ([byte-buffer offset count]
   (unpack-data-directories (slice-byte-buffer byte-buffer offset) count)))


(def image-section-header-spec
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
   (unpack-image-section-headers (slice-byte-buffer byte-buffer offset) count)))


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


(defn get-section-data
  [pe section-name]
  (let [section-header (get-in pe [:section-headers section-name])
        start (:PointerToRawData section-header)
        length (:SizeOfRawData section-header)
        end (+ start length)
        ;; this may have size <= length,
        raw-buf (slice-byte-buffer (:byte-buffer pe) start end)
        ;; so allocate a new buffer,
        out-buf (ByteBuffer/allocate length)]
    ;; and place the raw data into it.
    (.put out-buf raw-buf)
    (.position out-buf 0)
    out-buf))


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
