(ns construct-clj.core
  (:gen-class))

(defn -main
  "I don't do a whole lot ... yet."
  [& args]
  (println "Hello, World!"))


(defn parse
  [spec byte-buffer]
  (if (:primitive? spec)
    {:result (apply (:parse spec) [byte-buffer])
     :spec spec}
    ;; TODO
    (throw (Exception. (str "parse not implemented on non-primitive specs")))))

(defn unpack
  [parsed-results]
  (let [spec (:spec parsed-results)]
    (when (not (:primitive? spec))
      ;; TODO
      (throw (Exception. "unpack not implemented on non-primitive specs")))
    (if (some? (:unpack spec))
      (apply (:unpack spec) [parsed-results])
      (:result parsed-results))))

(defn repr
  [instance]
  (apply (:repr (:spec instance)) [(:result instance)]))


;; spec:
;; {
;;   :static-size optional-integer
;;   :dynamic-size optional-function: (fn [byte-buffer]->integer)

(defn struct
  ;; will need to compute static-size if all fields are static
  ;;  or dynamic-size, if all fields are either static or dynamic
  [])

(defn make-spec
  [base-spec & {:keys [repr static-size dynamic-size]}]
  {:repr repr
   :static-size static-size
   :dynamic-size dynamic-size})

(defn- make-primitive-spec
  [& {:keys [repr static-size dynamic-size parse unpack]}]
  {:pre [(not (nil? parse))
         (not (nil? repr))]}
  {:primitive? true
   :repr repr
   :parse parse
   :unpack unpack
   :static-size static-size
   :dynamic-size dynamic-size})

(def repr-hex (partial format "0x%x"))

(defn read-uint8
  ([byte-buffer offset]
   (bit-and 0xFF (long (.get byte-buffer offset))))
  ([byte-buffer]
   (read-uint8 byte-buffer 0)))

(defn read-int8
  ([byte-buffer offset]
   (.get byte-buffer offset))
  ([byte-buffer]
   (read-int8 byte-buffer 0)))

(def uint8 (make-primitive-spec :static-size 1
                                :repr repr-hex
                                :parse (fn uint8-parse
                                         ([byte-buffer offset] (read-uint8 byte-buffer))
                                         ([byte-buffer] (uint8-parse byte-buffer 0)))))

(def int8 (make-primitive-spec :static-size 1
                               :repr repr-hex
                               :parse (fn int8-parse
                                        ([byte-buffer offset] (.get byte-buffer offset))
                                        ([byte-buffer] (int8-parse byte-buffer 0)))))

(def uint16 (make-primitive-spec :static-size 2
                                 :repr repr-hex
                                 :parse (fn uint16-parse
                                          ([byte-buffer offset] (bit-and 0xFFFF (long (.getShort byte-buffer offset))))
                                          ([byte-buffer] (uint16-parse byte-buffer 0)))))

(def int16 (make-primitive-spec :static-size 2
                                :repr repr-hex
                                :parse (fn int16-parse
                                         ([byte-buffer offset] (.getShort byte-buffer offset))
                                         ([byte-buffer] (int16-parse byte-buffer 0)))))

(def uint32 (make-primitive-spec :static-size 4
                                 :repr repr-hex
                                 :parse (fn uint32-parse
                                          ([byte-buffer offset] (bit-and 0xFFFFFFFF (long (.getInt byte-buffer offset))))
                                          ([byte-buffer] (uint32-parse byte-buffer 0)))))

(def int32 (make-primitive-spec :static-size 4
                                :repr repr-hex
                                :parse (fn int32-parse
                                         ([byte-buffer offset] (.getInt byte-buffer offset))
                                         ([byte-buffer] (int32-parse byte-buffer 0)))))

(def uint64 (make-primitive-spec :static-size 8
                                 :repr repr-hex
                                 :parse (fn uint64-parse
                                          ([byte-buffer offset]
                                           ;; via: github.com/geoffsalmon/bytebuffer
                                           (let [l (.getLong byte-buffer offset)]
                                             (if (>= l 0)
                                               l
                                               ;; add 2^64 to treat the negative 64bit 2's complement
                                               ;; num as unsigned.
                                               (+ 18446744073709551616N (bigint l)))))
                                          ([byte-buffer] (uint64-parse byte-buffer 0)))))

(def int64 (make-primitive-spec :static-size 8
                                :repr repr-hex
                                :parse (fn int64-parse
                                         ([byte-buffer offset] (.getLong byte-buffer offset))
                                         ([byte-buffer] (int64-parse byte-buffer 0)))))

(defn hexify
  "Hex format the give byte-array.

  If the argument is not a byte array, it should be a sequence of `byte` instances.

   Args:
    s (byte-array): the bytes to format."
  [s]
  (apply str
    ;; java bytes are signed, so we have to mask them down to uint8
    (map #(format "%02x" (bit-and 0xFF (int %))) s)))

(defn unhexify [hex]
  (apply str
    (map
      (fn [[x y]] (char (Integer/parseInt (str x y) 16)))
      (partition 2 hex))))

(defn byte-buffer->byte-array
  ([byte-buffer count]
   ;; java bytes are signed, so we have to keep them signed here.
   (byte-array (map #(byte (read-int8 byte-buffer %)) (range count))))
  ([byte-buffer]
   (byte-buffer->byte-array byte-buffer (.limit byte-buffer))))

(defn slice-byte-buffer
  ([byte-buffer start end]
   (.position byte-buffer start)
   (let [slice (.slice byte-buffer)
         slice-size (- end start)]
     (.position byte-buffer 0)
     ;; if end is greater than the limit, truncate to limit.
     (when (> (.limit slice) slice-size)
       (.limit slice slice-size))
     slice))
  ([byte-buffer start]
   (slice-byte-buffer byte-buffer start (.limit byte-buffer))))

(defn repr-bytes
  [byte-buffer]
  (let [max-chunk 0x6  ;; this uses (6 * 2) + 3 == 15 characters
        chunk-buf (slice-byte-buffer byte-buffer 0 max-chunk)
        chunk (byte-buffer->byte-array chunk-buf)]
    (if (> (.limit byte-buffer) max-chunk)
      (str (hexify chunk) "...")
      (hexify chunk))))

(defn byte-sequence
  "byte-sequence maps to the native type `ByteBuffer`."
  ;; TODO: move to its own module and refer to using namespace.
  [count]
  (make-primitive-spec :static-size count
                       :repr repr-bytes
                       :parse (fn byte-seq-parse
                                ([byte-buffer offset] (slice-byte-buffer byte-buffer offset (+ offset count)))
                                ([byte-buffer] (slice-byte-buffer byte-buffer 0 count)))))


(defn array
  [spec count]
  (when (nil? (:static-size spec))
    (throw (Exception. "arrays with elements of dynamic size are not yet supported")))
  (let [size (* count (:static-size spec))]
    (make-primitive-spec :static-size size
                         :repr #(str "[ " (clojure.string/join ", " (map repr %)) " ]")
                         :parse (fn array-parse
                                 ([byte-buffer offset]
                                  (into [] (for [i (range count)]
                                             (let [element-offset (+ offset (* i (:static-size spec)))
                                                   element-buffer (slice-byte-buffer byte-buffer element-offset)]
                                               (parse spec element-buffer)))))
                                 ([byte-buffer] (array-parse byte-buffer 0)))
                         :unpack (fn [unpack-results]
                                   (into [] (map unpack (:result unpack-results)))))))

;; instance:
;; {
;;   :spec ...
;;   :fully-parsed? bool
;;   :parsed-size integer
;; }


(defn- get-instance-semiparsed-length
  "Get the total length of an instance that has been partially, but not fully, parsed."
  ;; TODO: !!!
  [byte-buffer instance])

(defn get-instance-parsed-length
  "Get the total length of an instance."
  [instance]
  (cond
    ;; simplest case: this thing has a fixed size.
    (some? (:static-size (:spec instance))) (:static-size (:spec instance))
    ;; common case: the instance is already fully parsed, so pull the parsed size.
    (:fully-parsed? instance) (:parsed-length instance)
    :else (get-instance-semiparsed-length instance)))

(defn get-spec-parsed-length
  "Get the total length of a spec parsed at the given byte buffer."
  [spec byte-buffer]
  (cond
    ;; simplest case: this thing has a fixed size.
    (some? (:static-size spec)) (:static-size spec)
    ;; complex case: need to parse some fields to compute the total size.
    (some? (:dynamic-size spec)) (apply (:dynamic-size spec) [byte-buffer])
    ;; worst case: we have to instantiate and parse the whole thing to fetch length.
    :else (get-instance-parsed-length (parse spec byte-buffer))))
