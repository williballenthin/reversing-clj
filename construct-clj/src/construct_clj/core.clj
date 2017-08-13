(ns construct-clj.core
  (:import (java.nio ByteBuffer ByteOrder))
  (:gen-class))

(defn- uint64->byte-buffer
  [integer]
  (let [byte-buffer (ByteBuffer/allocate 8)]
    (.order byte-buffer ByteOrder/BIG_ENDIAN)
    (.putLong byte-buffer 0 integer)
    byte-buffer))


(defn -main
  "I don't do a whole lot ... yet."
  [& args]
  (println "Hello, World!"))


(defn parse
  [spec byte-buffer]
  {:result (apply (:parse spec) [byte-buffer])
   :spec spec})

(defn unpack
  [parsed-results]
  (let [spec (:spec parsed-results)]
    (if (some? (:unpack spec))
      (apply (:unpack spec) [parsed-results])
      (:result parsed-results))))

(defn repr
  [instance]
  (apply (:repr (:spec instance)) [(:result instance)]))

(declare get-struct-size)

(defn size
  [parsed-results]
  (let [spec (:spec parsed-results)]
    (cond
      (some? (:static-size spec)) (:static-size spec)
      (some? (:is-struct spec)) (second (get-struct-size parsed-results))
      :else (throw (Exception. "don't know how to compute size")))))

;; spec:
;; {
;;   :static-size optional-integer
;;   :dynamic-size optional-function: (fn [byte-buffer]->integer)

(defn make-spec
  [& {:keys [repr static-size dynamic-size parse unpack] :as spec}]
  {:pre [(not (nil? parse))]}
  spec)

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
                         ;; TODO: parse lazily.
                         :parse (fn array-parse
                                 ([byte-buffer offset]
                                  (into [] (for [i (range count)]
                                             (let [element-offset (+ offset (* i (:static-size spec)))
                                                   element-buffer (slice-byte-buffer byte-buffer element-offset)]
                                               (parse spec element-buffer)))))
                                 ([byte-buffer] (array-parse byte-buffer 0)))
                         :unpack (fn [parse-results]
                                   (into [] (map unpack (:result parse-results)))))))

;; (defn array-parse-element [parse-result index]) -> (results, element)

(declare get-struct-index-offset)
(declare get-struct-size)
(declare parse-struct-index)

(defn struct
  [fields & {:keys [repr static-size dynamic-size]}]
  (make-spec :is-struct true
             :repr repr
             :static-size static-size
             :dynamic-size dynamic-size
             :parse (fn struct-parse [byte-buffer]
                      (let [field-pairs (partition 2 fields)
                            indexes-by-name (into {} (map-indexed (fn [idx field-name] [field-name idx])
                                                                  (map first field-pairs))) ;; query by field name
                            field-meta (into [] (map #(hash-map :name (first %)
                                                                :spec (second %)
                                                                ;; TODO: don't include these up front
                                                                :results nil
                                                                :offset nil
                                                                :size nil)
                                                     field-pairs))]
                        {:indexes indexes-by-name    ;; from name to index
                         :fields field-meta          ;; from index to metadata
                         :byte-buffer byte-buffer}))
             :unpack (fn struct-unpack [parse-result]
                       (loop [parse-result parse-result
                              ret {}
                              i 0]
                         (if (= i (count (:fields (:result parse-result))))
                           ret  ;; unfortunately, we throw away the parse-result
                           (let [[parse-result field-result] (parse-struct-index parse-result i)
                                 field (get-in parse-result [:result :fields i])]
                             (recur parse-result
                                    (assoc ret (:name field) (unpack field-result))
                                    (inc i))))))))


(defn get-struct-field-index
  [parse-result field-name]
  {:pre [(get-in parse-result [:spec :is-struct])]}
  (let [spec (:spec parse-result)
        field-index (get-in parse-result [:result :indexes field-name])]
    field-index))

;; TODO: define exactly what a spec looks like if it's not an array/struct.
;; how does it define its size, once parsed?

(defn get-struct-index-size
  [parse-result field-index]
  {:pre [(get-in parse-result [:spec :is-struct])]}
  (let [field-result (get-in parse-result [:result :fields field-index])
        field-spec (:spec field-result)]
    (cond
      ;; simple, static case.
      (some? (:static-size field-spec)) [parse-result (:static-size field-spec)]
      ;; cached from previous calculation.
      (:size field-result) [parse-result (:size field-result)]
      ;; need to do some parsing ourselves.
      (some? (:dynamic-size field-spec)) (let [[parse-result field-offset] (get-struct-index-offset parse-result field-index)
                                               element-buffer (slice-byte-buffer (:byte-buffer (:result parse-result)) field-offset)
                                               element-size (apply (:dynamic-size field-spec) [element-buffer])]
                                           ;; TODO: cache results
                                           [parse-result element-size])
      :else  (let [[parse-result field-offset] (get-struct-index-offset parse-result field-index)
                   element-buffer (slice-byte-buffer (:byte-buffer (:result parse-result)) field-offset)
                   element (parse field-spec element-buffer)
                   ;; HACK: assume this is a struct! other cases should be handled above. until we have user specs.
                   [element element-size] (get-struct-size element)]
               ;; TODO: cache results
               [parse-result element-size]))))

(defn get-struct-size
  [parse-result]
  {:pre [(get-in parse-result [:spec :is-struct])]}
  (let [last-index (dec (count (:fields (:result parse-result))))
        [parse-result last-offset] (get-struct-index-offset parse-result last-index)
        [parse-result last-size] (get-struct-index-size parse-result last-index)]
        ;; TODO: cache results
    [parse-result (+ last-offset last-size)]))

(defn get-struct-index-offset
  [parse-result field-index]
  {:pre [(get-in parse-result [:spec :is-struct])]}
  (let [field-result (get-in parse-result [:result :fields field-index])]
    (cond
      (some? (:offset field-result)) [parse-result (:offset field-result)]
      (= 0 field-index) [parse-result 0]
      :else (let [[parse-result last-offset] (get-struct-index-offset parse-result (dec field-index))
                  [parse-result last-size] (get-struct-index-size parse-result (dec field-index))]
              ;; TODO: update parse-result to cache this thing
              [parse-result (+ last-offset last-size)]))))

(defn get-struct-field-offset
  [parse-result field-name]
  {:pre [(get-in parse-result [:spec :is-struct])]}
  (let [field-index (get-struct-field-index parse-result field-name)]
    (get-struct-index-offset parse-result field-index)))

(defn get-struct-field-size
  [parse-result field-name]
  {:pre [(get-in parse-result [:spec :is-struct])]}
  (let [field-index (get-struct-field-index parse-result field-name)]
    (get-struct-index-size parse-result field-index)))

(defn parse-struct-index
  [parse-result field-index]
  {:pre [(get-in parse-result [:spec :is-struct])]}
  (let [field (get-in parse-result [:result :fields field-index])]
    (if (some? (:result field))
      [parse-result field]
      (let [field-spec (:spec field)
            [parse-result field-offset] (get-struct-index-offset parse-result field-index)
            element-buffer (slice-byte-buffer (:byte-buffer (:result parse-result)) field-offset)
            element (parse field-spec element-buffer)]
         ;; TODO: cache results
         [parse-result element]))))

(defn parse-struct-field
  [parse-result field-name]
  {:pre [(get-in parse-result [:spec :is-struct])]}
  (let [field-index (get-struct-field-index parse-result field-name)]
    (parse-struct-index parse-result field-index)))

(defn unpack-struct-field
  [parse-result field-name]
  {:pre [(get-in parse-result [:spec :is-struct])]}
  (let [[parse-result field-result] (parse-struct-field parse-result field-name)
        unpack-result (unpack field-result)]
    [parse-result unpack-result]))

;; (defn parse-in [parse-result field-name]) -> (new-parse-result, element)
;; (defn unpack-in [parse-result field-name]) -> (new-parse-result, element)
