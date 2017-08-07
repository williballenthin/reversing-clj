(ns construct-clj.core
  (:gen-class))

(defn -main
  "I don't do a whole lot ... yet."
  [& args]
  (println "Hello, World!"))

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
  [& {:keys [repr static-size dynamic-size parse]}]
  {:pre [(not (nil? parse))
         (not (nil? repr))]}
  {:primitive? true
   :repr repr
   :parse parse
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
                                :parse (fn parse
                                         ([byte-buffer offset] (read-uint8 byte-buffer))
                                         ([byte-buffer] (parse byte-buffer 0)))))


(def int8 (make-primitive-spec :static-size 1
                               :repr repr-hex
                               :parse (fn parse
                                        ([byte-buffer offset] (.get byte-buffer offset))
                                        ([byte-buffer] (parse byte-buffer 0)))))

(def uint16 (make-primitive-spec :static-size 2
                                 :repr repr-hex
                                 :parse (fn parse
                                          ([byte-buffer offset] (bit-and 0xFFFF (long (.getShort byte-buffer offset))))
                                          ([byte-buffer] (parse byte-buffer 0)))))

(def int16 (make-primitive-spec :static-size 2
                                :repr repr-hex
                                :parse (fn parse
                                         ([byte-buffer offset] (.getShort byte-buffer offset))
                                         ([byte-buffer] (parse byte-buffer 0)))))

(def uint32 (make-primitive-spec :static-size 4
                                 :repr repr-hex
                                 :parse (fn parse
                                          ([byte-buffer offset] (bit-and 0xFFFFFFFF (long (.getInt byte-buffer offset))))
                                          ([byte-buffer] (parse byte-buffer 0)))))

(def int32 (make-primitive-spec :static-size 4
                                :repr repr-hex
                                :parse (fn parse
                                         ([byte-buffer offset] (.getInt byte-buffer offset))
                                         ([byte-buffer] (parse byte-buffer 0)))))

(def uint64 (make-primitive-spec :static-size 8
                                 :repr repr-hex
                                 :parse (fn parse
                                          ([byte-buffer offset]
                                           ;; via: github.com/geoffsalmon/bytebuffer
                                           (let [l (.getLong byte-buffer offset)]
                                             (if (>= l 0)
                                               l
                                               ;; add 2^64 to treat the negative 64bit 2's complement
                                               ;; num as unsigned.
                                               (+ 18446744073709551616N (bigint l)))))
                                          ([byte-buffer] (parse byte-buffer 0)))))

(def int64 (make-primitive-spec :static-size 8
                                :repr repr-hex
                                :parse (fn parse
                                         ([byte-buffer offset] (.getLong byte-buffer offset))
                                         ([byte-buffer] (parse byte-buffer 0)))))

(defn hexify
  "Hex format the give byte-array.

   Args:
    s (byte-array): the bytes to format."
  [s]
  (apply str
    ;; java bytes are signed, so we have to mask them down to uint8
    (map #(format "%02x" (bit-and 0xFF (int %))) s)))

(defn unhexify [hex]
  (apply str
    (map
      (fn [[x y]] (char (Integer/parseInt (str x y) 16))
      (partition 2 hex)))))

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
   (slice-byte-buffer byte-buffer (.limit byte-buffer))))

(defn repr-bytes
  [byte-buffer]
  (let [max-chunk 0x6  ;; this uses (6 * 2) + 3 == 15 characters
        chunk-buf (slice-byte-buffer byte-buffer 0 max-chunk)
        chunk (byte-buffer->byte-array chunk-buf)]
    (if (> (.limit byte-buffer) max-chunk)
      (str (hexify chunk) "...")
      (hexify chunk))))

(defn bytes
  [count]
  (make-primitive-spec :static-size count
                       :repr repr-bytes))


;; instance:
;; {
;;   :spec ...
;;   :fully-parsed? bool
;;   :parsed-size integer
;; }

(defn parse
  [spec byte-buffer]
  (if (:primitive? spec)
    (apply (:parse spec) [byte-buffer])
    ;; TODO: !!!
    (throw (Exception. "parse not implemented on non-primitive specs"))))

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
