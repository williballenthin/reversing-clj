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


(defn make-spec
  [base-spec & {:keys [repr static-size dynamic-size]}]
  {:repr repr
   :static-size static-size
   :dynamic-size dynamic-size})


(defn- make-primitive-spec
  [& {:keys [repr static-size dynamic-size parse]}]
  ;; TODO: use clojure facilities for checking these args
  (when (nil? parse)
    (throw (Exception. "primitive requires parse function")))
  (when (nil? repr)
    (throw (Exception. "primitive requires repr function")))
  {:primitive? true
   :repr repr
   :parse parse
   :static-size static-size
   :dynamic-size dynamic-size})


(def repr-hex (partial format "0x%x"))


(def uint8 (make-primitive-spec :static-size 1
                                :repr repr-hex
                                :parse (fn [byte-buffer]
                                         (bit-and 0xFF (long (.get byte-buffer 0))))))

(def int8 (make-primitive-spec :static-size 1
                               :repr repr-hex
                               :parse (fn [byte-buffer]
                                        (.get byte-buffer))))

(def uint16 (make-primitive-spec :static-size 2
                                 :repr repr-hex
                                 :parse (fn [byte-buffer]
                                          (bit-and 0xFFFF (long (.getShort byte-buffer 0))))))

(def int16 (make-primitive-spec :static-size 2
                                :repr repr-hex
                                :parse (fn [byte-buffer]
                                         (.getShort byte-buffer 0))))

(def uint32 (make-primitive-spec :static-size 4
                                 :repr repr-hex
                                 :parse (fn [byte-buffer]
                                          (bit-and 0xFFFFFFFF (long (.getInt byte-buffer 0))))))

(def int32 (make-primitive-spec :static-size 4
                                :repr repr-hex
                                :parse (fn [byte-buffer]
                                         (.getInt byte-buffer 0))))

(def uint64 (make-primitive-spec :static-size 8
                                 :repr repr-hex
                                 :parse (fn [byte-buffer]
                                          ;; via: github.com/geoffsalmon/bytebuffer
                                          (let [l (.getLong byte-buffer 0)]
                                            (if (>= l 0)
                                              l
                                              ;; add 2^64 to treat the negative 64bit 2's complement
                                              ;; num as unsigned.
                                              (+ 18446744073709551616N (bigint l)))))))

(def int64 (make-primitive-spec :static-size 8
                                :repr repr-hex
                                :parse (fn [byte-buffer]
                                         (.getLong byte-buffer 0))))


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
