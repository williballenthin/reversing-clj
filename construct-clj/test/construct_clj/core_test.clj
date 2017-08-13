(ns construct-clj.core-test
  (:require [clojure.test :refer :all]
            [construct-clj.core :refer :all])
  (:import (java.nio ByteBuffer ByteOrder)))


(defn uint32->byte-buffer
  [integer]
  (let [byte-buffer (ByteBuffer/allocate 4)]
    (.order byte-buffer ByteOrder/BIG_ENDIAN)
    (.putInt byte-buffer 0 integer)
    byte-buffer))

(defn uint64->byte-buffer
  [integer]
  (let [byte-buffer (ByteBuffer/allocate 8)]
    (.order byte-buffer ByteOrder/BIG_ENDIAN)
    (.putLong byte-buffer 0 integer)
    byte-buffer))

(deftest size-test
  (let [byte-buffer (uint64->byte-buffer 0x1122334455667788)]
    (testing "numbers"
      (is (= (size (parse uint8 byte-buffer)) 1))
      (is (= (size (parse int8 byte-buffer)) 1))
      (is (= (size (parse uint16 byte-buffer)) 2))
      (is (= (size (parse int16 byte-buffer)) 2))
      (is (= (size (parse uint32 byte-buffer)) 4))
      (is (= (size (parse int32 byte-buffer)) 4))
      (is (= (size (parse uint64 byte-buffer)) 8))
      (is (= (size (parse int64 byte-buffer)) 8)))
    (testing "array"
      (is (= (size (parse (array uint8 2) byte-buffer)) 2))
      (is (= (size (parse (array uint16 2) byte-buffer)) 4))
      (is (= (size (parse (array uint32 2) byte-buffer)) 8))
      (is (= (size (parse (array (array uint8 2) 2) byte-buffer)) 4)))
    (testing "struct"
      (is (= (size (parse (struct [:a uint8 :b uint16 :c uint32]) byte-buffer)) 7))
      (is (= (size (parse (struct [:a (struct [:x uint8 :y uint16])
                                   :b (struct [:m uint8 :n uint16])])
                          byte-buffer))
             6)))))

(deftest primitive-parse-test
  (let [byte-buffer (uint64->byte-buffer 0x1122334455667788)]
    (testing "numbers"
      (is (= (unpack (parse uint8 byte-buffer)) 0x11))
      (is (= (unpack (parse int8 byte-buffer)) 0x11))
      (is (= (unpack (parse uint16 byte-buffer)) 0x1122))
      (is (= (unpack (parse int16 byte-buffer)) 0x1122))
      (is (= (unpack (parse uint32 byte-buffer)) 0x11223344))
      (is (= (unpack (parse int32 byte-buffer)) 0x11223344))
      (is (= (unpack (parse uint64 byte-buffer)) 0x1122334455667788))
      (is (= (unpack (parse int64 byte-buffer)) 0x1122334455667788))))
  (let [byte-buffer (uint64->byte-buffer -1)]
    (testing "signed numbers"
      (is (= (unpack (parse uint8 byte-buffer)) 0xFF))
      (is (= (unpack (parse int8 byte-buffer)) -1))
      (is (= (unpack (parse uint16 byte-buffer)) 0xFFFF))
      (is (= (unpack (parse int16 byte-buffer)) -1))
      (is (= (unpack (parse uint32 byte-buffer)) 0xFFFFFFFF))
      (is (= (unpack (parse int32 byte-buffer)) -1))
      (is (= (unpack (parse uint64 byte-buffer)) 0xFFFFFFFFFFFFFFFF))
      (is (= (unpack (parse int64 byte-buffer)) -1))))
  (let [byte-buffer (uint64->byte-buffer 0x1122334455667788)]
    (testing "bytes"
      (is (= (repr (parse (byte-sequence 0) byte-buffer)) ""))
      (is (= (repr (parse (byte-sequence 1) byte-buffer)) "11"))
      (is (= (repr (parse (byte-sequence 2) byte-buffer)) "1122")))
    (testing "array"
      (is (= (unpack (parse (array uint32 2) byte-buffer)) [0x11223344 0x55667788]))
      (is (= (unpack (parse (array uint16 4) byte-buffer)) [0x1122 0x3344 0x5566 0x7788]))
      (is (= (unpack (parse (array uint8 8) byte-buffer)) [0x11 0x22 0x33 0x44 0x55 0x66 0x77 0x88]))
      (is (= (unpack (second (parse-array-index (parse (array uint8 8) byte-buffer) 2))) 0x33)))
    (testing "nested array"
      (is (= (unpack (parse (array (array uint8 4) 2) byte-buffer)) [[0x11 0x22 0x33 0x44] [0x55 0x66 0x77 0x88]])))
    (testing "ascii"
      (let [byte-buffer (uint64->byte-buffer 0x4142434445464748)]
        (is (= (unpack (parse (ascii 8) byte-buffer)) "ABCDEFGH"))
        (is (= (unpack (parse (utf-8 8) byte-buffer)) "ABCDEFGH"))))))

(deftest hexify-test
  (let [bytes (byte-array 0x10)]
    (doseq [i (range 0x10)]
      (aset-byte bytes i i))
    (testing "hexify"
      (is (= (hexify bytes) "000102030405060708090a0b0c0d0e0f")))
    (testing "unhexify"
      ;; round-trippin'
      (is (= (hexify (unhexify (hexify bytes))) "000102030405060708090a0b0c0d0e0f")))))

(deftest repr-test
  (testing "numbers"
    (is (= (repr-hex 0) "0x0"))
    (is (= (repr-hex 1) "0x1"))
    (is (= (repr-hex 16) "0x10"))
    (is (= (repr-hex 256) "0x100")))
  (testing "bytes"
    (let [byte-buffer (uint64->byte-buffer 0x1122334455667788)]
      (is (= (repr-bytes byte-buffer) "112233445566...")))
    (let [byte-buffer (uint32->byte-buffer 0x11223344)]
      (is (= (repr-bytes byte-buffer) "11223344")))))

(deftest struct-parse-test
  (let [byte-buffer (uint64->byte-buffer 0x1122334455667788)
        spec (struct [:a uint8
                      :b uint16
                      :c uint32])]
    (testing "struct field indexes"
      (let [parse-result (parse spec byte-buffer)]
        (is (= (get-struct-field-index parse-result :a) 0))
        (is (= (get-struct-field-index parse-result :b) 1))
        (is (= (get-struct-field-index parse-result :c) 2))))
    (testing "struct field sizes"
      (let [parse-result (parse spec byte-buffer)]
        (is (= (second (get-struct-index-size parse-result 0)) 1))
        (is (= (second (get-struct-index-size parse-result 1)) 2))
        (is (= (second (get-struct-index-size parse-result 2)) 4))))
    (testing "struct offsets"
      (let [parse-result (parse spec byte-buffer)]
        (is (= (second (get-struct-field-offset parse-result :a)) 0))
        (is (= (second (get-struct-field-offset parse-result :b)) 1))
        (is (= (second (get-struct-field-offset parse-result :c)) 3))))
    (testing "unpack fields"
      (let [parse-result (parse spec byte-buffer)]
        (is (= (second (unpack-struct-field parse-result :a)) 0x11))
        (is (= (second (unpack-struct-field parse-result :b)) 0x2233))
        (is (= (second (unpack-struct-field parse-result :c)) 0x44556677))))
    (testing "unpack struct"
      (let [parse-result (parse spec byte-buffer)]
        (is (= (unpack parse-result) {:a 0x11 :b 0x2233 :c 0x44556677}))
        (is (= (unpack (parse (struct [:a (struct [:x uint8 :y uint16])
                                       :b (struct [:m uint8 :n uint16])])
                              byte-buffer))
               {:a {:x 0x11 :y 0x2233} :b {:m 0x44 :n 0x5566}}))))))

(deftest parse-in-test
  (let [byte-buffer (uint64->byte-buffer 0x1122334455667788)
        nested (struct [:a (struct [:x uint8 :y uint16])
                        :b (struct [:m uint8 :n uint16])])
        arrays (array (array uint8 4) 2)
        mixed (struct [:a (array uint8 4) :b (array uint16 2)])]
    (testing "nested structs"
       (let [r (parse nested byte-buffer)]
          (is (= (unpack (second (parse-in r [:a :x]))) 0x11))
          (is (= (unpack (second (parse-in r [:a :y]))) 0x2233))
          (is (= (unpack (second (parse-in r [:b :m]))) 0x44))
          (is (= (unpack (second (parse-in r [:b :n]))) 0x5566))
          (is (= (unpack (second (parse-in r [:a]))) {:x 0x11 :y 0x2233}))
          (is (= (unpack (second (parse-in r [:b]))) {:m 0x44 :n 0x5566}))
          (is (= (unpack (second (parse-in r []))) {:a {:x 0x11 :y 0x2233} :b {:m 0x44 :n 0x5566}}))))
    (testing "arrays"
       (let [r (parse arrays byte-buffer)]
          (is (= (unpack (second (parse-in r [0 0]))) 0x11))
          (is (= (unpack (second (parse-in r [0 1]))) 0x22))
          (is (= (unpack (second (parse-in r [0 3]))) 0x44))
          (is (= (unpack (second (parse-in r [1 0]))) 0x55))
          (is (= (unpack (second (parse-in r [1 1]))) 0x66))
          (is (= (unpack (second (parse-in r [1 3]))) 0x88))))
    (testing "mixed struct and arrays"
       (let [r (parse mixed byte-buffer)]
          (is (= (unpack (second (parse-in r [:a 0]))) 0x11))
          (is (= (unpack (second (parse-in r [:a 1]))) 0x22))
          (is (= (unpack (second (parse-in r [:a 3]))) 0x44))
          (is (= (unpack (second (parse-in r [:b 0]))) 0x5566))
          (is (= (unpack (second (parse-in r [:b 1]))) 0x7788))))))
