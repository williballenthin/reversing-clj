(ns construct-clj.core-test
  (:require [clojure.test :refer :all]
            [construct-clj.core :refer :all])
  (:import (java.nio ByteBuffer ByteOrder)))


(deftest primitive-size-test
  (testing "numbers"
    (is (= (get-spec-parsed-length uint8 nil) 1))
    (is (= (get-spec-parsed-length int8 nil) 1))
    (is (= (get-spec-parsed-length uint16 nil) 2))
    (is (= (get-spec-parsed-length int16 nil) 2))
    (is (= (get-spec-parsed-length uint32 nil) 4))
    (is (= (get-spec-parsed-length int32 nil) 4))
    (is (= (get-spec-parsed-length uint64 nil) 8))
    (is (= (get-spec-parsed-length int64 nil) 8))))


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


(deftest primitive-parse-test
  (let [byte-buffer (uint64->byte-buffer 0x1122334455667788)]
    (testing "numbers"
      (is (= (parse uint8 byte-buffer) 0x11))
      (is (= (parse int8 byte-buffer) 0x11))
      (is (= (parse uint16 byte-buffer) 0x1122))
      (is (= (parse int16 byte-buffer) 0x1122))
      (is (= (parse uint32 byte-buffer) 0x11223344))
      (is (= (parse int32 byte-buffer) 0x11223344))
      (is (= (parse uint64 byte-buffer) 0x1122334455667788))
      (is (= (parse int64 byte-buffer) 0x1122334455667788))))
  (let [byte-buffer (uint64->byte-buffer -1)]
    (testing "signed numbers"
      (is (= (parse uint8 byte-buffer) 0xFF))
      (is (= (parse int8 byte-buffer) -1))
      (is (= (parse uint16 byte-buffer) 0xFFFF))
      (is (= (parse int16 byte-buffer) -1))
      (is (= (parse uint32 byte-buffer) 0xFFFFFFFF))
      (is (= (parse int32 byte-buffer) -1))
      (is (= (parse uint64 byte-buffer) 0xFFFFFFFFFFFFFFFF))
      (is (= (parse int64 byte-buffer) -1)))))


(deftest hexify-test
  (let [bytes (byte-array 0x10)]
    (doseq [i (range 0x10)]
      (aset-byte bytes i i))
    (testing "hexify"
      (is (= (hexify bytes) "000102030405060708090a0b0c0d0e0f")))))


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
