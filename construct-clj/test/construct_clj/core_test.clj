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

(deftest primitive-parse-test
  (let [byte-buffer (ByteBuffer/allocate 8)]
    (.order byte-buffer ByteOrder/BIG_ENDIAN)
    (.putLong byte-buffer 0 0x1122334455667788)
    (testing "numbers"
      (is (= (parse uint8 byte-buffer) 0x11))
      (is (= (parse int8 byte-buffer) 0x11))
      (is (= (parse uint16 byte-buffer) 0x1122))
      (is (= (parse int16 byte-buffer) 0x1122))
      (is (= (parse uint32 byte-buffer) 0x11223344))
      (is (= (parse int32 byte-buffer) 0x11223344))
      (is (= (parse uint64 byte-buffer) 0x1122334455667788))
      (is (= (parse int64 byte-buffer) 0x1122334455667788))))
  (let [byte-buffer (ByteBuffer/allocate 8)]
    (.order byte-buffer ByteOrder/BIG_ENDIAN)
    (.putLong byte-buffer 0 -1)
    (testing "signed numbers"
      (is (= (parse uint8 byte-buffer) 0xFF))
      (is (= (parse int8 byte-buffer) -1))
      (is (= (parse uint16 byte-buffer) 0xFFFF))
      (is (= (parse int16 byte-buffer) -1))
      (is (= (parse uint32 byte-buffer) 0xFFFFFFFF))
      (is (= (parse int32 byte-buffer) -1))
      (is (= (parse uint64 byte-buffer) 0xFFFFFFFFFFFFFFFF))
      (is (= (parse int64 byte-buffer) -1)))))

