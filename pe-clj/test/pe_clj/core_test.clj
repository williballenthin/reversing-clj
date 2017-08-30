(ns pe-clj.core-test
  (:require [clojure.test :refer :all]
            [pe-clj.core :refer :all]
            [clojure.java.io :as io]))

(def fixtures (.getPath (clojure.java.io/resource "fixtures")))
(def kern32 (io/file fixtures "kernel32.dll"))

(deftest dos-header-test
  (testing "the header"
    (let [pe (read-pe kern32)]
      pe)))



