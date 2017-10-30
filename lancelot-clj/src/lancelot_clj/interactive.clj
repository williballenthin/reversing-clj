(ns lancelot-clj.core
  (:gen-class)
  (:require
   [pe.core :as pe]
   [pe.macros :as pe-macros]
   [lancelot-clj.dis :refer :all]
   [lancelot-clj.anal :refer :all]
   [lancelot-clj.core :refer :all]
   [clojure.java.io :as io]
   [clojure.set :as set]
   [clojure.tools.logging :as log]
   [lancelot-clj.schema :as s]
   [com.walmartlabs.lacinia.util :as util]
   [com.walmartlabs.lacinia.schema :as schema]
   [com.walmartlabs.lacinia :as lacinia]
   [clojure.tools.logging :as log]))

#_(defmethod print-method Number
  [n ^java.io.Writer w]
  (.write w (format "0x%X" n)))

(def input-path "C:/Users/user//Documents/oh/conf/2017/recon/work/482d93562fc14e8fb4afe9ee5e00f05f")

;;; do this only once.
;;(def ws (analyze-workspace (load-binary input-path)))


(def schema (s/load-schema ws))

(defn q
  [query-string]
  (-> (lacinia/execute schema query-string nil nil)
      s/simplify))

(q "{ sample_by_md5(md5: \"482D93562FC14E8FB4AFE9EE5E0F05F\") {
        md5
        name
        sha1
        exports {va}
        entrypoint {
          address {
            va
            insn {
              mnem
              str
              size
            }
          }
          blocks {
            va
          }
        }}}")


;; ugh, we can't use hex-formatted numbers. 4235472 == 0x40A0D0.
(q "{ function_by_md5_va(md5: \"482D93562FC14E8FB4AFE9EE5E0F05F\", va: 4235472) {
        va
        blocks {
          va
          insns {
            va
            str
          }
          edges_to {
            src { va }
            type
          }
          edges_from {
            dst { va }
            type
          }
        }
      }
    }")
