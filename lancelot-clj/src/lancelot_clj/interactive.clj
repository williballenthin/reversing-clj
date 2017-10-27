(ns lancelot-clj.core
  (:gen-class)
  (:require
   [pantomime.mime :as panto]
   [pe.core :as pe]
   [pe.macros :as pe-macros]
   [lancelot-clj.dis :refer :all]
   [lancelot-clj.anal :refer :all]
   [lancelot-clj.core :refer :all]
   [lancelot-clj.testutils :refer :all]
   [clojure.java.io :as io]
   [clojure.set :as set]
   [clojure.tools.logging :as log]
   [lancelot-clj.schema :as s]
   [com.walmartlabs.lacinia.util :as util]
   [com.walmartlabs.lacinia.schema :as schema]
   [com.walmartlabs.lacinia :as lacinia]
   [clojure.tools.logging :as log]
   [clojure.edn :as edn]
   [clojure.walk :as walk])
  (:import (clojure.lang IPersistentMap))
  (:import (java.io RandomAccessFile))
  (:import (java.nio ByteBuffer ByteOrder))
  (:import (java.nio.channels FileChannel FileChannel$MapMode))
  (:import [capstone.Capstone])
  (:import [capstone.X86_const]))

;; global variables that are useful for tracing values
(def ctx (atom {}))
(:args @ctx)
(:value @ctx)

(defmethod print-method Number
  [n ^java.io.Writer w]
  (.write w (format "0x%X" n)))

(def input-path "C:/Users/user//Documents/oh/conf/2017/recon/work/482d93562fc14e8fb4afe9ee5e00f05f")

;;; do this only once.
;;(def ws (analyze-workspace (load-binary input-path)))

(defn workspace->sample
  "see resources/api-schema.edn/:objects/:Sample"
  [ws]
  (merge (get-hashes (:byte-buffer ws))
         {:name "TODO"}))

(defn va->function
  "see resources/api-schema.edn/:objects/:Function"
  [ws va]
  (merge {:va va}))

(defn resolve-sample-by-md5
  [ws context args value]
  (let [{:keys [md5]} args
        current-hashes (get-hashes (:byte-buffer ws))]
    (when (= (:md5 current-hashes) md5)
      (workspace->sample ws))))

(defn resolve-sample-exports
  [ws context args value]
  (for [va (get-exports (:pe ws))]
    (va->function ws va)))

(defn resolve-sample-entrypoint
  [ws context args value]
  (va->function ws (get-entrypoint (:pe ws))))

(defn resolve-function-addr
  [ws context args value]
  (let [{:keys [va]} value]
    {:va va}))

(defn resolve-addr-insn
  [ws context args value]
  (let [{:keys [va]} value
        insn (get-in ws [:analysis :insns-by-addr va])
        csinsn (:insn insn)
        mnem (.-mnemonic csinsn)
        size (.-size csinsn)
        opstr (.-opStr csinsn)]
    {:mnem mnem
     :opstr opstr
     :str (format "%s %s" mnem opstr)
     :size size
     ;; TODO: resolve the operands here
     :va va}))

(defn resolver-map
  [ws]
  {:query/sample-by-md5 (partial resolve-sample-by-md5 ws)
   :Sample/exports (partial resolve-sample-exports ws)
   :Sample/entrypoint (partial resolve-sample-entrypoint ws)
   :Function/address (partial resolve-function-addr ws)
   :Address/instruction (partial resolve-addr-insn ws)})

(defn load-schema
  [ws]
  (-> (io/resource "api-schema.edn")
      slurp
      edn/read-string
      (util/attach-resolvers (resolver-map ws))
      schema/compile))

(def schema (load-schema ws))

(defn simplify
  "Converts all ordered maps nested within the map into standard hash maps, and
   sequences into vectors, which makes for easier constants in the tests, and eliminates ordering problems."
  [m]
  (walk/postwalk
   (fn [node]
     (cond
       (instance? IPersistentMap node)
       (into {} node)

       (seq? node)
       (vec node)

       :else
       node))
   m))

(defn q
  [query-string]
  (-> (lacinia/execute schema query-string nil nil)
      simplify))


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
        }}}")

