(ns lancelot-clj.schema
  "resolvers and function to provide full schema"
  (:require
   [lancelot-clj.dis :refer :all]
   [lancelot-clj.anal :refer :all]
   [lancelot-clj.core :refer :all]
   [clojure.java.io :as io]
   [com.walmartlabs.lacinia.util :as util]
   [com.walmartlabs.lacinia.schema :as schema]
   [clojure.edn :as edn]
   [clojure.walk :as walk])
  (:import (clojure.lang IPersistentMap)))

(defn workspace->sample
  "see resources/api-schema.edn/:objects/:Sample"
  [ws]
  (merge (get-hashes (:byte-buffer ws))
         {:name "TODO"}))

(defn va->function
  "see resources/api-schema.edn/:objects/:Function"
  [ws va]
  (merge {:va va
          :address {:va va}}))

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

(defn resolve-function-by-md5-va
  [ws context args value]
  (let [{:keys [md5 va]} args
        current-hashes (get-hashes (:byte-buffer ws))]
    (when (= (:md5 current-hashes) md5)
      (va->function ws va))))

(defn va->insn
  [ws va]
  (let [insn (get-in ws [:analysis :insns-by-addr va])
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

(defn resolve-addr-insn
  [ws context args value]
  (let [{:keys [va]} value]
    (va->insn ws va))

(defn resolve-function-blocks
  [ws context args value]
  (let [{:keys [va]} value
        func (analyze-function ws va)]
    (for [[block-start block-addrs] (:blocks func)]
      {:va block-start
       :address {:va va} ;; TODO: va->address
       :func func})))

(defn resolve-block-preds
  [ws context args value]
  (let [{:keys [va func]} value]
    (prn func)
    (prn "a")
    (prn (get-in func [:preds va]))
    (doseq [pred (get-in func [:preds va])]
      (prn (:src pred)))
    (prn "b")

    (for [pred (get-in func [:preds va])]
      {:src {:va (:src pred) :address (:src pred) :func func}
       :dst {:va (:dst pred) :address (:dst pred) :func func}
       :type (:type pred)})))

(defn resolve-block-succs
  [ws context args value]
  (let [{:keys [va func]} value]
    (for [pred (get-in func [:succs va])]
      {:src {:va (:src pred) :address (:src pred) :func func}
       :dst {:va (:dst pred) :address (:dst pred) :func func}
       :type (:type pred)})))

(defn resolve-block-insns
  [ws context args value]
  (let [{:keys [va func]} value
        insn-addrs (get-in func [:blocks va])]
    (map #(va->insn ws %) insn-addrs))))

(defn resolver-map
  [ws]
  {:query/sample-by-md5 (partial resolve-sample-by-md5 ws)
   :query/function-by-md5-va (partial resolve-function-by-md5-va ws)

   :Sample/exports (partial resolve-sample-exports ws)
   :Sample/entrypoint (partial resolve-sample-entrypoint ws)
   :Address/instruction (partial resolve-addr-insn ws)
   :Function/blocks (partial resolve-function-blocks ws)
   :BasicBlock/preds (partial resolve-block-preds ws)
   :BasicBlock/succs (partial resolve-block-succs ws)
   :BasicBlock/insns (partial resolve-block-insns ws)})

(defn load-schema
  [ws]
  (-> (io/resource "api-schema.edn")
      slurp
      edn/read-string
      (util/attach-resolvers (resolver-map ws))
      schema/compile))


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

