(ns lancelot-clj.schema
  "resolvers and function to provide full schema"
  (:require
   [clojure.java.io :as io]
   [com.walmartlabs.lacinia.util :as util]
   [com.walmartlabs.lacinia.schema :as schema]
   [clojure.edn :as edn]))


#_(defn resolver-map
 []
 {:query/sample-by-md5 (fn [context args value]
                        nil)})


#_(defn load-schema
 []
 (-> (io/resource "api-schema.edn")
  slurp
  edn/read-string
  (util/attach-resolvers (resolver-map))
  schema/compile))
