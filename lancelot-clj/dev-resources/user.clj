(ns user
  (:require
   [clojure.set :as set]
   [clojure.string :as string]
   [clojure.java.io :as io]
   [clojure.tools.logging :as log]
   [pe.core :as pe]
   [pe.macros :as pe-macros]
   [lancelot-clj.dis :refer :all]
   [lancelot-clj.anal :refer :all]
   [lancelot-clj.core :refer :all]
   [lancelot-clj.api :refer :all]
   [lancelot-clj.schema :as s]
   [com.walmartlabs.lacinia.util :as util]
   [com.walmartlabs.lacinia.schema :as schema]
   [com.walmartlabs.lacinia :as lacinia]
   [com.walmartlabs.lacinia.pedestal :as lp]
   [io.pedestal.http :as http]
   [io.pedestal.http.route :as route]
   [io.pedestal.http.route.definition.table :as table]
   [io.pedestal.http.ring-middlewares :as middlewares]
   [io.pedestal.http.secure-headers :as secure-headers]
   [clojure.java.browse :refer [browse-url]]
   ))

#_(defmethod print-method Number
  [n ^java.io.Writer w]
  (.write w (format "0x%X" n)))

(defonce ws (atom nil))
(defonce schema (atom nil))
(defonce service-map (atom nil))
(defonce server (atom nil))

(defn load-ws []
  (reset! ws
          (analyze-workspace
           (load-binary (.getPath (clojure.java.io/resource "helloworld.exe")))))
  "ok")

(defn load-schema []
  (reset! schema (s/load-schema @ws))
  "ok")

(defn load-service-map []
  (reset! service-map (make-service-map @schema))
  "ok")

#_(defn q
  [query-string]
  (-> (lacinia/execute schema query-string nil nil)
      s/simplify))

(defn start-http []
  (reset! server
          (http/start (http/create-server
                       (assoc @service-map
                              ::http/join? false))))
  @server)

(defn stop-http []
  (http/stop @server))

(defn restart-http []
  (stop-http)
  (start-http))

;;(load-ws)
;;(load-schema)
;;(load-service-map)
;;(start-http)
(restart-http)
