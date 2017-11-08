(ns user
  (:require
   [clojure.java.io :as io]
   [clojure.tools.logging :as log]
   [lancelot-clj.api :as api]
   [lancelot-clj.anal :as analysis]
   [lancelot-clj.schema :as schema]
   [lancelot-clj.workspace :as workspace]
   [com.walmartlabs.lacinia :as lacinia]
   [io.pedestal.http :as http])
  (:import (ch.qos.logback.classic Logger Level)))

(.setLevel
 (org.slf4j.LoggerFactory/getLogger (Logger/ROOT_LOGGER_NAME)) Level/INFO)

(defonce ws (atom nil))
(defonce schema (atom nil))
(defonce service-map (atom nil))
(defonce server (atom nil))

(defn load-ws []
  (reset! ws
          (analysis/analyze-workspace
           (workspace/load-binary (.getPath (clojure.java.io/resource "helloworld.exe")))))
  "ok")

(defn load-schema []
  (reset! schema (schema/load-schema @ws))
  "ok")

(defn load-service-map []
  (reset! service-map (api/make-service-map @schema))
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
;;(restart-http)
;;(stop-http)

#_(defmethod print-method Number
    [n ^java.io.Writer w]
    (.write w (format "0x%X" n)))

