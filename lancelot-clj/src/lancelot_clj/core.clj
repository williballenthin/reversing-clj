(ns lancelot-clj.core
  (:gen-class)
  (:require
   [io.pedestal.http :as http]
   [lancelot-clj.api :as api]
   [lancelot-clj.anal :as analysis]
   [lancelot-clj.schema :as schema]
   [lancelot-clj.workspace :as workspace]
   )
  (:import (ch.qos.logback.classic Logger Level)))

#_(defmethod print-method Number
    [n ^java.io.Writer w]
    (.write w (format "0x%X" n)))

(defn -main
  [& args]
  ;; logging level should really be set by some configuration file,
  ;; but i can't figure out how to get this to respect log4j.properties,
  ;; so, we'll just do it with code.
  (.setLevel
   (org.slf4j.LoggerFactory/getLogger (Logger/ROOT_LOGGER_NAME)) Level/INFO)
  (let [input-path (first args)
        ws (analysis/analyze-workspace (workspace/load-binary input-path))
        schema (schema/load-schema ws)
        service-map (api/make-service-map schema)]
    (http/start (http/create-server service-map))))
