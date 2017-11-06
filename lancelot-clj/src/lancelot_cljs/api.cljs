(ns lancelot_cljs.api
  (:require [ajax.core :refer [GET POST PUT]]
            [clojure.string :as string]
            [cljs.core.async :refer [put! chan <! close!]]
            [lancelot_cljs.common :as cmn]
            [lancelot_cljs.config :as lancelot_cljs.config])
  (:require-macros [cljs.core.async.macros :refer [go]]))


(defn- api-url
  [url & rest]
  (str lancelot_cljs.config/api-base-url url (string/join "" rest)))


(defn- http
  ([method url]
   (http method url {}))

  ([method url body]
   (let [ch (chan)]
     (method url (merge {:format          :json
                         :response-format :json
                         :keywords?       true
                         :handler         #(put! ch {:status :success :response %})
                         :error-handler   #(put! ch {:status :error :response %})}
                        body))
     ch)))

(defn http-post [url body s e]
  (go
    (let [resp (<! (http POST url body))]
      (if (= :success (:status resp))
        (s (:response resp))
        (e (:response resp))))))

(defn http-get [url s e]
  (go
    (let [resp (<! (http GET url))]
      (if (= :success (:status resp))
        (s (:response resp))
        (e (:response resp))))))


(defn- api-get [url s e]
  (go
    (let [resp (<! (http GET (api-url url)))]
      (if (= :success (:status resp))
        (s (:response resp))
        (e (:response resp))))))


(defn analyze-all
  []
  ;; analyze all+experimental: aaaa
  ;; analyze all: aaaa
  (http GET (api-url "/aaa")))


(defn get-functions
  []
  ;; list all functions: afl
  (http GET (api-url "/aflj")))


(defn get-basic-blocks
  [fva]
  ;; seek: s 0x401000
  ;; get basic blocks for current function: aflj
  (http GET (api-url (str "/s " fva "; afbj"))))


(defn get-instructions
  [addr count]
  ;; seek: s 0x401000
  ;; get extended disassembly info for 10 instructions: aoj 10
  (http GET (api-url (str "/s " addr "; aoj " count))))

(defn- http-graphql-post
  "make a GraphQL query request to given endpoint with the given query.
   invoke the given success handler on success.
   invoke the given error handler on error.
   this is a POST-based request.
  "
  [url query s e]
  (POST url {:format          :json
             :response-format :json
             :keywords?       true
             :params          {:query query}
             :handler         s
             :error-handler   e}))

(defn- http-graphql-get
  "make a GraphQL query request to given endpoint with the given query.
   invoke the given success handler on success.
   invoke the given error handler on error.
   this is a GET-based request.
  "
  [url query s e]
  (GET url {:format          :json
            :response-format :json
            :keywords?       true
            :params          {:query query}
            :handler         s
            :error-handler   e}))

(def http-graphql http-graphql-post)
