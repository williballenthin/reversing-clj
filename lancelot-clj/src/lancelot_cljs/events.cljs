(ns lancelot-cljs.events
  (:require
   [re-frame.core :refer [reg-event-db
                          reg-event-fx
                          dispatch
                          ]]
   [ajax.core :as ajax]
   [day8.re-frame.http-fx]
   [venia.core :as v]
   ))


(reg-event-db
 :initialize-db
 (fn [_ _]
   {}))

(reg-event-fx
 :load-samples
 (fn [_ _]
   {:http-xhrio {:method :get
                 :uri "/graphql"
                 :params {:query (v/graphql-query {:venia/queries [[:samples [:md5 :sha1]]]})}
                 :format (ajax/json-request-format)
                 :response-format (ajax/json-response-format {:keywords? true})
                 :on-success [:loaded-samples]
                 :on-failure [:errored-samples]}}))

(reg-event-db
 :loaded-samples
 (fn [db [_ response]]
   (prn "loaded samples: " response)
   (merge db {:samples (get-in response [:data :samples])})))

(reg-event-db
 :errored-samples
 (fn [db error]
   (prn "errored-samples: " error)
   db))

(reg-event-db
 :select-sample
 (fn [db [_ sample-md5]]
   (prn "select-sample: " db sample-md5)
   (dispatch [:load-functions])
   (assoc db :sample sample-md5)))

(reg-event-fx
 :load-functions
 (fn [{db :db} _]
   (prn "load-functions")
   {:http-xhrio {:method :get
                 :uri "/graphql"
                 :params {:query (v/graphql-query {:venia/queries [[:sample_by_md5 {:md5 (:sample db)}
                                                                    [[:entrypoint [:va]]
                                                                     [:exports [:va]]
                                                                    ]]]})}
                 :format (ajax/json-request-format)
                 :response-format (ajax/json-response-format {:keywords? true})
                 :on-success [:loaded-functions]
                 :on-failure [:errored-functions]}}))

(reg-event-db
 :loaded-functions
 (fn [db [_ response]]
   (let [exports (get-in response [:data :sample_by_md5 :exports])
         entrypoint (get-in response [:data :sample_by_md5 :entrypoint])
         functions (conj exports entrypoint)]
     (prn "loaded functions: " functions)
     (assoc db :functions functions))))

(reg-event-db
 :errored-functions
 (fn [db error]
   (prn "errored-functions: " error)
   db))

(reg-event-db
 :select-function
 (fn [db [_ function-va]]
   (prn "select-function: " db function-va)
   (assoc db :function function-va)))
