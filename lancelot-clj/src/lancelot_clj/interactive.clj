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
   [com.walmartlabs.lacinia.pedestal :as lp]
   [io.pedestal.http :as http]
   [io.pedestal.http.route :as route]
   [io.pedestal.http.route.definition.table :as table]
   [io.pedestal.http.ring-middlewares :as middlewares]
   [clojure.java.browse :refer [browse-url]]
   [clojure.tools.logging :as log]))

#_(defmethod print-method Number
  [n ^java.io.Writer w]
  (.write w (format "0x%X" n)))

(def input-path "C:/Users/user//Documents/oh/conf/2017/recon/work/482d93562fc14e8fb4afe9ee5e00f05f")

(defonce ws (analyze-workspace (load-binary input-path)))

(def schema (s/load-schema nil))

#_(defn q
  [query-string]
  (-> (lacinia/execute schema query-string nil nil)
      s/simplify))



#_(defn start-server
  [_]
  (let [server (-> schema
                   (lp/pedestal-service {:graphiql true
                                         :port 8888})
                   add-my-routes
                   http/create-server
                   http/start)]
    (browse-url "http://localhost:8888/")
    server))



(conj (lp/graphql-routes schema {:graphiql true
                                 :port 8889
                                 :resource-path "/public"
                                 :env :dev})
      ["/greet" :get respond-hello :route-name :greet])


(defn respond-hello [request]
  {:status 200 :body "Hello, world!"})

(defn lstrip
  "
  strip the give substring from the left side of the given string.

  example::

      => (lstrip 'foobar' 'foo')
      'bar'

      => (lstrip 'foobar' 'baz')
      'foobar'
  "
  [s w]
  (if (string/starts-with? s w)
    (subs s (count w))
    s))


(defn strip-prefix
  [prefix]
  {:name ::strip-prefix
   :enter (fn [context]
            (update-in context [:request :path-info] #(lstrip % prefix)))})


(defn log-field
  [field]
  {name ::log-field
   :enter (fn [context]
            (log/info "log field " (str field) " " (get-in context field))
            context)})

(def ctx (atom {}))
(def capture-ctx
  {:name ::capture-ctx
   :enter (fn [context]
            (swap! ctx assoc :ctx context)
            context)})

(restart-dev)

(def service-map
  {::http/routes (route/expand-routes
                    ;; include the handler directly inline,
                  #{["/greet" :get respond-hello :route-name :greet]
                    ;; or as the final element in a vector,
                    ["/greet2" :get [respond-hello] :route-name :greet2]
                    ;; where the prior elements are interceptors.
                    ["/greet3" :get [capture-ctx respond-hello] :route-name :greet3]
                    ;; serve files with `middlewares/resource`, but ensure the path is correct.
                    ;; TODO: there must be some built-in way to specify this prefix?
                    ["/rsrc/*file" :get [(strip-prefix "/rsrc")
                                         (middlewares/resource "/public")] :route-name :rsrc]})
   ::http/type   :jetty
   ::http/port   8891
   ;; here's how to serve from `$project/resources/public` using the default resource interceptor.
   ;; ref: https://github.com/pedestal/pedestal/blob/60332b883120c604475a86d72fcbfcb0dba0d3ef/service-template/src/leiningen/new/pedestal_service/service.clj#L65
   ;; however, if you use this, then they override other routes?
   ;;::http/resource-path "/public"

   ;; here's how to install your own resource middleware to `project/resources/public`.
   ;; this recursively serves the static files in this directory.
   ;; however, if you use this, then they override other routes?
   ;;::http/interceptors [(middlewares/resource "/public")]
   })




(defn start []
  (http/start (http/create-server service-map)))

(defn stop
  [server]
  (http/stop server))

;; For interactive development
(defonce server (atom nil))

(defn start-dev []
  (reset! server
          (http/start (http/create-server
                       (assoc service-map
                              ::http/join? false))))
  @server)

(defn stop-dev []
  (http/stop @server))

(defn restart-dev []
  (stop-dev)
  (start-dev))

(restart-dev)



#_(q "{ sample_by_md5(md5: \"482D93562FC14E8FB4AFE9EE5E0F05F\") {
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
#_(q "{ function_by_md5_va(md5: \"482D93562FC14E8FB4AFE9EE5E0F05F\", va: 4235472) {
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

(prn "ok")
