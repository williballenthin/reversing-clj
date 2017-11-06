(ns lancelot-clj.api
  (:require
   [clojure.set :as set]
   [clojure.string :as string]
   [clojure.tools.logging :as log]
   [io.pedestal.http :as http]
   [io.pedestal.http.route :as route]
   [io.pedestal.http.ring-middlewares :as middlewares]
   [com.walmartlabs.lacinia.pedestal :as lp]
   ))


(defn respond-hello
  "example HTTP API endpoint."
  [request]
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
  "pedestal interceptor that re-writes the path-info to strip the given prefix string."
  [prefix]
  {:name ::strip-prefix
   :enter (fn [context]
            (update-in context [:request :path-info] #(lstrip % prefix)))})


(defn log-field
  "pedestal interceptor that logs the given context field to INFO."
  [field]
  {name ::log-field
   :enter (fn [context]
            (log/info "log field " (str field) " " (get-in context field))
            context)})

(def ctx (atom {}))
(def capture-ctx
  "pedestal interceptor that captures the request context to the global atom `ctx`."
  {:name ::capture-ctx
   :enter (fn [context]
            (swap! ctx assoc :ctx context)
            context)})


(def script-domains [;; graphiql src hosts
                     "cdn.jsdelivr.net" "unpkg.com"])
(defn make-script-src-policy
  "format a script Content Security Policy that allows sources from the given domains."
  [domains]
  (str "'self' 'unsafe-inline' 'unsafe-eval' " (string/join " " domains)))


(def style-domains [;; client
                    "fonts.googleapis.com"])
(defn make-style-src-policy
  "format a style Content Security Policy that allows sources from the given domains."
  [domains]
  (str "'self' 'unsafe-inline' " (string/join " " domains)))


(defn make-routes
  [schema]
  (set/union
    ;; the GraphQL endpoint will be: `/graphql`
    (lp/graphql-routes schema {})
    ;; and we'll still be able to host other resources.
    #{;; the handler can be specified directly,
      ["/greet" :get respond-hello :route-name :greet]
      ["/lancelot/*file" :get [(strip-prefix "/lancelot")
                               (middlewares/resource "/public/client")
                               middlewares/file-info]
                         :route-name :client]
      ["/graphiql/*file" :get [(strip-prefix "/graphiql")
                               (middlewares/resource "/public/graphiql")
                               middlewares/file-info]
                         :route-name :graphiql]}))

(defn make-service-map
  [schema]
  {::http/routes (route/expand-routes (make-routes schema))
   ::http/type   :jetty
   ::http/port   8891
   ::http/secure-headers {:content-security-policy-settings {:default-src "*"
                                                             :style-src (make-style-src-policy style-domains)
                                                             :script-src (make-script-src-policy script-domains)}}
   })
