(defproject lancelot-clj "0.1.0-SNAPSHOT"
  :description "Binary analysis framework"
  :url "https://github.com/williballenthin/reversing-clj/tree/master/lancelot-clj"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  :dependencies [[org.clojure/clojure "1.8.0"]
                 ;; see install instructions for capstone shared library in capstone-clj repo.
                 [com.williballenthin/capstone-clj "0.1.0-SNAPSHOT"]
                 [capstone/capstone "3.5.0-rc3"]
                 [com.williballenthin/pe "0.1.0-SNAPSHOT"]
                 ;; for mime-type detection. pulls in lots of stuff. ripe for replacement.
                 [com.novemberain/pantomime "2.9.0"]
                 ;; for logging
                 [org.clojure/tools.logging "0.4.0"]
                 [ch.qos.logback/logback-classic "1.1.3"]
                 ;; for graphql
                 [com.walmartlabs/lacinia "0.22.0"]
                 [com.walmartlabs/lacinia-pedestal "0.3.0"]

                 ;; for web client
                 [org.clojure/clojurescript "1.9.946"]
                 [org.omcljs/om "1.0.0-alpha47" :exclusions [cljsjs/react]]
                 ;; this one doesn't seem to work with om-alpha47
                 ;;[cljsjs/react-with-addons "15.4.2-2"]
                 [cljsjs/react-with-addons "15.3.1-0"]
                 [figwheel-sidecar "0.5.9-SNAPSHOT" :scope "test"]
                 [cljs-ajax "0.7.2"]
                 [prismatic/om-tools "0.4.0"]
                 [binaryage/devtools "0.9.2"]
                 ;; for graphql
                 [vincit/venia "0.2.4"]]
  :plugins [[lein-cljsbuild "1.1.5"]
            [lein-figwheel "0.5.14"]]
  :main ^:skip-aot lancelot-clj.core
  :target-path "target/%s"
  :profiles {:uberjar {:aot :all}}

  ;; for web client
  :cljsbuild {:builds [{:id "client-dev"
                        ;; The path to the top-level ClojureScript source directory:
                        :source-paths ["src"]
                        :figwheel true
                        ;; The standard ClojureScript compiler options:
                        ;; (See the ClojureScript compiler documentation for details.)
                        :compiler {:asset-path "js" ;; directory of `main.js` relative to `index.html`
                                   :output-to "resources/public/client/js/main.js"
                                   :output-dir "resources/public/client/js"
                                   :verbose true
                                   :main lancelot_cljs.core
                                   :optimizations :none
                                   :pretty-print true}}]})
