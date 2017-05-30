(defproject unicorn-clj "0.1.0-SNAPSHOT"
  :description "FIXME: write description"
  :url "http://example.com/FIXME"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  :dependencies [[org.clojure/clojure "1.8.0"]
                 [net.java.dev.jna/jna "4.1.0"]]
  :resource-paths ["resources/unicorn.jar"]
  :main ^:skip-aot unicorn-clj.core
  :target-path "target/%s"
  :profiles {:uberjar {:aot :all}})
