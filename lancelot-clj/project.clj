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
                 [ch.qos.logback/logback-classic "1.1.3"]]
  :main ^:skip-aot lancelot-clj.core
  :target-path "target/%s"
  :profiles {:uberjar {:aot :all}})
