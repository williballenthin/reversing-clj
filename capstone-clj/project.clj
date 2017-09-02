(defproject com.williballenthin/capstone-clj "0.1.0-SNAPSHOT"
  :description "FIXME: write description"
  :url "http://example.com/FIXME"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  :dependencies [[org.clojure/clojure "1.8.0"]
                 [net.java.dev.jna/jna "4.1.0"]]
  ;; to install capstone for clojure:
  ;;    $ git clone https://github.com/aquynh/capstone.git
  ;;    $ cd capstone
  ;;    $ ./make.sh
  ;;    $ cd bindings/java
  ;;    $ sudo dnf install jna              # fedora
  ;;    $ sudo apt-get install libjna-java  # ubuntu
  ;;    $ make
  ;;    $ mvn install:install-file -Dfile=$(pwd)/capstone.jar
  ;;                               -DgroupId=capstone
  ;;                               -DartifactId=capstone.jar
  ;;                               -Dversion=3.5.0-rc3
  ;;                               -Dpackaging=jar
  ;; via: https://maven.apache.org/guides/mini/guide-3rd-party-jars-local.html
  :main ^:skip-aot capstone-clj.core
  :target-path "target/%s"
  :profiles {:uberjar {:aot :all}})
