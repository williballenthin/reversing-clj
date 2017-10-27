(defproject com.williballenthin/capstone-clj "0.1.0-SNAPSHOT"
  :description "FIXME: write description"
  :url "http://example.com/FIXME"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  :dependencies [[org.clojure/clojure "1.8.0"]
                 [net.java.dev.jna/jna "4.1.0"]
                 ;; first, build java capstone bindings:
                 ;;  linux:
                 ;;    $ git clone https://github.com/aquynh/capstone.git
                 ;;    $ cd capstone
                 ;;    $ ./make.sh
                 ;;    $ cd bindings/java
                 ;;    $ sudo dnf install jna              # fedora
                 ;;    $ sudo apt-get install libjna-java  # ubuntu
                 ;;    $ make
                 ;;  windows:
                 ;;    see: https://github.com/aquynh/capstone/issues/1043
                 ;; to install capstone into the local maven repository:
                 ;;    $ mvn install:install-file -Dfile=$(pwd)/capstone.jar
                 ;;                               -DgroupId=capstone
                 ;;                               -DartifactId=capstone
                 ;;                               -Dversion=3.5.0-rc3
                 ;;                               -Dpackaging=jar
                 ;; via: https://maven.apache.org/guides/mini/guide-3rd-party-jars-local.html
                 [capstone/capstone "3.5.0-rc3"]]
  :main ^:skip-aot capstone-clj.core
  :target-path "target/%s"
  :profiles {:uberjar {:aot :all}})
