(ns lancelot_cljs.common
  (:require [om.next :as om]
            [cljs.pprint]))

(defn pp
  "via: http://stackoverflow.com/a/32108640/87207"
  [s]
  (with-out-str (cljs.pprint/pprint s)))

(defn d
  "
    Log a debug message to the console.
    With cljs-devtools installed, things are formatted nicely.
  "
  [msg]
  (.log js/console msg))


(defn update-values
  "
  apply a function to update all the values in the given map.

  via: http://blog.jayfields.com/2011/08/clojure-apply-function-to-each-value-of.html
  "
  [m f & args]
  (reduce (fn [r [k v]] (assoc r k (apply f v args))) {} m))


(defn update-keys
  "
  apply a function to update all the keys in the given map.
  "
  [m f & args]
  (reduce (fn [r [k v]] (assoc r (apply f k args) v)) {} m))


(defn index-by
  "
  create a map from the given sequence, using `key` to extract the key.
  the value is the first element with the extracted key.
  "
  [key col]
  (update-values (group-by key col) first))

