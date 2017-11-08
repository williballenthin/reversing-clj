(ns lancelot-cljs.utils)

(defn index-by
  "
  create a map indexed by the given key of the given collection.
  like `group-by`, except its assumed there's only one value per key.

  example::

      (index-by [{:a 1 :b 2} {:a 3 :b 4}] :a)
      => {1 {:a 1 :b 2}
          3 {:a 3 :b 4}}
  "
  [f col]
  (into {} (map #(vector (apply f [%]) %) col)))

