(ns pe.macros)


(defmacro with-position
  "
  temporarily work with the given byte buffer at the given position.
  restores the position to its original value upon leaving this block.
  "
  [byte-buffer pos & body]
  `(let [orig-position# (.position ~byte-buffer)]
     (.position ~byte-buffer ~pos)
     (let [res# (do ~@body)]
       (.position ~byte-buffer orig-position#)
       res#)))


