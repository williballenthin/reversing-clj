(ns lancelot_cljs.layout.klay
  (:require [lancelot_cljs.common :as cmn]))


(def klay (js* "$klay"))


(defn make
  []
  {"id" "root"
   "properties" {"direction" "DOWN"
                 "intCoordinates" false

                 ;; base spacing value
                 ;; unit: em
                 "spacing" 2

                 ;; horizontal spacing within a layer
                 ;; unit: multiple of `spacing`
                 "de.cau.cs.kieler.klay.layered.inLayerSpacingFactor" 3.5

                 ;; how far apart to route parallel, horizontal edges
                 ;; unit: multiple of `spacing`
                 "de.cau.cs.kieler.klay.layered.edgeSpacingFactor" 0.1

                 ;; spacing around the border of the view
                 ;; unit: em?
                 "de.cau.cs.kieler.borderSpacing" 1

                ;; no apparent effect
                 "de.cau.cs.kieler.portSpacing" 0.1

                 ;; no apparent effect
                 "de.cau.cs.kieler.klay.layered.components.compact" true

                 ;; unclear what this does
                 "de.cau.cs.kieler.klay.layered.unnecessaryBendpoints" true

                 ;; how many iterations to run the algorithm
                 ;; default: 7
                 ;; limit: 1000
                 ;; 500 was noticable over 19 nodes
                 "de.cau.cs.kieler.klay.layered.thoroughness" 25}
                 ;; not supported in klayjs?
                 ;;"de.cau.cs.kieler.klay.layered.edgeNodeSpacingFactor" 0.1

   "children" []
   "edges" []})


(defn- cfg-bb->klay
  [bb]
  {"id" (str (:addr bb))
   "width" (:width bb)
   "height" (:height bb)
   "properties" {"de.cau.cs.kieler.portConstraints" "FIXED_SIDE"}})


(defn add-node
  [g bb]
  (update-in g ["children"] #(cons (cfg-bb->klay bb) %)))


(defn- cfg-edge->klay
  [edge]
  {"source" (str (:src edge))
   "target" (str (:dst edge))
   "type" (:type edge)
   "id" (str (:src edge) (:type edge) (:dst edge))})


(defn add-edge
  [g edge]
  (update-in g ["edges"] #(cons (cfg-edge->klay edge) %)))


(defn- klay-bb->cfg
  [bb]
  (let [x (get bb "x")
        y (get bb "y")
        w (get bb "width")
        h (get bb "height")]
    {:x x
     :y y
     :height h
     :width w
     :id (js/parseInt (get bb "id"))}))


(defn get-nodes
  [g]
  (mapv klay-bb->cfg (js->clj (aget g "children"))))


(defn- klay-point->cfg
  [point]
  {:x (get point "x")
   :y (get point "y")})


(defn- klay-edge->cfg
  [edge]
  (let [src-point (get edge "sourcePoint")
        target-point (get edge "targetPoint")
        bend-points (get edge "bendPoints")
        points (concat [src-point] bend-points [target-point])]
    {:points (mapv klay-point->cfg points)
     :type (keyword (get edge "type"))
     :src (js/parseInt (get edge "source"))
     :dst (js/parseInt (get edge "target"))}))


(defn get-edges
  [g]
  (mapv klay-edge->cfg (js->clj (aget g "edges"))))


(defn- make-port-name
  [src dst direction]
  (str src "-" direction "-" dst))


(defn- make-in-edge-port
  [edge]
  (make-port-name (get edge "source") (get edge "target") "IN"))


(defn- make-out-edge-port
  [edge]
  (make-port-name (get edge "source") (get edge "target") "OUT"))


(defn- update-ports
  "
   Add ports to nodes and edges.
  "
  [g]
  (let [edges (get g "edges")
        edges' (map
                 (fn [edge]
                   (merge edge  {"sourcePort" (make-out-edge-port edge)
                                 "targetPort" (make-in-edge-port edge)}))
                 edges)
        nodes (get g "children")
        nodes-by-id (cmn/index-by #(get % "id") nodes)
        nodes-by-id' (reduce
                      (fn [nodes edge]
                        (let [nodes' (update-in nodes  [(get edge "source") "ports"] conj {"id" (make-out-edge-port edge)
                                                                                           "properties" {"de.cau.cs.kieler.portSide" "SOUTH"}
                                                                                           ;; practical effect: offset from the node at which to start
                                                                                           "height" 0
                                                                                           "width" 0})
                              nodes' (update-in nodes' [(get edge "target") "ports"] conj {"id" (make-in-edge-port edge)
                                                                                           "properties" {"de.cau.cs.kieler.portSide" "NORTH"}
                                                                                           "height" 0
                                                                                           "width" 0})]
                          nodes'))
                      nodes-by-id
                      edges)]
      (merge g {"children" (into [] (vals nodes-by-id'))
                "edges" edges'})))


(defn layout
  [g s e]
  (let [layout-fn (aget klay "layout")
        g' (update-ports g)]
    (layout-fn (clj->js {"graph" g'
                         "options" {}
                         "success" s
                         "error" e}))))
