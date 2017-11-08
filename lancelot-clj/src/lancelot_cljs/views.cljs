(ns lancelot-cljs.views

  (:require [reagent.core  :as reagent]
            [re-frame.core :refer [subscribe dispatch]]
            [clojure.string :as str]
            [lancelot_cljs.utils :as utils]
            [lancelot_cljs.layout.klay :as klay]
            [lancelot_cljs.layout.dagre :as dagre]
            ))

(def <sub (comp deref re-frame.core/subscribe))
(def >evt re-frame.core/dispatch)

(defn hex-format
  "format the given number into a hex string.

   example::
       => (hex-format 10)
       '0xA'
  "
  [n]
  (str "0x" (str/upper-case (.toString n 16))))

(defn canvas
  "
  component that renders the given children on a pan-able canvas.
  mouse click-drag pans the canvas, while mouse wheel in/out zooms it.

  example::
      => [canvas
          [:h1#title 'hello world!']]
  "
  ([meta children]
   ;; this works by constructing a viewport over a "canvas" div containing the children.
   ;; as the client moves the mouse to pan, we translate the canvas.
   ;;
   ;; we capture events at the viewport layer, and apply the translations to the canvas layer.
   ;;
   ;; the size of the canvas may exceed that of the viewport; its no problem, as we can use CSS to clip it.
   ;;
   (let [state (reagent/atom {:shift-left 0    ; the x translation of the canvas
                              :shift-top 0     ; the y translation of the canvas
                              :dragging false  ; is the user currently dragging?
                              :drag-x 0        ; the x delta since the user started dragging, 0 if not dragging
                              :drag-y 0        ; the y delta since the user started dragging, 0 if not dragging
                              :zoom 1.0})]     ; the zoom scale of the canvas
     (fn []
       [:div.canvas-viewport
        (merge
         meta
         {:on-wheel
          ;; handle zooming in/out.
          ;; just a simple update to the zoom translation.
          (fn [e]
            (.preventDefault e)
            (let [zoom-factor 1.1
                  delta (.-deltaY e)]
              (if (> 0 delta)
                (swap! state update :zoom #(* zoom-factor %))
                (swap! state update :zoom #(/ % zoom-factor)))))
          :on-mouse-down
          ;; handle the mouse starting a drag.
          ;; on drag, we capture a few things:
          ;;  - that dragging is in progress,
          ;;  - where the dragging began, and
          ;;  - the x-y delta from when when dragging began (always (0, 0) for :on-mouse-down)
          ;;
          ;; when we apply the translation to the canvas layer, the x-y coordinate gets calculated from:
          ;;
          ;;    (+ initial-location drag-delta)
          ;;
          ;; where drag-delta is:
          ;;
          ;;    (- current-drag-location drag-start)
          (fn [e]
            (.preventDefault e)
            (let [evt (or e (js/event))
                  client-x (.-clientX evt)
                  client-y (.-clientY evt)]
              (swap! state merge {:dragging true
                                  :down-x client-x
                                  :down-y client-y
                                  :drag-x 0
                                  :drag-y 0})))
          :on-mouse-move
          ;; handle mouse continuing a drag.
          ;; we've already recorded where the drag started, so just need to update the drag-delta.
          (fn [e]
            (.preventDefault e)
            (when (:dragging @state)
              (let [evt (or e (js/event))
                    client-x (.-clientX evt)
                    client-y (.-clientY evt)]
                (swap! state merge {:drag-x (- client-x (:down-x @state))
                                    :drag-y (- client-y (:down-y @state))}))))
          :on-mouse-up
          ;; handle the mouse ending a drag.
          ;; now that the drag is complete, we commit the delta to the canvas layer position.
          (fn [e]
            (.preventDefault e)
            (when (:dragging @state)
              (let [evt (or e (js/event))
                    client-x (.-clientX evt)
                    client-y (.-clientY evt)]
                (swap! state #(-> %
                                  (dissoc :down-x)
                                  (dissoc :down-y)
                                  (merge {:dragging false
                                          :drag-x 0
                                          :drag-y 0
                                          :shift-left (+ (:shift-left @state)
                                                         (- client-x (:down-x @state)))
                                          :shift-top (+ (:shift-top @state)
                                                        (- client-y (:down-y @state)))}))))))
          :on-mouse-leave
          ;; handle when the mouse exceeds the bounds of the viewport.
          ;; commit the current drag, and end it.
          ;; note this is a duplication of :on-mouse-up. TODO: refactor code.
          ;;
          ;; note: don't try to change this to use :on-mouse-out.
          ;; that event fires when the mouse enters another element, which happens often during a lagging drag.
          (fn [e]
            (when (:dragging @state)
              (.preventDefault e)
              (let [evt (or e (js/event))
                    client-x (.-clientX evt)
                    client-y (.-clientY evt)]
                (swap! state #(-> %
                                  (dissoc :down-x)
                                  (dissoc :down-y)
                                  (merge {:dragging false
                                          :drag-x 0
                                          :drag-y 0
                                          :shift-left (+ (:shift-left @state)
                                                         (- client-x (:down-x @state)))
                                          :shift-top (+ (:shift-top @state)
                                                        (- client-y (:down-y @state)))}))))))

          })
        [:div.canvas
         {:style {:transform
                  (let [{:keys [zoom drag-x drag-y shift-left shift-top]} @state]
                    (str
                     "translate(" (+ drag-x shift-left) "px, "
                                  (+ drag-y shift-top)  "px) "
                     "scale(" zoom  ") "
                     ))}}
         children]])))
  ([children] (canvas {} children))
  ([] (canvas {} [:div.empty])))

(defn positioned
  "wrap the given children with a div at the given x-y coordinates"
  [{:keys [x y]} children]
  [:div.laid-out
   {:style {:top (str y "em")
            :left (str x "em")}}
   children])

(def sqrt (.-sqrt js/Math))
(def PI (.-PI js/Math))
(def atan2 (.-atan2 js/Math))

;; these line drawing algorithms ripped directly from:
;;  http://stackoverflow.com/questions/4270485/drawing-lines-on-html-page

(defn geoline
  [x y length angle]
  ^{:key (str x "-" y "-" length "-" angle)}
  [:div.line
   {:style {:width (str length "em")
            :transform (str "rotate(" angle "rad)")
            :top (str y "em")
            :left (str x "em")}}])

(defn line
  [x2 y2 x1 y1]
  (let [a (- x1 x2)
        b (- y1 y2)
        c (sqrt
           (+
            (* a a)
            (* b b)))
        sx (/ (+ x1 x2) 2)
        sy (/ (+ y1 y2) 2)
        x (- sx (/ c 2))
        y sy
        alpha (- PI (atan2 (- b) a))]
    (geoline x y c alpha)))

(defn multi-line
  [props children]
  (let [class (:class props)
        class (if class
                (str "multi-line " class)
                "multi-line")]
    [:div
     {:class class}
     children]))

(defn sample-list
  [samples]
  [:section#samples
   [:h1 "samples:"]
   [:ul
    (for [sample samples]
      ^{:key (:md5 sample)} [:div
                             {:on-click #(dispatch [:select-sample (:md5 sample)])}
                             (:md5 sample)])]])

(defn function-list
  [functions]
  [:ul
    (for [function functions]
      (let [va (:va function)]
        ^{:key va} [:div {:on-click #(dispatch [:select-function va])}
                         (hex-format va)]))])

(defn insn-list
  [insns]
  [:ul
   (for [insn (sort :va insns)]
     (let [va (:va insn)]
       ^{:key va} [:div (str (hex-format va) " " (:mnem insn) " " (:opstr insn))]))])

(defn basic-block
  [va]
  (let [block @(subscribe [:basic-block va])]
    [:div.basic-block
     [:div.bb-header "basic block " (hex-format (:va block))]
     [:div.bb-content
      [:table
       [:thead]
       [:tbody
        (for [insn (:insns block)]
          ^{:key (:va insn)}
          [:tr.insn
           [:td.va (hex-format (:va insn))]
           [:td.padding-1]
           ;; TODO: re-enable bytes
           [:td.bytes #_(str/upper-case (:bytes insn))]
           [:td.padding-2]
           [:td.mnem (:mnem insn)]
           [:td.padding-3]
           [:td.operands (:opstr insn)]
           [:td.padding-4]
           [:td.comments (when (and (:comments insn)
                                    (not= "" (:comments insn)))
                           (str ";  " (:comments insn)))]])]]]]))

(defn compute-bb-height
  "
  units: em
  "
  [bb]
  (let [insn-count (count (:insns bb))
        ;; assume header size is 1em,
        ;; which is defined in the css style.
        header-size 1]
    (+ header-size insn-count)))

(defn compute-bb-width
  "
  units: em
  "
  [bb]
  ;; the following constants are defined in the css style.
  (let [padding-1-size 1
        padding-2-size 1
        padding-3-size 1
        padding-4-size 1
        bytes-size 12
        mnem-size 6
        operands-size (apply max (map #(count (:opstr %)) (:insns bb)))
        comments-size (apply max (map #(count (:comments %)) (:insns bb)))]
    (+ padding-1-size
       padding-2-size
       padding-3-size
       padding-4-size
       bytes-size
       mnem-size
       operands-size)))

(defn layout-cfg-klay
  [basic-blocks edges s e]
  (when (< 0 (count (remove nil? basic-blocks)))
    (let [bbs (map #(-> %
                        (assoc :width (compute-bb-width %))
                        (assoc :height (compute-bb-height %))
                        (dissoc :edges_to)
                        (dissoc :edges_from))
                   basic-blocks)
          g (klay/make)
          g (reduce klay/add-node g bbs)
          g (reduce klay/add-edge g edges)]
      (klay/layout g
                   (fn [r]
                     (s {:nodes (klay/get-nodes r)
                         :edges (klay/get-edges r)}))
                   (fn [err]
                     (e {:msg "klay: error"
                         :error err}))))))

(defn layout-cfg
  [basic-blocks edges s e]
  (layout-cfg-klay basic-blocks edges s e))
;;(layout-cfg-dagre basic-blocks s e))

(defn edge-line
  [edge]
  (multi-line
   {:class (condp = (:type edge)
             :fail "edge-false"
             "edge-true")}
   (doall
    (for [pair (partition 2 1 (:points edge))]
      (let [start (first pair)
            end (second pair)
            x1 (:x start)
            y1 (:y start)
            x2 (:x end)
            y2 (:y end)]
        ^{:key (str x1 "-" y1 "-" x2 "-" y2)}
        (line x1 y1 x2 y2))))))

(defn compute-edge-id
  [e]
  (str (:src e) "->" (:dst e)))

(defn add-edge-id
  [e]
  (assoc e :id (compute-edge-id e)))

(defn function-graph
  []
  (let [layout (reagent/atom {})
        blocks (vals (<sub [:blocks]))
        edges (<sub [:edges])
        ;; TODO: do this in layer 3.
        edges (map add-edge-id edges)]
    (layout-cfg blocks edges
                (fn [{:keys [nodes edges]}]
                  (swap! layout #(-> %
                                     (assoc :nodes (utils/index-by :id nodes))
                                     (assoc :edges (map add-edge-id edges)))))
                prn)
    (fn []
      [canvas
       (concat (doall
                (for [va @(subscribe [:block-addresses])]
                  ^{:key va}
                  [positioned
                   (get-in @layout [:nodes va])
                   [basic-block va]]))
               (doall
                (for [edge (:edges @layout)]
                  ^{:key (:id edge)}
                  [edge-line edge])))])))

(defn dis-app
  []
  [:div
   [:section#dis-app
    [:section#hello "Hello world!"]
    (if (not @(subscribe [:samples-loaded?]))
      [:section#loading-samples "loading samples..."]
      (sample-list @(subscribe [:samples])))
    (when @(subscribe [:sample-selected?])
      [:div#sample
       [:h1 @(subscribe [:sample])]
       (if (not @(subscribe [:functions-loaded?]))
         [:section#loading-functions "loading functions..."]
         [:section#functions
          [:h2 "functions:"]
          (function-list @(subscribe [:functions]))])])
    (when @(subscribe [:function-loaded?])
      [:section#basic-blocks
       [:h3 "basic blocks:"]
       [function-graph]])
    ]])
