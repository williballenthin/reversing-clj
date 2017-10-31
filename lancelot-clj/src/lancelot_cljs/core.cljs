(ns lancelot_cljs.core
  (:require [goog.dom :as gdom]
            [clojure.data]
            [clojure.string :as string]
            [cljs.core.async :refer [put! chan <! close!] :as async]
            [goog.string :as gstring]
            [goog.string.format]
            [cljs.pprint]
            [om-tools.dom :as dom]
            [om.next :as om :refer-macros [defui]]
            ;; include this first so it gets installed early
            [lancelot_cljs.devtools :as lancelot_cljs.devtools]
            [lancelot_cljs.common :as cmn]
            [lancelot_cljs.api :as r2]
            [lancelot_cljs.layout.dagre :as dagre]
            [lancelot_cljs.layout.klay :as klay]
            [venia.core :as v])
  (:require-macros [cljs.core.async.macros :refer [go]]))


(enable-console-print!)



(defui Canvas
  Object
  (initLocalState
   [this]
   {:dragging false
    :last-x 0
    :shift-left 0
    :last-y 0
    :shift-top 0
    :zoom 1.0})
  (render
   [this]
   ;; use local mutable state for performance.
   ;; while panning, update this state, and only re-render upon `onMouseUp`.
   (let [state (om/get-state this)
         a-last-x (atom (:last-x state))
         a-shift-left (atom (:shift-left state))
         a-last-y (atom (:last-y state))
         a-shift-top (atom (:shift-top state))]
     (dom/div {:class "canvas-viewport"
               :ref "viewport"
               ;; scroll to zoom support on canvas
               :onWheel
               (fn [e]
                 (.preventDefault e)
                 (let [delta (aget e "deltaY")
                       state (om/get-state this)]
                   (if (> 0 delta)
                     (do
                       (prn "scroll in")
                       (om/set-state! this (assoc state :zoom (* 1.1 (:zoom state)))))
                     (do
                       (prn "scroll out")
                       (om/set-state! this (assoc state :zoom (* 0.9 (:zoom state))))))))
               ;; click-and-drag on the viewport pans the canvas
               :onMouseDown
               (fn [e]
                 (.preventDefault e)
                 (let [evt (or e (js/event))
                       last-x (aget evt "clientX")
                       last-y (aget evt "clientY")
                       state (om/get-state this)]
                   (om/set-state! this (assoc state :dragging true :last-x last-x :last-y last-y))))
               :onMouseUp
               (fn [e]
                 (.preventDefault e)
                 (let [evt (or e (js/event))
                       state (om/get-state this)
                       updates {:dragging false
                                :last-x @a-last-x
                                :shift-left @a-shift-left
                                :last-y @a-last-y
                                :shift-top @a-shift-top}]
                   (om/set-state! this (merge state updates))))
               :onMouseMove
               (fn [e]
                 (.preventDefault e)
                 (when (:dragging (om/get-state this))
                   (let [evt (or e (js/event))
                         canvas (js/ReactDOM.findDOMNode (aget this "refs" "canvas"))
                         style (aget canvas "style")
                         scale (:zoom state)
                         client-x (aget evt "clientX")
                         delta-x (- client-x @a-last-x)
                         delta-x (* delta-x (/ 1.0 scale))
                         shift-left' (+ @a-shift-left delta-x)
                         client-y (aget evt "clientY")
                         delta-y (- client-y @a-last-y)
                         delta-y (* delta-y (/ 1.0 scale))
                         shift-top' (+ @a-shift-top delta-y)
                         transform (str "scale(" (:zoom state) ") translate(" shift-left' "px, " shift-top' "px)")]
                     (reset! a-last-x client-x)
                     (reset! a-shift-left shift-left')
                     (reset! a-last-y client-y)
                     (reset! a-shift-top shift-top')
                     (aset style "transform" transform))))}
              (let [transform (str "scale(" (:zoom state)  ") translate(" (:shift-left state) "px, " (:shift-top state) "px)")]
                (dom/div {:class "canvas"
                          :ref "canvas"
                          :style #js{"transform" transform}}
                         (om/children this)))))))


(def canvas (om/factory Canvas))


(defn hex-format
  [n]
  (str "0x" (string/upper-case (.toString n 16))))


(defn basicblock
  [props]
  (dom/div
   {:class "basic-block"}
   (dom/div {:class "bb-header"})
   (dom/div
    {:class "bb-content"}
    (dom/table
     (dom/thead)
     (dom/tbody
      (for [insn (:instructions props)]
        (dom/tr {:key (str (:addr insn)) :class "insn"}
                (dom/td {:class "addr"}
                        (hex-format (:addr insn)))
                (dom/td {:class "padding-1"})
                (dom/td {:class "bytes"}
                        (string/upper-case (:bytes insn)))
                (dom/td {:class "padding-2"})
                (dom/td {:class "mnem"}
                        (:mnem insn))
                (dom/td {:class "padding-3"})
                (dom/td {:class "operands"}
                        (:operands insn))
                (dom/td {:class "padding-4"})
                (dom/td {:class "comments"}
                        (when (and (:comments insn)
                                   (not= "" (:comments insn)))
                          (str ";  " (:comments insn)))))))))))



(defn function-list
  [props]
  (let [functions (:functions props)
        functions (sort-by :name functions)
        on-select-function (:select-function props)]
    (dom/div
     {:class "function-list"}
     (dom/h3 {:class "title"}
             "functions (" (count functions) " total):")
     (dom/ul
      (for [function functions]
        (dom/li {:key (str (:offset function))
                 :class "function"
                 :onClick #(on-select-function (:offset function))}
                (dom/span {:class "offset"}
                          (hex-format (:offset function)))
                ": "
                (dom/span {:class "name"}
                          (:name function))
                " ("
                (dom/span {:class "basic-block-count"}
                          (:nbbs function))
                ")"))))))


(defn basic-block-list
  [props]
  (let [bbs (:basic-blocks props)
        bbs (sort bbs)
        on-select-bb (:select-bb props)]
    (dom/div
     {:class "bb-list"}
     (dom/h3 {:class "title"}
             "basic blocks (" (count bbs) " total):")
     (dom/ul
      (for [bbva bbs]
        (dom/li {:key (str bbva)
                 :class "bb"
                 :onClick #(on-select-bb bbva)}
                (dom/span {:class "offset"}
                          (hex-format bbva))))))))


(def sqrt (.-sqrt js/Math))
(def PI (.-PI js/Math))
(def atan2 (.-atan2 js/Math))


;; these line drawing algorithms ripped directly from:
;;  http://stackoverflow.com/questions/4270485/drawing-lines-on-html-page

(defn geoline
  [x y length angle]
  (dom/div
   {:class "line"
    :style {:width (str length "em")
            :transform (str "rotate(" angle "rad)")
            :top (str y "em")
            :left (str x "em")}}))


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
    (dom/div {:class class}
             children)))


(def *model* (atom {:functions {}
                    :basic-blocks {}}))
(declare app)
(declare dispatch!)
(declare update-model!)



(defn r2->insn
  [insn]
  {:addr (:addr insn)
   :bytes (:bytes insn)
   :mnem (:mnemonic insn)
   :operands (subs (:opcode insn) (inc (count (:mnemonic insn))))
   :comments nil})


(defn compute-bb-height
  "
  units: em
  "
  [bb]
  (let [insn-count (count (:instructions bb))
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
        operands-size (apply max (map #(count (:operands %)) (:instructions bb)))
        comments-size (apply max (map #(count (:comments %)) (:instructions bb)))]
    (+ padding-1-size
       padding-2-size
       padding-3-size
       padding-4-size
       bytes-size
       mnem-size
       operands-size)))


(defn compute-edges
  [basic-blocks]
  (remove nil?
          (concat
           (for [bb basic-blocks]
             (when (:jump bb)
               {:src (:addr bb) :dst (:jump bb) :type :jump}))
           (for [bb basic-blocks]
             (when (:fail bb)
               {:src (:addr bb) :dst (:fail bb) :type :fail})))))


(defn dump-edges
  [edges]
  (doseq [edge edges]
    (prn (str (:type edge) " " (hex-format (:src edge)) " -> " (hex-format (:dst edge))))))


(defn layout-cfg-dagre
  [basic-blocks s e]
  (when (< 0 (count (remove nil? basic-blocks)))
    (let [edges (compute-edges basic-blocks)
          bbs (map #(assoc % :width (compute-bb-width %)) basic-blocks)
          bbs (map #(assoc % :height (compute-bb-height %)) bbs)
          g (dagre/make)]
      (doseq [bb bbs]
        (dagre/add-node! g bb))
      (doseq [edge edges]
        (dagre/add-edge! g edge))
      (dagre/layout! g)
      (s {:nodes (dagre/get-nodes g)
          :edges (dagre/get-edges g)}))))


(defn layout-cfg-klay
  [basic-blocks s e]
  (when (< 0 (count (remove nil? basic-blocks)))
    (let [edges (compute-edges basic-blocks)
          bbs (map #(assoc % :width (compute-bb-width %)) basic-blocks)
          bbs (map #(assoc % :height (compute-bb-height %)) bbs)
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
  [basic-blocks s e]
  (layout-cfg-klay basic-blocks s e))
  ;;(layout-cfg-dagre basic-blocks s e))


(defn positioned
  [props children]
  (let [x (:x props)
        y (:y props)
        w (:width props)
        h (:height props)
        top (str y "em")
        left (str x "em")]
    (dom/div {:class "laid-out"
              :style {:top top
                      :left left}}
             children)))


(defn edge-line
  [edge]
  (multi-line
   {:class (condp = (:type edge)
             :fail "edge-false"
             "edge-true")}
   (for [pair (partition 2 1 (:points edge))]
     (let [start (first pair)
           end (second pair)
           x1 (:x start)
           y1 (:y start)
           x2 (:x end)
           y2 (:y end)]
       (line x1 y1 x2 y2)))))


(defn- fetch-basic-block-instructions
  [bb]
  (go
    (let [addr (:addr bb)
          ninstr (:ninstr bb)
          aoj (<! (r2/get-instructions addr ninstr))
          insns (map r2->insn (:response aoj))]
      (assoc bb :instructions insns))))


(defn- fetch-function
  [fva]
  (go
    (let [afbj (<! (r2/get-basic-blocks fva))
          basic-blocks (:response afbj)]
      (<! (async/map vector (map fetch-basic-block-instructions basic-blocks))))))


(defn key-input
  [props]
  (dom/input
   {:type "text"
    :class "key-input"
    :autoFocus true
    :onKeyUp (or (:on-key-up props)
                 cmn/d)}))


(defn app
  [props]
  (dom/div
   {:class "app"}
   (key-input {:on-key-up (fn [e]
                            (prn "keyup")
                            (cmn/d e))})
   (dom/div
    {:class "panels"}
    (function-list
     {:functions (vals (:functions props))
      :select-function (fn [fva]
                         (dispatch! :set-selected-function {:selected-function fva})
                         (go
                           (let [basic-blocks (<! (fetch-function fva))]
                             (dispatch! :set-function-basic-blocks {:function fva :basic-blocks basic-blocks})
                             (layout-cfg basic-blocks
                                         (fn [layout]
                                           (dispatch! :set-function-layout {:function fva
                                                                            :nodes (:nodes layout)
                                                                            :edges (:edges layout)}))
                                         (fn [err]
                                           (prn "ERROR!")
                                           (cmn/d err))))))})
    (when (:selected-function props)
      (let [fva (:selected-function props)
            function (get-in props [:functions fva])
            basic-blocks (:basic-blocks function)]
        (basic-block-list {:basic-blocks basic-blocks
                           :select-bb #(update-model! {:selected-basic-block %})}))))
   (when (:selected-function props)
     (let [fva (:selected-function props)
           function (get-in props [:functions fva])
           layout (:layout function)]
       (canvas
        {}
        [(for [bbva (:basic-blocks function)]
           (let [pos (get-in layout [:nodes bbva])
                 bb (get-in props [:basic-blocks bbva])]
             (positioned pos (basicblock bb))))
         (for [edge (:edges layout)]
           (edge-line edge))])))))


(defn- render!
  ([model]
   (prn "render!")
   (js/ReactDOM.render
    (app @model)
    (gdom/getElement "app")))
  ([model changes]
   (swap! model (fn [model]
                  (merge model changes)))
   (render! model))
  ([model path changes]
   (swap! model (fn [model]
                  (update-in model path (fn [cur]
                                          (if cur
                                            (merge cur changes)
                                            changes)))))
   (render! model)))


(defn update-model!
  ([new-stuff]
   (render! *model* new-stuff))
  ([path new-stuff]
   (render! *model* path new-stuff)))

(defmulti action-handler (fn [key &rest] key))

(defmethod action-handler :default
  [key model args]
  (prn (str "ERROR: no dispatch! handler for: " key)))


(defmethod action-handler :set-selected-function
  [key model args]
  (let [fva (:selected-function args)]
    (assoc model :selected-function fva)))


(defmethod action-handler :set-function-basic-blocks
  [key model args]
  (let [fva (:function args)
        bbs (mapv :addr (:basic-blocks args))
        model' (update-in model [:functions fva] assoc :basic-blocks bbs)]
    (reduce (fn [m bb]
              (update m :basic-blocks assoc (:addr bb) bb))
            model'
            (:basic-blocks args))))


(defmethod action-handler :set-function-layout
  [key model args]
  (let [fva (:function args)
        nodes (:nodes args)
        edges (:edges args)]
    (update-in model [:functions fva] assoc :layout {:nodes (cmn/index-by :id nodes)
                                                     :edges edges})))


(defn dispatch!
  [key args]
  (prn (str "dispatch! " key))
  (let [before-model @*model*]
    (reset! *model* (action-handler key @*model* args))
    (cmn/d (second (clojure.data/diff before-model @*model*)))
    (render! *model*)))


;;(render! *model*)


(defn ensure-init
  []
  (let [ret (chan)]
    (go
      (let [aflj (<! (r2/get-functions))]
        (if (= :success (:status aflj))
          (do
            (prn "already init'd")
            (put! ret true)) ;
          (let [_ (prn "not yet init'd")
                _ (prn "initializing...")
                aaaa (<! (r2/analyze-all))
                _ (prn "initialized!")]
            (put! ret true)))))
    ret))



#_(go
  (let [_ (<! (ensure-init))
        aflj (<! (r2/get-functions))]
    (update-model! [:functions] (cmn/index-by :offset (:response aflj)))))


(def current-md5 "482D93562FC14E8FB4AFE9EE5E0F05F")
(def query (v/graphql-query {:venia/queries [[:sample_by_md5{:md5 current-md5} [:md5 :sha1]]]}))
(r2/http-graphql "/graphql" query prn prn)
